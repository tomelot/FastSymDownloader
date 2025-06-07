// fast_reload.cpp
#include "pch.h"

#include <windows.h>
#include <dbghelp.h>
#include <wdbgexts.h>
#include <DbgEng.h>
#include <string>
#include <vector>
#include <cstdio>
#include <filesystem>
#include <wininet.h>
#include <thread>
#include <fstream>
#include <mutex>

#pragma comment(lib, "wininet.lib")

constexpr int MAX_DOWNLOAD_THREADS = 300;

std::string GetEnvOrDefault(const char* name, const char* fallback) {
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) == 0 && value != nullptr) {
        std::string result(value);
        free(value);
        return result;
    }
    return std::string(fallback);
}
const std::string SYMBOL_SERVER_URL = GetEnvOrDefault("SYMBOL_SERVER", "https://msdl.microsoft.com/download/symbols");
const std::string SYMBOL_CACHE_DIR = GetEnvOrDefault("SYMBOL_CACHE", "C:\\symbols");

#pragma pack(push, 1)
struct CV_INFO_PDB70 {
    DWORD CvSignature;
    GUID Signature;
    DWORD Age;
    CHAR PdbFileName[1]; // Null-terminated PDB path
};
#pragma pack(pop)

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) {
    return TRUE;
}

extern "C" __declspec(dllexport)
HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags) {
    *Version = DEBUG_EXTENSION_VERSION(1, 0);
    *Flags = 0;
    return S_OK;
}

extern "C" __declspec(dllexport)
void CALLBACK DebugExtensionUninitialize(void) {}

extern "C" __declspec(dllexport)
LPEXT_API_VERSION CALLBACK ExtensionApiVersion(void) {
    static EXT_API_VERSION version = { 1, 0, EXT_API_VERSION_NUMBER64, 0 };
    return &version;
}

bool ReadModulePdbInfo(IDebugDataSpaces* dataspace, ULONG64 base, GUID& outGuid, DWORD& outAge, std::string& outPdbName) {
    IMAGE_DOS_HEADER dosHeader = {};
    if (FAILED(dataspace->ReadVirtual(base, &dosHeader, sizeof(dosHeader), nullptr)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return false;

    IMAGE_NT_HEADERS64 ntHeaders = {};
    if (FAILED(dataspace->ReadVirtual(base + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), nullptr)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE)
        return false;

    IMAGE_DATA_DIRECTORY dbgDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (dbgDir.VirtualAddress == 0 || dbgDir.Size == 0)
        return false;

    IMAGE_DEBUG_DIRECTORY debugEntry = {};
    if (FAILED(dataspace->ReadVirtual(base + dbgDir.VirtualAddress, &debugEntry, sizeof(debugEntry), nullptr)) ||
        debugEntry.Type != IMAGE_DEBUG_TYPE_CODEVIEW)
        return false;

    BYTE cvBuffer[sizeof(CV_INFO_PDB70) + MAX_PATH] = {};
    if (FAILED(dataspace->ReadVirtual(base + debugEntry.AddressOfRawData, &cvBuffer, sizeof(cvBuffer), nullptr)))
        return false;

    CV_INFO_PDB70* cv = reinterpret_cast<CV_INFO_PDB70*>(cvBuffer);
    if (cv->CvSignature != 'SDSR') // 'RSDS'
        return false;

    outGuid = cv->Signature;
    outAge = cv->Age;
    outPdbName = cv->PdbFileName;

    return true;
}

std::string FormatPdbGuid(const GUID& guid, DWORD age) {
    char buffer[64];
    sprintf_s(buffer, sizeof(buffer),
        "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%d",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7], age);
    return std::string(buffer);
}

bool DownloadFileFromServer(const std::string& fileName, const std::string& formattedGuid) {
    std::filesystem::path cachePath = std::filesystem::path(SYMBOL_CACHE_DIR) / fileName / formattedGuid;
    std::filesystem::create_directories(cachePath);

    std::string downloadUrl = std::string(SYMBOL_SERVER_URL) + "/" + fileName + "/" + formattedGuid + "/" + fileName;
    std::filesystem::path localPath = cachePath / fileName;

    if (std::filesystem::exists(localPath)) {
        return true;
    }

    HINTERNET hInternet = InternetOpen(L"WinDbgExtension", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInternet) return false;

    HINTERNET hFile = InternetOpenUrlA(hInternet, downloadUrl.c_str(), nullptr, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        InternetCloseHandle(hInternet);
        return false;
    }

    HANDLE hLocal = CreateFileW(localPath.wstring().c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hLocal == INVALID_HANDLE_VALUE) {
        InternetCloseHandle(hFile);
        InternetCloseHandle(hInternet);
        return false;
    }

    BYTE buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hFile, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        DWORD written;
        WriteFile(hLocal, buffer, bytesRead, &written, nullptr);
    }

    CloseHandle(hLocal);
    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    return true;
}

extern "C" __declspec(dllexport)
HRESULT CALLBACK FastReload(PDEBUG_CLIENT4 Client, PCSTR args) {
    IDebugSymbols3* symbols = nullptr;
    IDebugControl* control = nullptr;
    IDebugDataSpaces* dataspace = nullptr;

    if (FAILED(Client->QueryInterface(__uuidof(IDebugSymbols3), (void**)&symbols)) ||
        FAILED(Client->QueryInterface(__uuidof(IDebugControl), (void**)&control)) ||
        FAILED(Client->QueryInterface(__uuidof(IDebugDataSpaces), (void**)&dataspace))) {
        return E_FAIL;
    }

    ULONG moduleCount = 0, unloadedCount = 0;
    if (FAILED(symbols->GetNumberModules(&moduleCount, &unloadedCount))) {
        symbols->Release(); control->Release(); dataspace->Release();
        return E_FAIL;
    }

    std::vector<std::thread> threads;
    for (ULONG64 i = 0; i < moduleCount; ++i) {
        DEBUG_MODULE_PARAMETERS modParams = {};
        if (FAILED(symbols->GetModuleParameters(1, nullptr, i, &modParams))) continue;

        char moduleName[MAX_PATH] = {};
        symbols->GetModuleNames(i, 0, moduleName, MAX_PATH, nullptr, nullptr, 0, nullptr, nullptr, 0, 0);

        GUID pdbGuid;
        DWORD pdbAge;
        std::string pdbName;

        if (!ReadModulePdbInfo(dataspace, modParams.Base, pdbGuid, pdbAge, pdbName))
            continue;

        std::string formattedGuid = FormatPdbGuid(pdbGuid, pdbAge);

        threads.emplace_back([pdbName, formattedGuid]() {
            DownloadFileFromServer(pdbName, formattedGuid);
            });

        if (threads.size() == MAX_DOWNLOAD_THREADS) {
            for (auto& t : threads) {
                if (t.joinable()) {
                    t.join();
                }
            }
            threads.clear();
        }
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

    control->Execute(DEBUG_OUTCTL_ALL_CLIENTS, ".reload /i /f", DEBUG_EXECUTE_DEFAULT);

    symbols->Release();
    control->Release();
    dataspace->Release();
    return S_OK;
}
