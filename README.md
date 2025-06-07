# FastReload - A Faster Symbol Downloader for WinDbg

I got bored of waiting for WinDbg to finish downloading all the symbols from a dump file I was trying to debug, so I asked ChatGPT to write me an extension that downloads symbols **multithreaded**, because for some reason WinDbg downloads each symbol **synchronously**.

After some tinkering, I made the code work — and the final result is pretty good. The performance improvement will of course depend on your internet speed and hardware, but WinDbg’s default algorithm is so slow that **almost everyone should see a significant speed-up**.

### 🔧 Recommendation
**Remove the symbol server URL from the WinDbg symbol path**.  
Why? Because WinDbg still tries to download symbols itself (even after mine), and it does so one-by-one with long timeouts.  
Instead, **only include your cache directory** in `.sympath`, and let `!FastReload` handle everything else.

### ⚙️ Configuration
You can configure the extension using environment variables:

- `SYMBOL_SERVER`: the symbol server URL (default: `https://msdl.microsoft.com/download/symbols`)
- `SYMBOL_CACHE`: the local symbol cache path (default: `C:\symbols`)

### 🚀 Usage

Inside WinDbg, just run:

```
!FastReload
```

And let it handle the rest.