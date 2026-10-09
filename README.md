# TRUnpacker
<img width="520" height="352" alt="Screenshot 2026-10-10 021253" src="https://github.com/user-attachments/assets/35883f68-551a-4697-b972-8147ce2fc4d9" />

Unpack TARA-packed `trgame.exe` and disable XIGNCODE in one step.

Output is written next to the input as `*_unpacked.exe`  
(e.g. `trgame.exe` → `trgame_unpacked.exe`, `trgame_th.exe` → `trgame_th_unpacked.exe`).

## How to use

### GUI
1. Open `TRUnpacker.exe`
2. Browse or drag-drop `trgame.exe` into the window
3. Leave **Disable XIGNCODE** checked (default)
4. Click **Unpack**

### Drop onto the exe
Drop any `.exe` onto `TRUnpacker.exe` — it unpacks immediately (no window needed).

### Command line
```text
TRUnpacker.exe trgame.exe
TRUnpacker.exe trgame.exe --no-xigncode
TRUnpacker.exe --patch-only trgame_unpacked.exe
```

| Flag | Meaning |
|---|---|
| *(default)* | Unpack + disable XIGNCODE |
| `--no-xigncode` | Unpack only (keep anti-cheat) |
| `--patch-loadbalance` / `--lvs` | Bypass hardcoded LoadBalance host (HK → like TH) |
| `--patch-only` | Re-apply selected patches on an already-unpacked exe |

### LoadBalance (HK)

HK clients whitelist `lvs.talesrunner.com.hk`. TH uses the host/port from the login server.

Tick **Patch LoadBalance** (off by default) to remove that whitelist so HK accepts your server’s LVS address like TH.

## What it does

1. **Unpack** — live-unpacks the TARA packer and rebuilds a runnable PE  
2. **Disable XIGNCODE** (when enabled):
   - Stub XIGNCODE init (`ZCWAVE_SysInit` / `SysEnter`)
   - Stub `CHackingDetection::detectHacking`
   - Force `IsDebuggerPresent` checks to return false
   - UAC manifest → `asInvoker`
   - Crash reporter URL → loopback

Works across builds that share the same XIGNCODE / detection strings (including common regional clients). If a build is too different, the tool fails instead of writing a half-patched file.

## Build from source

Requires .NET 9 SDK (Windows, x64).

### Visual Studio

**Build** (F6) only compiles. VS will log `TRUnpacker.dll`, but `TRUnpacker.exe` is also created in the same folder — next to many runtime DLLs. That is **not** the single-file build.

For the one standalone exe:

1. Right-click the project → **Publish…**
2. Choose profile **FolderProfile** (or Folder → `publish\`)
3. Click **Publish**

Result: `publish\TRUnpacker.exe` (one file, no extra DLLs).

### Command line

```text
dotnet publish TRUnpacker.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
```

Result: `publish\TRUnpacker.exe`

| Action | Output |
|---|---|
| Build | `bin\Release\...\TRUnpacker.exe` + many DLLs |
| Publish | `publish\TRUnpacker.exe` only |

## Notes

- Run the unpacked exe from the game client folder so game DLLs can load.
- If `dbghelp.dll` in the game folder is 32-bit, rename it (e.g. `dbghelp.x86.dll`) so the 64-bit client can use the system one.
- Keep **Disable XIGNCODE** on for offline / private-server use.
