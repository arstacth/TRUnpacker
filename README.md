# TRUnpacker

<img width="520" height="352" alt="Screenshot 2026-10-01 025200" src="https://github.com/user-attachments/assets/bf0e0415-04b3-4b2c-977f-4ee4ff68a9f2" />


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
| `--patch-only` | Re-apply XIGNCODE disable on an already-unpacked exe |

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

```text
dotnet publish TRUnpacker.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
```

Result: `publish\TRUnpacker.exe`

## Notes

- Run the unpacked exe from the game client folder so game DLLs can load.
- If `dbghelp.dll` in the game folder is 32-bit, rename it (e.g. `dbghelp.x86.dll`) so the 64-bit client can use the system one.
- Keep **Disable XIGNCODE** on for offline / private-server use.
