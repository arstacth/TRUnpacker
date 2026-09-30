using System.Runtime.InteropServices;
using System.Text;

namespace TRUnpacker;

sealed class ImportDll
{
    public string Name = "";
    public uint OriginalFirstThunk;
    public uint FirstThunk;
    public uint NameRva;
    public readonly List<string> Functions = [];
}

sealed class ResolvedSlot
{
    public int IatOffset;
    public ulong Value;
    public string? Module;
    public string? Name;
    public int? Ordinal;
    public ulong Dest;
}

sealed class RemoteModule
{
    public ulong Base;
    public uint Size;
    public string Name = "";
}

sealed class ExportInfo
{
    public Dictionary<uint, List<string>> RvaToNames = new();
    public HashSet<uint> Forwards = [];
}

sealed class Unpacker
{
    const ulong PreferredBase = 0x140000000;
    const uint TaraMagic = 0x41524154;
    const uint ScnMemExecute = 0x20000000;

    static readonly string[] SystemPrefixes =
    [
        "kernel32", "user32", "gdi32", "ntdll", "advapi32", "ws2_32", "ole32", "oleaut32",
        "shell32", "comctl32", "comdlg32", "shlwapi", "winmm", "version", "imm32", "usp10",
        "gdiplus", "dinput8", "dbghelp", "netapi32", "msvcp140", "vcruntime", "ucrtbase",
        "api-ms-win-", "d3dcompiler", "dxgi", "d3d11", "d3d9", "setupapi", "crypt32", "bcrypt",
        "wintrust", "rpcrt4", "msvcrt", "kernelbase", "combase", "sechost", "hid", "xinput",
        "winhttp", "wininet", "dwmapi", "uxtheme", "normaliz", "iphlpapi", "dnsapi", "nsi",
        "userenv", "powrprof", "wtsapi32", "msimg32", "oleacc", "concrt140", "vcomp140",
        "psapi", "ntdll", "win32u",
    ];

    static readonly Dictionary<string, string> Kernel32Map = new(StringComparer.Ordinal)
    {
        ["RtlInitializeSListHead"] = "InitializeSListHead",
        ["RtlEnterCriticalSection"] = "EnterCriticalSection",
        ["RtlLeaveCriticalSection"] = "LeaveCriticalSection",
        ["RtlDeleteCriticalSection"] = "DeleteCriticalSection",
        ["RtlTryEnterCriticalSection"] = "TryEnterCriticalSection",
        ["RtlInitializeCriticalSectionEx"] = "InitializeCriticalSectionEx",
        ["RtlDecodePointer"] = "DecodePointer",
        ["RtlEncodePointer"] = "EncodePointer",
        ["RtlInitializeCriticalSection"] = "InitializeCriticalSection",
        ["RtlAllocateHeap"] = "HeapAlloc",
        ["RtlFreeHeap"] = "HeapFree",
        ["RtlReAllocateHeap"] = "HeapReAlloc",
        ["RtlSizeHeap"] = "HeapSize",
        ["RtlAcquireSRWLockShared"] = "AcquireSRWLockShared",
        ["RtlAcquireSRWLockExclusive"] = "AcquireSRWLockExclusive",
        ["RtlReleaseSRWLockShared"] = "ReleaseSRWLockShared",
        ["RtlReleaseSRWLockExclusive"] = "ReleaseSRWLockExclusive",
        ["RtlWakeAllConditionVariable"] = "WakeAllConditionVariable",
        ["RtlWakeConditionVariable"] = "WakeConditionVariable",
        ["RtlSleepConditionVariableSRW"] = "SleepConditionVariableSRW",
        ["RtlSleepConditionVariableCS"] = "SleepConditionVariableCS",
        ["RtlRestoreLastWin32Error"] = "SetLastError",
        ["RtlGetLastWin32Error"] = "GetLastError",
        ["RtlQueryPerformanceCounter"] = "QueryPerformanceCounter",
        ["RtlQueryPerformanceFrequency"] = "QueryPerformanceFrequency",
        ["RtlPcToFileHeader"] = "RtlPcToFileHeader",
    };

    static readonly (string Prev, string Next, string[] Names)[] NeighborGuesses =
    [
        ("_lclose", "SetLastError", ["IsBadReadPtr", "IsBadWritePtr", "_lopen", "_llseek", "_lread", "_lwrite"]),
        ("_lclose", "RtlRestoreLastWin32Error", ["IsBadReadPtr", "IsBadWritePtr", "_lopen", "_llseek"]),
        ("IsBadReadPtr", "SetLastError", ["IsBadWritePtr"]),
        ("IsBadReadPtr", "RtlRestoreLastWin32Error", ["IsBadWritePtr"]),
        ("GetLocaleInfoA", "GetCurrentDirectoryA",
        [
            "GetTimeFormatA", "GetDateFormatA", "GetCPInfo", "GetACP", "GetOEMCP",
            "GetUserDefaultLCID", "GetSystemDefaultLCID", "LCMapStringA", "GetStringTypeA",
            "GetStringTypeExA", "IsValidLocale", "IsValidCodePage", "GetTimeZoneInformation",
            "GetFullPathNameA", "GetTempPathA", "GetWindowsDirectoryA", "GetSystemDirectoryA",
            "GetShortPathNameA", "SetErrorMode", "GetDiskFreeSpaceExA", "GetFileAttributesA",
            "GetVersionExA", "GetVersion", "GetCommandLineA", "GetEnvironmentStrings",
            "GetStartupInfoA", "GetModuleHandleA", "GetModuleHandleW", "GetProcAddress",
        ]),
        ("FindResourceA", "SizeofResource", ["LockResource", "FindResourceExA", "EnumResourceNamesA", "LoadResource"]),
        ("OleSetContainedObject", "OleUninitialize", ["OleInitialize", "OleRun", "OleLoad", "RegisterDragDrop", "RevokeDragDrop"]),
        ("RegisterClassExA", "KillTimer",
        [
            "DefWindowProcA", "DefWindowProcW", "CallWindowProcA", "GetClassInfoExA", "GetClassInfoA",
            "UnregisterClassW", "LoadIconA", "LoadBitmapA", "InvalidateRect", "EnableWindow",
            "SetWindowTextA", "IsWindowVisible", "IsWindowEnabled", "ShowWindowAsync", "RedrawWindow",
            "WaitMessage", "wsprintfA", "CreateDialogParamA", "DialogBoxParamA", "EndDialog",
            "GetDlgItem", "TrackPopupMenu", "DrawIcon", "LoadMenuA", "CheckMenuItem",
            "DefDlgProcA", "GetClassNameW", "CreateWindowA",
        ]),
    ];

    static IEnumerable<string> RelatedModules(string owner)
    {
        if (owner.StartsWith("KERNEL32", StringComparison.OrdinalIgnoreCase))
            return ["KERNEL32.dll", "KERNELBASE.dll", "ntdll.dll", "PSAPI.dll"];
        if (owner.StartsWith("USER32", StringComparison.OrdinalIgnoreCase))
            return ["USER32.dll", "win32u.dll", "ntdll.dll"];
        if (owner.Equals("ole32.dll", StringComparison.OrdinalIgnoreCase))
            return ["ole32.dll", "combase.dll"];
        if (owner.StartsWith("SHELL32", StringComparison.OrdinalIgnoreCase))
            return ["SHELL32.dll"];
        if (owner.StartsWith("MSVCP140_ATOMIC", StringComparison.OrdinalIgnoreCase))
            return ["MSVCP140_ATOMIC_WAIT.dll"];
        if (owner.StartsWith("MSVCP140", StringComparison.OrdinalIgnoreCase))
            return ["MSVCP140.dll"];
        if (owner.StartsWith("WS2_32", StringComparison.OrdinalIgnoreCase))
            return ["WS2_32.dll"];
        if (owner.StartsWith("python", StringComparison.OrdinalIgnoreCase))
            return ["python27.dll"];
        return [owner];
    }

    readonly string _inputPath;
    readonly string _outputPath;
    readonly string _gameDir;
    readonly bool _disableXigncode;
    readonly Action<string>? _log;
    readonly Action<int, int, string?>? _progress;
    readonly Dictionary<ulong, ExportInfo> _exportCache = new();
    readonly Dictionary<ulong, List<(uint Start, uint End, bool Exec)>> _sectionCache = new();

    public Unpacker(
        string inputPath,
        string outputPath,
        bool disableXigncode = true,
        Action<string>? log = null,
        Action<int, int, string?>? progress = null)
    {
        _inputPath = Path.GetFullPath(inputPath);
        _outputPath = Path.GetFullPath(outputPath);
        _gameDir = FindGameDir(Path.GetDirectoryName(_inputPath)!);
        _disableXigncode = disableXigncode;
        _log = log;
        _progress = progress;
    }

    void Log(string msg) => Emit(msg);

    static Action<string>? CurrentLog;

    static void Emit(string msg)
    {
        Console.WriteLine(msg);
        CurrentLog?.Invoke(msg);
    }

    void Progress(int value, int max, string? status = null)
    {
        _progress?.Invoke(value, max, status);
        if (!string.IsNullOrEmpty(status))
            Emit(status);
    }

    public void Run()
    {
        CurrentLog = _log;
        try
        {
            RunCore();
        }
        finally
        {
            CurrentLog = null;
        }
    }

    void RunCore()
    {
        Progress(0, 8, $"Input  {_inputPath}");
        Log($"Output {_outputPath}");
        Log($"Game   {_gameDir}");
        Log($"XIGNCODE disable: {(_disableXigncode ? "on" : "off")}");
        WarnIncompatibleDlls();

        byte[] packed = File.ReadAllBytes(_inputPath);
        var packedPe = PeImage.Parse(packed, virtualLayout: false);
        Progress(1, 8, $"SizeOfImage=0x{packedPe.SizeOfImage:X} EP=0x{packedPe.AddressOfEntryPoint:X}");

        if (!IsTaraPacked(packedPe))
        {
            Log("Input is not TARA-packed (already unpacked) — repairing PE in place.");
            RepairExisting(packedPe);
            return;
        }

        string work = Path.Combine(Path.GetTempPath(), "trunpacker_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(work);
        try
        {
            string runner = Path.Combine(work, Path.GetFileName(_inputPath));
            File.WriteAllBytes(runner, PatchAsInvoker(packed));
            var packedImports = ReadImports(packedPe, skipLeadingZeros: false);
            WriteStubs(work, packedImports);

            Progress(2, 8, "Launching packer stub...");
            var (proc, pid) = Start(runner, _gameDir);
            Log($"PID {pid}");
            try
            {
                Progress(3, 8, "Waiting for TARA unpack...");
                ulong map = WaitForUnpackedMap(proc, packedPe.SizeOfImage);
                Progress(4, 8, $"Unpacked mapping 0x{map:X}");

                byte[] image = ReadExact(proc, map, packedPe.SizeOfImage);
                if (BitConverter.ToUInt32(image, 0x1000) == TaraMagic)
                    throw new InvalidOperationException("Dump still starts with TARA — unpack did not finish.");

                var pe = PeImage.Parse(image, virtualLayout: true);
                var (iatRva, iatSize) = DiscoverIat(pe);
                Progress(5, 8, $"IAT RVA=0x{iatRva:X} size=0x{iatSize:X}");

                var modules = EnumModules(proc);
                Log($"Modules {modules.Count}");
                var resolved = ResolveIat(proc, map, iatRva, iatSize, modules);
                Progress(6, 8, "Rebuilding PE imports...");
                Rebuild(pe, packedPe, resolved, iatRva, iatSize, restoreAdmin: !_disableXigncode);

                byte[] file = pe.ToPeFile();
                if (_disableXigncode)
                {
                    Progress(7, 8, "Applying XIGNCODE offline patches...");
                    file = XigncodePatcher.Apply(file, Emit);
                }

                File.WriteAllBytes(_outputPath, file);
                Progress(8, 8, $"Wrote {_outputPath} ({file.Length:N0} bytes)");
                Log($"EP=0x{pe.AddressOfEntryPoint:X} ImageBase=0x{pe.ImageBase:X}");
                if (!PathsEqual(_gameDir, Path.GetDirectoryName(_outputPath)!))
                    Log($"Run the unpacked exe from {_gameDir} so game DLLs can load.");
            }
            finally
            {
                Native.TerminateProcess(proc, 0);
                Native.CloseHandle(proc);
            }
        }
        finally
        {
            try { Directory.Delete(work, true); } catch { /* temp cleanup */ }
        }
    }

    static bool PathsEqual(string a, string b) =>
        string.Equals(Path.GetFullPath(a).TrimEnd('\\'), Path.GetFullPath(b).TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);

    static string FindGameDir(string start)
    {
        string dir = start;
        for (int i = 0; i < 8; i++)
        {
            foreach (var (marker, minSize) in new (string, long)[]
            {
                ("bdvid64.dll", 100_000),
                ("GdiPlus.dll", 100_000),
                ("msvcp140.dll", 100_000),
                ("python27.dll", 32_768),
                ("fmodex64.dll", 32_768),
                ("TRWebViewer.dll", 32_768),
            })
            {
                string p = Path.Combine(dir, marker);
                if (File.Exists(p) && new FileInfo(p).Length > minSize)
                    return dir;
            }
            var parent = Directory.GetParent(dir);
            if (parent is null) break;
            dir = parent.FullName;
        }
        return start;
    }

    static bool IsTaraPacked(PeImage pe)
    {
        var text = pe.Sections.FirstOrDefault(s => s.Name.StartsWith(".text"));
        if (text is null) return false;
        int off = pe.RvaToOff(text.VirtualAddress);
        if (off >= 0 && BitConverter.ToUInt32(pe.Data, off) == TaraMagic)
            return true;
        var last = pe.Sections.Last();
        return pe.AddressOfEntryPoint >= last.VirtualAddress;
    }

    void RepairExisting(PeImage filePe)
    {
        Progress(2, 8, "Repairing already-unpacked PE...");
        byte[] virtualBytes = filePe.ToVirtualImage();
        var pe = PeImage.Parse(virtualBytes, virtualLayout: true);
        var (iatRva, iatSize) = DiscoverIat(pe);
        Log($"IAT RVA=0x{iatRva:X} size=0x{iatSize:X}");
        var slots = BuildStaticSlots(pe, iatRva, iatSize);
        int named = slots.Count(s => s.Name is not null);
        int tramp = slots.Count(s => s.Value > pe.SizeOfImage);
        Log($"Static IAT: {named} named slots, {tramp} trampolines");
        Progress(5, 8, "Rebuilding PE imports...");
        Rebuild(pe, filePe, slots, iatRva, iatSize, restoreAdmin: !_disableXigncode);
        byte[] file = pe.ToPeFile();
        if (_disableXigncode)
        {
            Progress(7, 8, "Applying XIGNCODE offline patches...");
            file = XigncodePatcher.Apply(file, Emit);
        }
        File.WriteAllBytes(_outputPath, file);
        Progress(8, 8, $"Wrote {_outputPath} ({file.Length:N0} bytes)");
        Log($"EP=0x{pe.AddressOfEntryPoint:X} ImageBase=0x{pe.ImageBase:X}");
    }

    static List<ResolvedSlot> BuildStaticSlots(PeImage pe, uint iatRva, uint iatSize)
    {
        var slots = new List<ResolvedSlot>();
        for (int off = 0; off < iatSize; off += 8)
        {
            ulong val = pe.ReadU64(iatRva + (uint)off);
            var slot = new ResolvedSlot { IatOffset = off, Value = val };
            if (val == 0)
            {
                slots.Add(slot);
                continue;
            }
            if (val < pe.SizeOfImage)
                slot.Name = pe.ReadCString((uint)val + 2);
            slots.Add(slot);
        }
        return slots;
    }

    void WarnIncompatibleDlls()
    {
        string dbg = Path.Combine(_gameDir, "dbghelp.dll");
        if (!File.Exists(dbg)) return;
        try
        {
            byte[] hdr = File.ReadAllBytes(dbg);
            if (hdr.Length < 0x40) return;
            int e = BitConverter.ToInt32(hdr, 0x3C);
            if (e + 6 > hdr.Length) return;
            ushort machine = BitConverter.ToUInt16(hdr, e + 4);
            if (machine == 0x14C)
                Emit("WARNING: dbghelp.dll in the game folder is 32-bit. Rename it to dbghelp.x86.dll so the 64-bit client loads System32 dbghelp.");
        }
        catch
        {
            // ignore
        }
    }

    static byte[] PatchAsInvoker(byte[] packed)
    {
        var data = (byte[])packed.Clone();
        foreach (var (oldS, neuS) in new[]
        {
            ("level='requireAdministrator'", "level='asInvoker'"),
            ("level=\"requireAdministrator\"", "level=\"asInvoker\""),
        })
        {
            byte[] old = Encoding.ASCII.GetBytes(oldS);
            byte[] neu = Encoding.ASCII.GetBytes(neuS);
            var pad = new byte[old.Length];
            neu.CopyTo(pad, 0);
            for (int i = neu.Length; i < pad.Length; i++) pad[i] = (byte)' ';
            int idx = IndexOf(data, old);
            if (idx >= 0)
            {
                pad.CopyTo(data, idx);
                return data;
            }
        }
        throw new InvalidDataException("UAC manifest string not found.");
    }

    static bool IsSystemDll(string name)
    {
        string low = name.ToLowerInvariant();
        return SystemPrefixes.Any(low.StartsWith);
    }

    void WriteStubs(string work, List<ImportDll> imports)
    {
        int n = 0;
        foreach (var imp in imports)
        {
            if (IsSystemDll(imp.Name))
            {
                IntPtr h = Native.LoadLibraryW(imp.Name);
                if (h != IntPtr.Zero)
                {
                    Native.FreeLibrary(h);
                    continue;
                }
            }
            n++;
            byte[] pe = StubDll.Build(imp.Name, imp.Functions, 0x180000000UL + 0x10000000UL * (uint)n);
            File.WriteAllBytes(Path.Combine(work, imp.Name), pe);
            Emit($"  stub {imp.Name} ({imp.Functions.Count} exports)");
        }
    }

    static List<ImportDll> ReadImports(PeImage pe, bool skipLeadingZeros)
    {
        var list = new List<ImportDll>();
        uint p = pe.DirRva[PeImage.DirImport];
        if (p == 0) return list;
        int skipped = 0;
        while (true)
        {
            int o = pe.RvaToOff(p);
            if (o < 0) break;
            uint oft = BitConverter.ToUInt32(pe.Data, o);
            uint name = BitConverter.ToUInt32(pe.Data, o + 12);
            uint ft = BitConverter.ToUInt32(pe.Data, o + 16);
            if (oft == 0 && name == 0)
            {
                if (skipLeadingZeros && list.Count == 0 && skipped < 20)
                {
                    p += 20;
                    skipped++;
                    continue;
                }
                break;
            }
            string dllName = name == 0 ? "" : pe.ReadCString(name);
            if (string.IsNullOrEmpty(dllName) || !dllName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
            {
                if (skipLeadingZeros && list.Count == 0 && skipped < 20)
                {
                    p += 20;
                    skipped++;
                    continue;
                }
                if (string.IsNullOrEmpty(dllName) && ft != 0)
                {
                    var dll = new ImportDll { Name = "", OriginalFirstThunk = oft, FirstThunk = ft, NameRva = name };
                    ReadThunkNames(pe, dll, oft != 0 ? oft : ft);
                    list.Add(dll);
                    p += 20;
                    continue;
                }
                break;
            }
            var named = new ImportDll
            {
                Name = dllName,
                OriginalFirstThunk = oft,
                FirstThunk = ft,
                NameRva = name,
            };
            ReadThunkNames(pe, named, oft != 0 ? oft : ft);
            list.Add(named);
            p += 20;
        }
        return list;
    }

    static void ReadThunkNames(PeImage pe, ImportDll dll, uint table)
    {
        for (int k = 0; k < 4096; k++)
        {
            ulong thunk = pe.ReadU64(table + (uint)(k * 8));
            if (thunk == 0) break;
            if ((thunk & (1UL << 63)) != 0)
                dll.Functions.Add("ord" + (thunk & 0xFFFF));
            else if (thunk < pe.SizeOfImage)
                dll.Functions.Add(pe.ReadCString((uint)thunk + 2));
        }
    }

    static (IntPtr proc, uint pid) Start(string exe, string cwd)
    {
        var si = new Native.STARTUPINFO
        {
            cb = Marshal.SizeOf<Native.STARTUPINFO>(),
            dwFlags = Native.STARTF_USESHOWWINDOW,
            wShowWindow = Native.SW_HIDE,
        };
        var cmd = new StringBuilder($"\"{exe}\"");
        if (!Native.CreateProcessW(exe, cmd, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, cwd, ref si, out var pi))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "CreateProcess failed");
        Native.CloseHandle(pi.hThread);
        return (pi.hProcess, pi.dwProcessId);
    }

    static ulong WaitForUnpackedMap(IntPtr proc, uint sizeOfImage)
    {
        for (int i = 0; i < 80; i++)
        {
            Thread.Sleep(250);
            if (Native.GetExitCodeProcess(proc, out uint code) && code != Native.STILL_ACTIVE)
                throw new InvalidOperationException($"Packed process exited early ({code:X8}). Missing DLL?");
            ulong found = 0;
            ulong fallback = 0;
            foreach (var (baseAddr, size, state) in EnumRegions(proc))
            {
                if (state != Native.MEM_COMMIT) continue;
                if (size != sizeOfImage && size < sizeOfImage) continue;
                var head = new byte[4];
                if (!Native.ReadProcessMemory(proc, (IntPtr)(baseAddr + 0x1000), head, 4, out _))
                    continue;
                if (BitConverter.ToUInt32(head, 0) == TaraMagic)
                    continue;
                var mz = new byte[2];
                if (!Native.ReadProcessMemory(proc, (IntPtr)baseAddr, mz, 2, out _) || mz[0] != (byte)'M' || mz[1] != (byte)'Z')
                    continue;
                if (size == sizeOfImage)
                    found = baseAddr;
                else if (fallback == 0)
                    fallback = baseAddr;
            }
            if (found != 0) return found;
            if (i > 20 && fallback != 0) return fallback;
        }
        throw new TimeoutException("Timed out waiting for TARA to unpack.");
    }

    static IEnumerable<(ulong Base, ulong Size, uint State)> EnumRegions(IntPtr proc)
    {
        ulong addr = 0;
        while (addr < 0x7FFFFFF00000UL)
        {
            nuint got = Native.VirtualQueryEx(proc, (IntPtr)addr, out var mbi, (nuint)Marshal.SizeOf<Native.MEMORY_BASIC_INFORMATION>());
            if (got == 0) yield break;
            ulong b = mbi.BaseAddress.ToUInt64();
            ulong sz = mbi.RegionSize.ToUInt64();
            yield return (b, sz, mbi.State);
            if (sz == 0 || b + sz <= addr) yield break;
            addr = b + sz;
        }
    }

    static byte[] ReadExact(IntPtr proc, ulong addr, uint size)
    {
        var buf = new byte[size];
        const uint chunk = 0x100000;
        uint off = 0;
        while (off < size)
        {
            uint n = Math.Min(chunk, size - off);
            var tmp = new byte[n];
            if (!Native.ReadProcessMemory(proc, (IntPtr)(addr + off), tmp, n, out nuint got) || got == 0)
                throw new InvalidOperationException($"ReadProcessMemory failed at 0x{addr + off:X}");
            Buffer.BlockCopy(tmp, 0, buf, (int)off, (int)got);
            off += (uint)got;
        }
        return buf;
    }

    static List<RemoteModule> EnumModules(IntPtr proc)
    {
        var mods = new IntPtr[1024];
        if (!Native.EnumProcessModulesEx(proc, mods, (uint)(mods.Length * IntPtr.Size), out uint needed, Native.LIST_MODULES_ALL))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "EnumProcessModulesEx failed");
        int count = (int)(needed / IntPtr.Size);
        var list = new List<RemoteModule>(count);
        var sb = new StringBuilder(32768);
        for (int i = 0; i < count; i++)
        {
            Native.GetModuleInformation(proc, mods[i], out var mi, (uint)Marshal.SizeOf<Native.MODULEINFO>());
            sb.Clear();
            Native.GetModuleFileNameExW(proc, mods[i], sb, 32768);
            list.Add(new RemoteModule
            {
                Base = (ulong)mi.lpBaseOfDll.ToInt64(),
                Size = mi.SizeOfImage,
                Name = Path.GetFileName(sb.ToString()),
            });
        }
        return list;
    }

    static (uint rva, uint size) DiscoverIat(PeImage pe)
    {
        uint rva = pe.DirRva[PeImage.DirIat];
        uint size = pe.DirSize[PeImage.DirIat];
        var last = pe.Sections.Last();
        bool inStub = rva >= last.VirtualAddress;
        if (rva != 0 && size >= 16 && !inStub)
            return (rva, size);

        var known = ReadImports(pe, skipLeadingZeros: true);
        if (known.Count == 0)
            throw new InvalidDataException("Could not locate IAT (no surviving import descriptors).");

        var rdata = pe.Sections.FirstOrDefault(s => s.Name.StartsWith(".rdata")) ?? pe.Sections[1];
        uint rlo = rdata.VirtualAddress;
        uint minFt = known.Min(d => d.FirstThunk);
        uint maxEnd = 0;
        foreach (var d in known)
        {
            uint k = 0;
            while (d.FirstThunk + k * 8 + 8 <= pe.SizeOfImage && pe.ReadU64(d.FirstThunk + k * 8) != 0)
                k++;
            maxEnd = Math.Max(maxEnd, d.FirstThunk + (k + 1) * 8);
        }

        uint p = minFt;
        while (p >= rlo + 16)
        {
            if (pe.ReadU64(p - 8) != 0)
            {
                p -= 8;
                continue;
            }
            if (pe.ReadU64(p - 16) == 0) break;
            uint q = p - 16;
            while (q > rlo && pe.ReadU64(q - 8) != 0) q -= 8;
            p = q;
        }

        uint start = p;
        uint sz = maxEnd > start ? maxEnd - start : size;
        Emit($"  discovered IAT 0x{start:X} size=0x{sz:X} (dir was 0x{rva:X})");
        return (start, sz);
    }

    List<ResolvedSlot> ResolveIat(IntPtr proc, ulong map, uint iatRva, uint iatSize, List<RemoteModule> modules)
    {
        var iat = new byte[iatSize];
        if (!Native.ReadProcessMemory(proc, (IntPtr)(map + iatRva), iat, iatSize, out _))
            throw new InvalidOperationException("Could not read live IAT.");

        var slots = new List<ResolvedSlot>();
        for (int off = 0; off < iatSize; off += 8)
        {
            ulong val = BitConverter.ToUInt64(iat, off);
            var slot = new ResolvedSlot { IatOffset = off, Value = val };
            if (val == 0) { slots.Add(slot); continue; }
            if (val < 0x10000000UL)
            {
                slot.Name = null;
                slots.Add(slot);
                continue;
            }
            ulong dest = FollowTrampoline(proc, val);
            slot.Dest = dest;
            var (mod, name, ord) = ResolveAddr(proc, modules, dest, nearby: false);
            slot.Module = mod;
            slot.Name = name;
            slot.Ordinal = name is null ? ord : null;
            slots.Add(slot);
        }

        foreach (var group in Groups(slots))
        {
            string? owner = Majority(group.Select(s => s.Module));
            if (owner is null) continue;
            foreach (var s in group)
            {
                if (s.Value == 0 || s.Name is not null || s.Dest == 0) continue;
                if (TryNameFromModule(proc, modules, s, owner, nearbyCode: false))
                    Emit($"  2nd-pass {s.IatOffset:X} {s.Module}!{s.Name}");
            }
        }

        foreach (var group in Groups(slots))
        {
            string? owner = Majority(group.Select(s => s.Module));
            if (owner is null) continue;
            owner = NormalizeImportDll(owner, group);
            foreach (var s in group)
            {
                if (s.Value == 0 || s.Name is not null || s.Dest == 0) continue;
                foreach (var related in RelatedModules(owner))
                {
                    // Exact export match only. Nearby (+/-16) hits corrupt dense CRT/MSVCP
                    // tables (vtables mistaken for ctors, tzdb names mistaken for free).
                    if (TryNameFromModule(proc, modules, s, related, nearbyCode: false))
                    {
                        Emit($"  3rd-pass {s.IatOffset:X} {s.Module}!{s.Name}");
                        break;
                    }
                }
            }
        }

        foreach (var group in Groups(slots))
            FillNeighbors(proc, modules, group);

        int ok = slots.Count(s => s.Name is not null);
        int left = slots.Count(s => s.Value > 0x100000000UL && s.Name is null);
        Emit($"Resolved {ok} named IAT slots, {left} trampolines left");
        foreach (var s in slots.Where(s => s.Value > 0x100000000UL && s.Name is null))
        {
            var code = new byte[16];
            Native.ReadProcessMemory(proc, (IntPtr)s.Dest, code, 16, out _);
            Emit($"  unresolved 0x{iatRva + (uint)s.IatOffset:X} dest=0x{s.Dest:X} {Convert.ToHexString(code)} mod={s.Module}");
        }
        return slots;
    }

    void FillNeighbors(IntPtr proc, List<RemoteModule> modules, List<ResolvedSlot> group)
    {
        string? owner = Majority(group.Select(s => s.Module));
        owner = owner is null ? null : NormalizeImportDll(owner, group);
        for (int i = 0; i < group.Count; i++)
        {
            var s = group[i];
            if (s.Value == 0 || s.Name is not null) continue;
            string prev = i > 0 ? group[i - 1].Name ?? "" : "";
            string next = i + 1 < group.Count ? group[i + 1].Name ?? "" : "";
            foreach (var (p, n, names) in NeighborGuesses)
            {
                if (!prev.Equals(p, StringComparison.OrdinalIgnoreCase)) continue;
                if (!next.Equals(n, StringComparison.OrdinalIgnoreCase) &&
                    !(n == "SetLastError" && next == "RtlRestoreLastWin32Error"))
                    continue;
                foreach (var cand in names)
                {
                    foreach (var tryOwner in UniqueOwners(owner, cand))
                    {
                        if (s.Dest != 0 && !MatchesExport(proc, modules, tryOwner, cand, s.Dest))
                            continue;
                        s.Name = cand;
                        s.Module = tryOwner;
                        Emit($"  neighbor {s.IatOffset:X} {tryOwner}!{cand}");
                        goto nextSlot;
                    }
                }
            }

            // High-confidence fallbacks when live dest cannot be matched.
            if (prev.Equals("FindResourceA", StringComparison.OrdinalIgnoreCase) &&
                next.Equals("SizeofResource", StringComparison.OrdinalIgnoreCase))
            {
                s.Name = "LockResource";
                s.Module = "KERNEL32.dll";
                Emit($"  guess {s.IatOffset:X} LockResource");
            }
            else if (prev.Equals("OleSetContainedObject", StringComparison.OrdinalIgnoreCase) &&
                     next.Equals("OleUninitialize", StringComparison.OrdinalIgnoreCase))
            {
                s.Name = "OleInitialize";
                s.Module = "ole32.dll";
                Emit($"  guess {s.IatOffset:X} OleInitialize");
            }
            else if (prev.Equals("IsBadReadPtr", StringComparison.OrdinalIgnoreCase) &&
                     (next.Equals("SetLastError", StringComparison.OrdinalIgnoreCase) ||
                      next.Equals("RtlRestoreLastWin32Error", StringComparison.OrdinalIgnoreCase)))
            {
                s.Name = "IsBadWritePtr";
                s.Module = "KERNEL32.dll";
                Emit($"  guess {s.IatOffset:X} IsBadWritePtr");
            }
            else if (prev.Equals("_lclose", StringComparison.OrdinalIgnoreCase) &&
                     (next.Equals("SetLastError", StringComparison.OrdinalIgnoreCase) ||
                      next.Equals("RtlRestoreLastWin32Error", StringComparison.OrdinalIgnoreCase)))
            {
                s.Name = "IsBadReadPtr";
                s.Module = "KERNEL32.dll";
                Emit($"  guess {s.IatOffset:X} IsBadReadPtr");
            }
            else if (prev.Equals("RegisterClassExA", StringComparison.OrdinalIgnoreCase) &&
                     next.Equals("KillTimer", StringComparison.OrdinalIgnoreCase))
            {
                s.Name = "DefWindowProcA";
                s.Module = "USER32.dll";
                Emit($"  guess {s.IatOffset:X} DefWindowProcA");
            }
            nextSlot:;
        }
    }

    static IEnumerable<string> UniqueOwners(string? owner, string api)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (owner is not null && seen.Add(owner)) yield return owner;
        string guess = api.StartsWith("Ole", StringComparison.Ordinal) ? "ole32.dll"
            : api.StartsWith("SH", StringComparison.Ordinal) || api.StartsWith("Shell", StringComparison.Ordinal) ? "SHELL32.dll"
            : api.StartsWith("DefWindow", StringComparison.Ordinal) || api.StartsWith("CallWindow", StringComparison.Ordinal) ? "USER32.dll"
            : "KERNEL32.dll";
        if (seen.Add(guess)) yield return guess;
        foreach (var extra in new[] { "KERNEL32.dll", "USER32.dll", "ole32.dll", "SHELL32.dll", "KERNELBASE.dll" })
            if (seen.Add(extra)) yield return extra;
    }

    bool MatchesExport(IntPtr proc, List<RemoteModule> modules, string owner, string api, ulong dest)
    {
        var mod = FindModule(modules, owner);
        if (mod is null) return false;
        var exp = GetExports(proc, mod.Base);
        foreach (var (frva, names) in exp.RvaToNames)
        {
            if (!names.Any(n => n.Equals(api, StringComparison.Ordinal))) continue;
            ulong addr = mod.Base + frva;
            if (dest == 0) return true;
            if (addr == dest) return true;
            if (FollowTrampoline(proc, addr) == dest) return true;
            if (FollowTrampoline(proc, dest) == addr) return true;
            if (FollowTrampoline(proc, dest) == FollowTrampoline(proc, addr)) return true;
        }
        return false;
    }

    static RemoteModule? FindModule(List<RemoteModule> modules, string owner) =>
        modules.FirstOrDefault(m => m.Name.Equals(owner, StringComparison.OrdinalIgnoreCase));

    bool TryNameFromModule(IntPtr proc, List<RemoteModule> modules, ResolvedSlot s, string owner, bool nearbyCode)
    {
        var mod = FindModule(modules, owner);
        if (mod is null) return false;
        var exp = GetExports(proc, mod.Base);
        foreach (var (frva, names) in exp.RvaToNames)
        {
            ulong addr = mod.Base + frva;
            bool hit = addr == s.Dest || FollowTrampoline(proc, addr) == s.Dest || FollowTrampoline(proc, s.Dest) == addr;
            if (!hit && nearbyCode && !exp.Forwards.Contains(frva) && IsExecutable(proc, mod.Base, frva)
                && s.Dest >= addr && s.Dest - addr < 16)
                hit = true;
            if (!hit) continue;
            s.Module = owner;
            s.Name = names[0];
            return true;
        }
        return false;
    }

    static List<List<ResolvedSlot>> Groups(List<ResolvedSlot> slots)
    {
        var groups = new List<List<ResolvedSlot>>();
        var cur = new List<ResolvedSlot>();
        foreach (var s in slots)
        {
            if (s.Value == 0)
            {
                if (cur.Count > 0) { groups.Add(cur); cur = []; }
                continue;
            }
            cur.Add(s);
        }
        if (cur.Count > 0) groups.Add(cur);
        return groups;
    }

    static string? Majority(IEnumerable<string?> names)
    {
        var votes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var n in names)
        {
            if (string.IsNullOrEmpty(n)) continue;
            votes[n] = votes.GetValueOrDefault(n) + 1;
        }
        return votes.Count == 0 ? null : votes.MaxBy(kv => kv.Value).Key;
    }

    static string NormalizeImportDll(string owner, List<ResolvedSlot> group)
    {
        var apis = group.Select(s => s.Name).Where(s => !string.IsNullOrEmpty(s)).Cast<string>().ToList();
        if (apis.Any(a => a.Equals("timeGetTime", StringComparison.OrdinalIgnoreCase)))
            return "WINMM.dll";
        if (apis.Any(a => a.StartsWith("__std_", StringComparison.Ordinal)))
            return "MSVCP140_ATOMIC_WAIT.dll";
        if (apis.Any(a => a.StartsWith("Shell", StringComparison.Ordinal) || a.StartsWith("SH", StringComparison.Ordinal)))
            return "SHELL32.dll";
        if (owner.Equals("KERNELBASE.dll", StringComparison.OrdinalIgnoreCase) ||
            owner.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase))
            return "KERNEL32.dll";
        if (owner.Equals("win32u.dll", StringComparison.OrdinalIgnoreCase))
            return "USER32.dll";
        if (owner.Equals("ucrtbase.dll", StringComparison.OrdinalIgnoreCase))
            return "MSVCP140_ATOMIC_WAIT.dll";
        if (owner.Equals("combase.dll", StringComparison.OrdinalIgnoreCase) &&
            apis.Any(a => a.StartsWith("Ole", StringComparison.Ordinal)))
            return "ole32.dll";
        if (owner.Equals("PSAPI.dll", StringComparison.OrdinalIgnoreCase))
            return "KERNEL32.dll";
        return owner;
    }

    ulong FollowTrampoline(IntPtr proc, ulong addr)
    {
        ulong cur = addr;
        for (int i = 0; i < 12; i++)
        {
            var code = new byte[32];
            if (!Native.ReadProcessMemory(proc, (IntPtr)cur, code, 32, out nuint got) || got < 6)
                return cur;
            if (code[0] == 0xE9)
            {
                int rel = BitConverter.ToInt32(code, 1);
                cur = unchecked(cur + 5 + (ulong)(long)rel);
                continue;
            }
            if (code[0] == 0xEB)
            {
                cur = cur + 2 + (ulong)(sbyte)code[1];
                continue;
            }
            if (code[0] == 0xE8 && got >= 5)
            {
                int rel = BitConverter.ToInt32(code, 1);
                cur = unchecked(cur + 5 + (ulong)(long)rel);
                continue;
            }
            if (code[0] == 0xFF && code[1] == 0x25)
            {
                int rel = BitConverter.ToInt32(code, 2);
                cur = ReadU64(proc, unchecked(cur + 6 + (ulong)(long)rel));
                continue;
            }
            if (code[0] == 0xFF && code[1] == 0x15)
            {
                int rel = BitConverter.ToInt32(code, 2);
                cur = ReadU64(proc, unchecked(cur + 6 + (ulong)(long)rel));
                continue;
            }
            if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0)
            {
                cur = BitConverter.ToUInt64(code, 2);
                continue;
            }
            if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0x50 && code[11] == 0xC3)
            {
                cur = BitConverter.ToUInt64(code, 2);
                continue;
            }
            if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0)
            {
                cur = BitConverter.ToUInt64(code, 2);
                continue;
            }
            if (code[0] == 0x68 && code[5] == 0xC3)
            {
                cur = BitConverter.ToUInt32(code, 1);
                continue;
            }
            if (code[0] == 0x48 && code[1] == 0xFF && code[2] == 0x25)
            {
                int rel = BitConverter.ToInt32(code, 3);
                cur = ReadU64(proc, unchecked(cur + 7 + (ulong)(long)rel));
                continue;
            }
            if (code[0] == 0x48 && code[1] == 0x8B && code[2] == 0x05)
            {
                int rel = BitConverter.ToInt32(code, 3);
                cur = ReadU64(proc, unchecked(cur + 7 + (ulong)(long)rel));
                continue;
            }
            if (code[0] == 0x48 && code[1] == 0x8D && code[2] == 0x05)
            {
                int rel = BitConverter.ToInt32(code, 3);
                cur = unchecked(cur + 7 + (ulong)(long)rel);
                continue;
            }
            return cur;
        }
        return cur;
    }

    static ulong ReadU64(IntPtr proc, ulong addr)
    {
        var b = new byte[8];
        Native.ReadProcessMemory(proc, (IntPtr)addr, b, 8, out _);
        return BitConverter.ToUInt64(b, 0);
    }

    (string? mod, string? name, int? ord) ResolveAddr(IntPtr proc, List<RemoteModule> modules, ulong addr, bool nearby)
    {
        foreach (var m in modules)
        {
            if (addr < m.Base || addr >= m.Base + m.Size) continue;
            var exp = GetExports(proc, m.Base);
            uint rva = (uint)(addr - m.Base);
            if (exp.RvaToNames.TryGetValue(rva, out var names) && names.Count > 0)
                return (m.Name, names[0], null);
            if (!nearby) return (m.Name, null, null);
            string? near = null;
            uint best = 16;
            foreach (var (frva, nms) in exp.RvaToNames)
            {
                if (exp.Forwards.Contains(frva) || rva < frva) continue;
                if (!IsExecutable(proc, m.Base, frva)) continue;
                uint d = rva - frva;
                if (d < best) { best = d; near = nms[0]; }
            }
            if (near is not null) return (m.Name, near, null);
            return (m.Name, null, null);
        }
        return (null, null, null);
    }

    bool IsExecutable(IntPtr proc, ulong baseAddr, uint rva)
    {
        foreach (var (start, end, exec) in GetRemoteSections(proc, baseAddr))
        {
            if (rva >= start && rva < end) return exec;
        }
        return false;
    }

    List<(uint Start, uint End, bool Exec)> GetRemoteSections(IntPtr proc, ulong baseAddr)
    {
        if (_sectionCache.TryGetValue(baseAddr, out var cached)) return cached;
        var list = new List<(uint, uint, bool)>();
        try
        {
            var dos = ReadExact(proc, baseAddr, 0x40);
            int e = BitConverter.ToInt32(dos, 0x3C);
            var peh = ReadExact(proc, baseAddr + (uint)e, 0x18 + 0xF0);
            ushort num = BitConverter.ToUInt16(peh, 6);
            ushort opt = BitConverter.ToUInt16(peh, 20);
            int sh = 24 + opt;
            var sect = ReadExact(proc, baseAddr + (uint)e + (uint)sh, (uint)(num * 40));
            for (int i = 0; i < num; i++)
            {
                uint vsize = BitConverter.ToUInt32(sect, i * 40 + 8);
                uint va = BitConverter.ToUInt32(sect, i * 40 + 12);
                uint ch = BitConverter.ToUInt32(sect, i * 40 + 36);
                list.Add((va, va + Math.Max(vsize, 1), (ch & ScnMemExecute) != 0));
            }
        }
        catch
        {
            // leave empty
        }
        _sectionCache[baseAddr] = list;
        return list;
    }

    ExportInfo GetExports(IntPtr proc, ulong baseAddr)
    {
        if (_exportCache.TryGetValue(baseAddr, out var cached)) return cached;
        var info = new ExportInfo();
        try
        {
            var dos = ReadExact(proc, baseAddr, 0x40);
            int e = BitConverter.ToInt32(dos, 0x3C);
            var peh = ReadExact(proc, baseAddr + (uint)e, 0x18 + 0xF0);
            if (BitConverter.ToUInt16(peh, 24) != 0x20B) { _exportCache[baseAddr] = info; return info; }
            uint expRva = BitConverter.ToUInt32(peh, 24 + 112);
            uint expSz = BitConverter.ToUInt32(peh, 24 + 116);
            if (expRva == 0) { _exportCache[baseAddr] = info; return info; }
            var exp = ReadExact(proc, baseAddr + expRva, 40);
            uint nfunc = BitConverter.ToUInt32(exp, 20);
            uint nname = BitConverter.ToUInt32(exp, 24);
            uint afunc = BitConverter.ToUInt32(exp, 28);
            uint anames = BitConverter.ToUInt32(exp, 32);
            uint aords = BitConverter.ToUInt32(exp, 36);
            var funcs = ReadExact(proc, baseAddr + afunc, 4 * nfunc);
            var names = nname == 0 ? [] : ReadExact(proc, baseAddr + anames, 4 * nname);
            var ords = nname == 0 ? [] : ReadExact(proc, baseAddr + aords, 2 * nname);
            for (int i = 0; i < nname; i++)
            {
                uint nrva = BitConverter.ToUInt32(names, i * 4);
                ushort oi = BitConverter.ToUInt16(ords, i * 2);
                var nb = ReadExact(proc, baseAddr + nrva, 1024);
                int z = Array.IndexOf(nb, (byte)0);
                string nm = Encoding.ASCII.GetString(nb, 0, z < 0 ? nb.Length : z);
                uint frva = BitConverter.ToUInt32(funcs, oi * 4);
                if (!info.RvaToNames.TryGetValue(frva, out var list))
                    info.RvaToNames[frva] = list = [];
                list.Add(nm);
                if (frva >= expRva && frva < expRva + expSz)
                    info.Forwards.Add(frva);
            }
        }
        catch
        {
            // leave empty
        }
        _exportCache[baseAddr] = info;
        return info;
    }

    void Rebuild(PeImage pe, PeImage packedPe, List<ResolvedSlot> slots, uint iatRva, uint iatSize, bool restoreAdmin)
    {
        uint importRva = pe.DirRva[PeImage.DirImport];
        if (importRva == 0)
            importRva = packedPe.DirRva[PeImage.DirImport];

        var known = ReadImports(pe, skipLeadingZeros: true)
            .Where(d => d.FirstThunk >= iatRva && d.FirstThunk < iatRva + iatSize)
            .ToList();
        var knownFt = known.Select(d => d.FirstThunk).ToHashSet();

        uint caveRva = FindCave(pe) ?? throw new InvalidDataException("No string cave in last section.");
        uint caveUsed = 0;
        Emit($"String cave RVA=0x{caveRva:X}");

        uint AllocHint(string s)
        {
            byte[] b = [0, 0, .. Encoding.ASCII.GetBytes(s), 0];
            uint rva = caveRva + caveUsed;
            int o = pe.RvaToOff(rva);
            b.CopyTo(pe.Data, o);
            caveUsed += (uint)((b.Length + 1) & ~1);
            return rva;
        }

        uint AllocString(string s)
        {
            byte[] b = Encoding.ASCII.GetBytes(s + "\0");
            uint rva = caveRva + caveUsed;
            int o = pe.RvaToOff(rva);
            b.CopyTo(pe.Data, o);
            caveUsed += (uint)((b.Length + 1) & ~1);
            return rva;
        }

        ulong Hint(string api)
        {
            int found = FindHintName(pe, api);
            return found >= 0 ? (uint)found : AllocHint(api);
        }

        foreach (var s in slots)
        {
            if (s.Value == 0 || s.Name is null) continue;
            uint slotRva = iatRva + (uint)s.IatOffset;
            pe.WriteU64Rva(slotRva, Hint(s.Name));
        }

        OverlayPackedHooks(pe, packedPe, known, Hint);

        foreach (var d in known)
        {
            if (d.OriginalFirstThunk == 0) continue;
            for (int k = 0; k < 4096; k++)
            {
                ulong t = pe.ReadU64(d.OriginalFirstThunk + (uint)(k * 8));
                ulong iat = pe.ReadU64(d.FirstThunk + (uint)(k * 8));
                if (t == 0 && iat == 0) break;
                if (t != 0)
                    pe.WriteU64Rva(d.FirstThunk + (uint)(k * 8), t);
            }
        }

        var missing = new List<(uint Ft, string Dll, List<ResolvedSlot> Slots)>();
        foreach (var g in Groups(slots))
        {
            uint ft = iatRva + (uint)g[0].IatOffset;
            if (knownFt.Contains(ft)) continue;
            string dll = Majority(g.Select(s => s.Module)) ?? "";
            dll = string.IsNullOrEmpty(dll) ? GuessDllFromApis(g) : NormalizeImportDll(dll, g);
            if (string.IsNullOrEmpty(dll) || dll.Equals("UNKNOWN.dll", StringComparison.OrdinalIgnoreCase))
                dll = GuessDllFromApis(g);
            missing.Add((ft, dll, g));
            Emit($"  import {dll} FT=0x{ft:X} n={g.Count}");
        }

        ApplyPackedImportNames(pe, packedPe, missing, Hint);
        RemapSpecialNames(pe, iatRva, iatSize, slots, Hint);
        var ownerByFt = new Dictionary<uint, string>();
        foreach (var (ft, dll, _) in missing) ownerByFt[ft] = dll;
        foreach (var d in known) ownerByFt[d.FirstThunk] = d.Name;
        SanitizeIat(pe, iatRva, slots, ownerByFt, Hint);

        var desc = new List<byte>();
        foreach (var (ft, dll, _) in missing)
        {
            uint nameRva = FindDllName(pe, dll) ?? AllocString(dll);
            if (string.IsNullOrEmpty(pe.ReadCString(nameRva)))
                nameRva = AllocString(dll);
            desc.AddRange(BitConverter.GetBytes(0u));
            desc.AddRange(BitConverter.GetBytes(0u));
            desc.AddRange(BitConverter.GetBytes(0u));
            desc.AddRange(BitConverter.GetBytes(nameRva));
            desc.AddRange(BitConverter.GetBytes(ft));
        }
        foreach (var d in known)
        {
            uint oft = d.OriginalFirstThunk;
            if (oft != 0 && pe.ReadU64(oft) == 0)
                oft = 0;
            desc.AddRange(BitConverter.GetBytes(oft));
            desc.AddRange(new byte[8]);
            desc.AddRange(BitConverter.GetBytes(d.NameRva));
            desc.AddRange(BitConverter.GetBytes(d.FirstThunk));
        }
        desc.AddRange(new byte[20]);
        int importOff = pe.RvaToOff(importRva);
        desc.CopyTo(pe.Data, importOff);
        pe.SetDir(PeImage.DirImport, importRva, (uint)desc.Count);
        pe.SetDir(PeImage.DirIat, iatRva, iatSize);

        uint oep = FindOep(pe);
        pe.SetEntryPoint(oep);
        Emit($"OEP 0x{oep:X}");

        pe.SetImageBase(PreferredBase);
        pe.SetDllCharacteristics((ushort)(pe.DllCharacteristics & ~(0x40 | 0x20)));
        pe.SetDir(PeImage.DirReloc, 0, 0);
        pe.SetDir(PeImage.DirSecurity, 0, 0);
        FixTls(pe, packedPe);
        if (restoreAdmin)
            RestoreAdminManifest(pe);

        int left = 0;
        for (uint off = 0; off < iatSize; off += 8)
        {
            ulong t = pe.ReadU64(iatRva + off);
            if (t > pe.SizeOfImage) left++;
        }
        Emit($"Extra import strings {caveUsed} bytes, leftover trampolines {left}");
        if (left > 0)
            Emit("WARNING: IAT still contains trampoline VAs; the loader may fail.");
    }

    static void OverlayPackedHooks(PeImage pe, PeImage packedPe, List<ImportDll> known, Func<string, ulong> hint)
    {
        var packed = ReadImports(packedPe, skipLeadingZeros: false);
        foreach (var pd in packed)
        {
            if (pd.Functions.Count == 0) continue;
            var kd = known.FirstOrDefault(k => k.Name.Equals(pd.Name, StringComparison.OrdinalIgnoreCase));
            if (kd is null) continue;
            if (kd.OriginalFirstThunk == 0) continue;
            if (pe.ReadU64(kd.OriginalFirstThunk) != 0) continue;
            int n = pd.Functions.Count;
            for (int i = 0; i < n; i++)
            {
                string api = pd.Functions[i];
                if (string.IsNullOrEmpty(api) || api.StartsWith("ord")) continue;
                pe.WriteU64Rva(kd.FirstThunk + (uint)(i * 8), hint(api));
            }
            Emit($"  packed-hook overlay {pd.Name} n={n}");
        }
    }

    /// <summary>
    /// For packer-zeroed import groups we rebuild from live trampolines, prefer the
    /// packed stub's OFT names when the DLL and thunk count match. Nearby-export
    /// matches (e.g. MSVCP140_ATOMIC_WAIT) otherwise invent wrong but valid exports.
    /// </summary>
    static void ApplyPackedImportNames(
        PeImage pe,
        PeImage packedPe,
        List<(uint Ft, string Dll, List<ResolvedSlot> Slots)> missing,
        Func<string, ulong> hint)
    {
        var packed = ReadImports(packedPe, skipLeadingZeros: false);
        foreach (var (ft, dll, group) in missing)
        {
            var pd = packed.FirstOrDefault(p => p.Name.Equals(dll, StringComparison.OrdinalIgnoreCase));
            if (pd is null || pd.Functions.Count == 0) continue;
            // Prefer exact thunk-count match. For ATOMIC_WAIT the packed stub OFT order
            // can disagree with the live game IAT; use the proven layout from the
            // working unpack (calloc/free/delete_tz/free/get_tz/get_leap).
            if (dll.StartsWith("MSVCP140_ATOMIC", StringComparison.OrdinalIgnoreCase) && group.Count == 6)
            {
                string[] atomic =
                [
                    "__std_calloc_crt",
                    "__std_free_crt",
                    "__std_tzdb_delete_time_zones",
                    "__std_free_crt",
                    "__std_tzdb_get_time_zones",
                    "__std_tzdb_get_leap_seconds",
                ];
                int fixedAtomic = 0;
                for (int i = 0; i < 6; i++)
                {
                    if (string.Equals(group[i].Name, atomic[i], StringComparison.Ordinal)) continue;
                    group[i].Name = atomic[i];
                    pe.WriteU64Rva(ft + (uint)(i * 8), hint(atomic[i]));
                    fixedAtomic++;
                }
                if (fixedAtomic > 0)
                    Emit($"  atomic-known overlay {dll} FT=0x{ft:X} fixed {fixedAtomic}/6");
                continue;
            }

            bool exact = pd.Functions.Count == group.Count;
            bool prefix = pd.Functions.Count < group.Count &&
                          dll.Equals("python27.dll", StringComparison.OrdinalIgnoreCase);
            if (!exact && !prefix) continue;

            int n = Math.Min(pd.Functions.Count, group.Count);
            int changed = 0;
            for (int i = 0; i < n; i++)
            {
                string api = pd.Functions[i];
                if (string.IsNullOrEmpty(api) || api.StartsWith("ord")) continue;
                if (string.Equals(group[i].Name, api, StringComparison.Ordinal)) continue;
                group[i].Name = api;
                pe.WriteU64Rva(ft + (uint)(i * 8), hint(api));
                changed++;
            }
            if (changed > 0)
                Emit($"  packed-OFT overlay {dll} FT=0x{ft:X} fixed {changed}/{n}");
        }
    }

    static string GuessDllFromApis(List<ResolvedSlot> group)
    {
        var apis = group.Select(s => s.Name).Where(s => !string.IsNullOrEmpty(s)).Cast<string>().ToList();
        if (apis.Any(a => a.StartsWith("Shell", StringComparison.Ordinal) || a.StartsWith("SH", StringComparison.Ordinal)))
            return "SHELL32.dll";
        if (apis.Any(a => a.StartsWith("Ole", StringComparison.Ordinal) || a.StartsWith("Co", StringComparison.Ordinal)))
            return "ole32.dll";
        if (apis.Any(a => a.StartsWith("Py", StringComparison.Ordinal)))
            return "python27.dll";
        return "KERNEL32.dll";
    }

    void SanitizeIat(PeImage pe, uint iatRva, List<ResolvedSlot> slots, Dictionary<uint, string> ownerByFt, Func<string, ulong> hint)
    {
        foreach (var group in Groups(slots))
        {
            uint ft = iatRva + (uint)group[0].IatOffset;
            if (!ownerByFt.TryGetValue(ft, out var dll) || string.IsNullOrEmpty(dll))
                continue;
            for (int i = 0; i < group.Count; i++)
            {
                var s = group[i];
                if (string.IsNullOrEmpty(s.Name)) continue;
                if (!IsSystemDll(dll)) continue;
                // Always rewrite known-bad MSVCP vtable false positives even if GetProcAddress succeeds.
                bool force = s.Name.StartsWith("??_7", StringComparison.Ordinal);
                if (!force && DllExports(dll, s.Name)) continue;
                string prev = i > 0 ? group[i - 1].Name ?? "" : "";
                string next = i + 1 < group.Count ? group[i + 1].Name ?? "" : "";
                string? neu = FixNameForDll(dll, s.Name, prev, next);
                if (neu is null || !DllExports(dll, neu))
                {
                    Emit($"  SANITIZE fail {dll}!{s.Name}");
                    continue;
                }
                Emit($"  sanitize {dll} {s.Name} -> {neu}");
                s.Name = neu;
                pe.WriteU64Rva(iatRva + (uint)s.IatOffset, hint(neu));
            }
        }
    }

    static string? FixNameForDll(string dll, string name, string prev, string next)
    {
        if (dll.StartsWith("KERNEL32", StringComparison.OrdinalIgnoreCase))
        {
            if (name.Equals("GetProcessMemoryInfo", StringComparison.OrdinalIgnoreCase))
                return "K32GetProcessMemoryInfo";
        }
        if (dll.StartsWith("WS2_32", StringComparison.OrdinalIgnoreCase))
        {
            if (name.Equals("GetLastError", StringComparison.OrdinalIgnoreCase))
                return "WSAGetLastError";
        }
        if (dll.StartsWith("MSVCP140_ATOMIC", StringComparison.OrdinalIgnoreCase))
        {
            // Packed TARA stub uses CRT helpers, not the nearby mutex/tzdb exports.
            if (name is "_calloc_base" or "calloc" or "malloc" or "__std_acquire_shared_mutex_for_instance")
                return "__std_calloc_crt";
            if (name is "free" or "__std_release_shared_mutex_for_instance")
                return "__std_free_crt";
            // Mis-resolved first slots that landed on tzdb deletes instead of CRT free.
            if (name.StartsWith("__std_tzdb_delete_", StringComparison.Ordinal) &&
                (prev.StartsWith("__std_calloc", StringComparison.Ordinal) ||
                 prev.StartsWith("__std_acquire", StringComparison.Ordinal) ||
                 string.IsNullOrEmpty(prev)))
                return "__std_free_crt";
        }
        else if (dll.StartsWith("MSVCP140", StringComparison.OrdinalIgnoreCase))
        {
            // Prefer the Concurrency export the old working unpack used, not _Thrd_id.
            if (name.Equals("GetCurrentThreadId", StringComparison.OrdinalIgnoreCase))
                return "?GetCurrentThreadId@platform@details@Concurrency@@YAJXZ";
            if (name.Equals("SwitchToThread", StringComparison.OrdinalIgnoreCase))
                return "_Thrd_yield";
            if (name.Equals("localeconv", StringComparison.OrdinalIgnoreCase))
                return "?_Getlconv@_Locinfo@std@@QEBAPEBUlconv@@XZ";
            // Nearby/exact false positives: vtable symbols where ctors/dtors belong.
            if (name == "??_7_Facet_base@std@@6B@")
                return "??1?$codecvt@DDU_Mbstatet@@@std@@MEAA@XZ";
            if (name == "??_7facet@locale@std@@6B@")
                return "??0facet@locale@std@@IEAA@_K@Z";
        }
        return null;
    }

    static readonly Dictionary<string, HashSet<string>> _dllExportCache = new(StringComparer.OrdinalIgnoreCase);

    static bool DllExports(string dll, string api)
    {
        if (!_dllExportCache.TryGetValue(dll, out var set))
        {
            set = [];
            IntPtr h = Native.LoadLibraryW(dll);
            if (h == IntPtr.Zero)
            {
                _dllExportCache[dll] = set;
                return false;
            }
            _dllExportCache[dll] = set;
            Native.FreeLibrary(h);
        }
        // LoadLibrary cache of names would require parsing exports; probe GetProcAddress.
        IntPtr mod = Native.LoadLibraryW(dll);
        if (mod == IntPtr.Zero) return false;
        IntPtr p = Native.GetProcAddress(mod, api);
        Native.FreeLibrary(mod);
        return p != IntPtr.Zero;
    }

    void RemapSpecialNames(PeImage pe, uint iatRva, uint iatSize, List<ResolvedSlot> slots, Func<string, ulong> hint)
    {
        for (int off = 0; off < iatSize; off += 8)
        {
            ulong t = pe.ReadU64(iatRva + (uint)off);
            if (t == 0 || t > pe.SizeOfImage) continue;
            string name = pe.ReadCString((uint)t + 2);
            string? neu = null;
            if (Kernel32Map.TryGetValue(name, out var k32)) neu = k32;
            else if (name.Equals("NtdllDefWindowProc_A", StringComparison.Ordinal))
                neu = "DefWindowProcA";
            else if (name.Equals("NtdllDefWindowProc_W", StringComparison.Ordinal))
                neu = "DefWindowProcW";
            else if (name.StartsWith("NtUser", StringComparison.Ordinal) && name.Length > 6)
                neu = name[6..];
            else if (name == "__uncaught_exceptions")
                neu = "?uncaught_exceptions@std@@YAHXZ";
            if (neu is null) continue;
            pe.WriteU64Rva(iatRva + (uint)off, hint(neu));
            var slot = slots.FirstOrDefault(s => s.IatOffset == off);
            if (slot is not null) slot.Name = neu;
        }
    }

    static uint FindOep(PeImage pe)
    {
        var text = pe.Sections.First(s => s.Name.StartsWith(".text"));
        int start = pe.RvaToOff(text.VirtualAddress);
        int len = (int)Math.Min(text.VirtualSize, (uint)(pe.Data.Length - start));
        uint last = 0;
        for (int i = 0; i < len - 18; i++)
        {
            if (pe.Data[start + i] != 0x48 || pe.Data[start + i + 1] != 0x83 || pe.Data[start + i + 2] != 0xEC || pe.Data[start + i + 3] != 0x28)
                continue;
            if (pe.Data[start + i + 4] != 0xE8) continue;
            if (pe.Data[start + i + 9] != 0x48 || pe.Data[start + i + 10] != 0x83 || pe.Data[start + i + 11] != 0xC4 || pe.Data[start + i + 12] != 0x28)
                continue;
            if (pe.Data[start + i + 13] != 0xE9) continue;
            last = text.VirtualAddress + (uint)i;
        }
        if (last == 0) throw new InvalidDataException("MSVC CRT entry thunk not found.");
        return last;
    }

    static void FixTls(PeImage pe, PeImage packedPe)
    {
        uint tlsRva = pe.DirRva[PeImage.DirTls];
        if (tlsRva == 0) return;
        int o = pe.RvaToOff(tlsRva);
        ulong start = BitConverter.ToUInt64(pe.Data, o);
        ulong end = BitConverter.ToUInt64(pe.Data, o + 8);
        ulong index = BitConverter.ToUInt64(pe.Data, o + 16);
        ulong cb = BitConverter.ToUInt64(pe.Data, o + 24);
        uint zf = BitConverter.ToUInt32(pe.Data, o + 32);
        uint ch = BitConverter.ToUInt32(pe.Data, o + 36);

        uint packedTls = packedPe.DirRva[PeImage.DirTls];
        ulong packedCb = 0;
        if (packedTls != 0)
        {
            int po = packedPe.RvaToOff(packedTls);
            packedCb = BitConverter.ToUInt64(packedPe.Data, po + 24);
        }
        uint cbRva = packedCb >= packedPe.ImageBase ? (uint)(packedCb - packedPe.ImageBase) : (packedPe.Sections.Last().VirtualAddress + 0x10);

        if (cb > 0x7F0000000000UL)
        {
            ulong live = cb - cbRva;
            ulong Rebase(ulong va) => va == 0 ? 0 : PreferredBase + (va - live);
            start = Rebase(start);
            end = Rebase(end);
            index = Rebase(index);
            cb = Rebase(cb);
            BitConverter.GetBytes(start).CopyTo(pe.Data, o);
            BitConverter.GetBytes(end).CopyTo(pe.Data, o + 8);
            BitConverter.GetBytes(index).CopyTo(pe.Data, o + 16);
            BitConverter.GetBytes(cb).CopyTo(pe.Data, o + 24);
            BitConverter.GetBytes(zf).CopyTo(pe.Data, o + 32);
            BitConverter.GetBytes(ch).CopyTo(pe.Data, o + 36);
            Emit($"TLS live base 0x{live:X} -> preferred");
        }

        uint listRva = cb >= PreferredBase ? (uint)(cb - PreferredBase) : (uint)cb;
        int lo = pe.RvaToOff(listRva);
        if (lo >= 0)
        {
            BitConverter.GetBytes(0UL).CopyTo(pe.Data, lo);
            Emit("Cleared TLS callbacks");
        }
    }

    static void RestoreAdminManifest(PeImage pe)
    {
        foreach (var (asInvS, reqS) in new[]
        {
            ("level='asInvoker'", "level='requireAdministrator'"),
            ("level=\"asInvoker\"", "level=\"requireAdministrator\""),
        })
        {
            byte[] asInv = Encoding.ASCII.GetBytes(asInvS);
            byte[] req = Encoding.ASCII.GetBytes(reqS);
            int idx = IndexOf(pe.Data, asInv);
            if (idx < 0) continue;
            if (idx + req.Length <= pe.Data.Length)
                req.CopyTo(pe.Data, idx);
            Emit("Restored requireAdministrator manifest");
            return;
        }
    }

    static uint? FindCave(PeImage pe)
    {
        var last = pe.Sections.Last();
        int off = pe.RvaToOff(last.VirtualAddress);
        int len = (int)Math.Min(last.VirtualSize, (uint)(pe.Data.Length - off));
        const int need = 0x4000;
        var span = pe.Data.AsSpan(off, len);
        int i = 0;
        while (i + need <= span.Length)
        {
            int nz = span.Slice(i, Math.Min(need + 0x100, span.Length - i)).IndexOfAnyExcept((byte)0);
            if (nz < 0 || nz >= need)
                return last.VirtualAddress + (uint)i;
            i += nz + 1;
        }
        return last.VirtualAddress + last.VirtualSize - need;
    }

    static uint OffsetToRva(PeImage pe, int p)
    {
        if (pe.VirtualLayout) return (uint)p;
        foreach (var s in pe.Sections)
        {
            if (p >= s.PointerToRawData && p < s.PointerToRawData + s.SizeOfRawData)
                return s.VirtualAddress + (uint)(p - s.PointerToRawData);
        }
        return (uint)p;
    }

    static int FindHintName(PeImage pe, string api)
    {
        byte[] needle = Encoding.ASCII.GetBytes(api + "\0");
        var rdata = pe.Sections.FirstOrDefault(s => s.Name.StartsWith(".rdata"));
        uint rlo = rdata?.VirtualAddress ?? 0;
        uint rhi = rdata is null ? 0 : rdata.VirtualAddress + Math.Max(rdata.VirtualSize, rdata.SizeOfRawData);
        int best = -1;
        int rdataBest = -1;
        int i = 0;
        while (true)
        {
            int p = IndexOf(pe.Data, needle, i);
            if (p < 0) break;
            if (p > 0 && IsIdentByte(pe.Data[p - 1]))
            {
                i = p + 1;
                continue;
            }
            uint rva = OffsetToRva(pe, p);
            uint hint = rva >= 2 ? rva - 2 : rva;
            if (rhi > 0 && hint >= rlo && hint < rhi && rdataBest < 0)
                rdataBest = (int)hint;
            if (best < 0) best = (int)hint;
            i = p + 1;
        }
        return rdataBest >= 0 ? rdataBest : best;
    }

    static uint? FindDllName(PeImage pe, string dll)
    {
        foreach (var v in new[] { dll, dll.ToUpperInvariant(), dll.ToLowerInvariant() })
        {
            byte[] needle = Encoding.ASCII.GetBytes(v + "\0");
            int i = 0;
            while (true)
            {
                int p = IndexOf(pe.Data, needle, i);
                if (p < 0) break;
                if (p > 0 && IsIdentByte(pe.Data[p - 1]))
                {
                    i = p + 1;
                    continue;
                }
                uint rva = OffsetToRva(pe, p);
                if (pe.ReadCString(rva).Equals(v, StringComparison.OrdinalIgnoreCase))
                    return rva;
                i = p + 1;
            }
        }
        return null;
    }

    static bool IsIdentByte(byte b) =>
        (b >= (byte)'A' && b <= (byte)'Z') || (b >= (byte)'a' && b <= (byte)'z') ||
        (b >= (byte)'0' && b <= (byte)'9') || b is (byte)'_' or (byte)'.' or (byte)'?';

    static int IndexOf(byte[] hay, byte[] needle, int start = 0)
    {
        int i = hay.AsSpan(start).IndexOf(needle);
        return i < 0 ? -1 : start + i;
    }
}
