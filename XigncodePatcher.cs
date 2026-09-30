using System.Text;

namespace TRUnpacker;

/// <summary>
/// Offline anti-cheat / anti-debug patches for unpacked trgame.exe:
/// 1) UAC manifest → asInvoker
/// 2) Stub XIGNCODE init (ZCWAVE_SysInit/SysEnter) so Wellbia never starts
///    (R186611 pinned call site OR string-discovered function)
/// 3) Stub CHackingDetection::detectHacking (IsDebuggerPresent / tool scans)
/// 4) Force IsDebuggerPresent IAT calls to return 0
/// 5) Crash reporter URL → loopback
/// String-based discovery — works across builds with different VAs.
/// </summary>
static class XigncodePatcher
{
    const ulong PreferredBase = 0x140000000;
    const ulong XigncodeInitVa = 0x141cefa90;
    const ulong CallVa = 0x141d0181c;
    const uint ScnMemExecute = 0x20000000;

    static readonly byte[] OldManifest = Encoding.ASCII.GetBytes("level='requireAdministrator'");
    static readonly byte[] NewManifest = Encoding.ASCII.GetBytes("level='asInvoker'" + new string(' ', 11));
    static readonly byte[] OldManifestQ = Encoding.ASCII.GetBytes("level=\"requireAdministrator\"");
    static readonly byte[] NewManifestQ = Encoding.ASCII.GetBytes("level=\"asInvoker\"" + new string(' ', 11));

    // R186611: call XIGNCODE_Init → mov al,1; nop*3
    static readonly byte[] OldCall = [0xE8, 0x6F, 0xE2, 0xFE, 0xFF];
    static readonly byte[] NewCall = [0xB0, 0x01, 0x90, 0x90, 0x90];

    // Function stubs (overwrite prologue, immediate ret).
    static readonly byte[] StubReturnTrue = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]; // mov eax,1; ret
    static readonly byte[] StubDetectHacking =
    [
        0x31, 0xC0,       // xor eax, eax
        0x41, 0x88, 0x00, // mov byte ptr [r8], al  (clear out-flag)
        0xC3,             // ret
    ];
    // call qword ptr [rip+disp] (6) → xor eax,eax; nop*4
    static readonly byte[] StubIsDebuggerPresent = [0x31, 0xC0, 0x90, 0x90, 0x90, 0x90];

    static readonly byte[] OldUrl = Encoding.ASCII.GetBytes("http://crash.rhaon.com/cgi-bin/posterr.cgi");
    static readonly byte[] NewUrl = BuildPaddedUrl(
        "http://127.0.0.1:1/cgi-bin/posterr.cgi",
        "http://crash.rhaon.com/cgi-bin/posterr.cgi");

    public sealed class Result
    {
        public bool Manifest;
        public bool XigncodeCall;
        public bool XigncodeFunc;
        public bool DetectHacking;
        public int IsDebuggerPresent;
        public bool CrashUrl;
        public bool Any => Manifest || XigncodeCall || XigncodeFunc || DetectHacking || IsDebuggerPresent > 0 || CrashUrl;
    }

    public static byte[] Apply(byte[] raw, Action<string>? log = null)
    {
        var pe = PeImage.Parse(raw, virtualLayout: false);
        if (pe.ImageBase != PreferredBase)
            log?.Invoke($"WARNING: ImageBase 0x{pe.ImageBase:X} (expected 0x{PreferredBase:X})");

        var image = (byte[])raw.Clone();
        var result = new Result();

        result.Manifest = PatchManifest(image, log);
        result.XigncodeCall = PatchXigncodeCall(image, pe, log);
        result.XigncodeFunc = PatchXigncodeFunction(image, pe, log);
        result.DetectHacking = PatchDetectHacking(image, pe, log);
        result.IsDebuggerPresent = PatchIsDebuggerPresentCalls(image, pe, log);
        result.CrashUrl = PatchCrashUrl(image, pe, log);

        log?.Invoke(
            $"Anti-cheat patch: manifest={(result.Manifest ? "yes" : "no")} " +
            $"xignCall={(result.XigncodeCall ? "yes" : "no")} " +
            $"xignFunc={(result.XigncodeFunc ? "yes" : "no")} " +
            $"detectHacking={(result.DetectHacking ? "yes" : "no")} " +
            $"IsDebuggerPresent={result.IsDebuggerPresent} " +
            $"crashUrl={(result.CrashUrl ? "yes" : "no")}");

        // Required: XIGNCODE must be stubbed and in-game detectHacking disabled.
        bool xignOk = result.XigncodeCall || result.XigncodeFunc;
        if (!xignOk || !result.DetectHacking)
        {
            var missing = new List<string>();
            if (!xignOk) missing.Add("XIGNCODE init");
            if (!result.DetectHacking) missing.Add("CHackingDetection::detectHacking");
            throw new InvalidDataException(
                "Failed to disable XIGNCODE on this build (missing: " +
                string.Join(", ", missing) +
                "). Expected an unpacked trgame.exe with XIGNCODE.");
        }

        return image;
    }

    static bool PatchManifest(byte[] image, Action<string>? log)
    {
        if (ReplaceOnce(image, OldManifest, NewManifest) || ReplaceOnce(image, OldManifestQ, NewManifestQ))
        {
            log?.Invoke("Patched UAC manifest → asInvoker");
            return true;
        }
        if (IndexOf(image, Encoding.ASCII.GetBytes("level='asInvoker'")) >= 0 ||
            IndexOf(image, Encoding.ASCII.GetBytes("level=\"asInvoker\"")) >= 0)
        {
            log?.Invoke("Manifest already asInvoker");
            return true;
        }
        log?.Invoke("Manifest string not found");
        return false;
    }

    static bool PatchCrashUrl(byte[] image, PeImage pe, Action<string>? log)
    {
        int idx = IndexOf(image, OldUrl);
        if (idx >= 0)
        {
            NewUrl.CopyTo(image, idx);
            log?.Invoke($"Patched crash URL @ file 0x{idx:X}");
            return true;
        }
        if (IndexOf(image, Encoding.ASCII.GetBytes("http://127.0.0.1:1/cgi-bin/posterr.cgi")) >= 0)
        {
            log?.Invoke("Crash URL already redirected");
            return true;
        }
        try
        {
            int off = pe.RvaToOff((uint)(0x142aa69d0UL - PreferredBase));
            if (off >= 0 && off + OldUrl.Length <= image.Length &&
                image.AsSpan(off, OldUrl.Length).SequenceEqual(OldUrl))
            {
                NewUrl.CopyTo(image, off);
                log?.Invoke($"Patched crash URL @ pinned file 0x{off:X}");
                return true;
            }
        }
        catch { /* ignore */ }
        log?.Invoke("Crash URL not found (ok if build differs)");
        return false;
    }

    static bool PatchXigncodeCall(byte[] image, PeImage pe, Action<string>? log)
    {
        if (IndexOfInExecutable(image, pe, NewCall) >= 0 &&
            FindCallsTo(image, pe, XigncodeInitVa).Count == 0)
        {
            log?.Invoke("XIGNCODE_Init call already disabled");
            return true;
        }

        try
        {
            int callOff = pe.RvaToOff((uint)(CallVa - PreferredBase));
            if (callOff >= 0 && callOff + OldCall.Length <= image.Length &&
                image.AsSpan(callOff, OldCall.Length).SequenceEqual(OldCall))
            {
                NewCall.CopyTo(image, callOff);
                log?.Invoke($"Patched XIGNCODE_Init call @ file 0x{callOff:X} (pinned R186611)");
                return true;
            }
        }
        catch { /* fall through */ }

        var sites = FindCallsTo(image, pe, XigncodeInitVa);
        if (sites.Count == 1)
        {
            NewCall.CopyTo(image, sites[0]);
            log?.Invoke($"Patched XIGNCODE_Init call @ file 0x{sites[0]:X} (scanned)");
            return true;
        }
        if (sites.Count > 1)
        {
            log?.Invoke($"Found {sites.Count} callers of XIGNCODE_Init — refusing ambiguous patch");
            return false;
        }

        int unique = IndexOfInExecutable(image, pe, OldCall);
        if (unique >= 0)
        {
            NewCall.CopyTo(image, unique);
            log?.Invoke($"Patched XIGNCODE_Init call @ file 0x{unique:X} (byte match)");
            return true;
        }
        return false;
    }

    /// <summary>
    /// Discover ZCWAVE_SysInit/SysEnter function via log string LEA and stub it to return success.
    /// This stops embedded Wellbia/XIGNCODE from starting (FindWindow / CE detection / minimize).
    /// </summary>
    static bool PatchXigncodeFunction(byte[] image, PeImage pe, Action<string>? log)
    {
        foreach (var needle in new[]
                 {
                     "[XIGNCODE]ZCWAVE_SysInit() start\0",
                     "[XIGNCODE]ZCWAVE_SysEnter() start\0",
                     "[XIGNCODE]Initializing...\0",
                 })
        {
            if (!TryFindStringVa(image, pe, needle, out ulong strVa))
                continue;
            var refs = FindLeaRefs(image, pe, strVa);
            foreach (ulong refVa in refs)
            {
                ulong? func = FindFunctionStart(image, pe, refVa);
                if (func is null) continue;
                int off = pe.RvaToOff((uint)(func.Value - PreferredBase));
                if (off < 0 || off + StubReturnTrue.Length > image.Length) continue;

                if (image.AsSpan(off, StubReturnTrue.Length).SequenceEqual(StubReturnTrue))
                {
                    log?.Invoke($"XIGNCODE init already stubbed @ VA 0x{func.Value:X}");
                    return true;
                }

                // Prefer the real SysInit/SysEnter function (sub rsp, 0x318) over a random leaf.
                bool looksLikeInit =
                    image[off] == 0x48 && image[off + 1] == 0x81 && image[off + 2] == 0xEC || // sub rsp, imm32
                    image[off] == 0x48 && image[off + 1] == 0x83 && image[off + 2] == 0xEC || // sub rsp, imm8
                    refs.Count == 1;

                if (!looksLikeInit && !needle.Contains("SysInit") && !needle.Contains("SysEnter"))
                    continue;

                StubReturnTrue.CopyTo(image, off);
                log?.Invoke($"Stubbed XIGNCODE init → return 1 @ VA 0x{func.Value:X} (via {needle.TrimEnd('\0')})");
                return true;
            }
        }
        log?.Invoke("XIGNCODE init function not found via strings");
        return false;
    }

    static bool PatchDetectHacking(byte[] image, PeImage pe, Action<string>? log)
    {
        if (!TryFindStringVa(image, pe, "CHackingDetection::detectHacking\0", out ulong strVa))
        {
            log?.Invoke("CHackingDetection::detectHacking string not found");
            return false;
        }
        var refs = FindLeaRefs(image, pe, strVa);
        if (refs.Count == 0)
        {
            log?.Invoke("No LEA refs to detectHacking string");
            return false;
        }

        // Majority-vote function start — later LEA sites can land mid-function on some builds (KR).
        var votes = new Dictionary<ulong, int>();
        foreach (ulong r in refs)
        {
            var f = FindFunctionStart(image, pe, r);
            if (f is null) continue;
            votes[f.Value] = votes.GetValueOrDefault(f.Value) + 1;
        }
        if (votes.Count == 0)
        {
            log?.Invoke("detectHacking function start not found");
            return false;
        }
        ulong func = votes.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).First().Key;

        int off = pe.RvaToOff((uint)(func - PreferredBase));
        if (off < 0 || off + StubDetectHacking.Length > image.Length)
            return false;

        if (image.AsSpan(off, StubDetectHacking.Length).SequenceEqual(StubDetectHacking))
        {
            log?.Invoke($"detectHacking already stubbed @ VA 0x{func:X}");
            return true;
        }

        StubDetectHacking.CopyTo(image, off);
        log?.Invoke($"Stubbed CHackingDetection::detectHacking @ VA 0x{func:X}");
        return true;
    }

    static int PatchIsDebuggerPresentCalls(byte[] image, PeImage pe, Action<string>? log)
    {
        ulong? iat = FindImportIatVa(pe, image, "IsDebuggerPresent");
        if (iat is null)
        {
            log?.Invoke("IsDebuggerPresent not in IAT");
            return 0;
        }

        int patched = 0;
        int already = 0;
        foreach (var sec in pe.Sections)
        {
            if ((sec.Characteristics & ScnMemExecute) == 0) continue;
            // Only patch the main image .text — skip RWX stub/embedded sections.
            if (!sec.Name.StartsWith(".text", StringComparison.Ordinal)) continue;

            int start = (int)sec.PointerToRawData;
            int end = Math.Min(start + (int)sec.SizeOfRawData, image.Length);
            for (int at = start; at + 6 <= end; at++)
            {
                if (image[at] != 0xFF || image[at + 1] != 0x15) continue;
                int rel = BitConverter.ToInt32(image, at + 1 + 1);
                ulong va = PreferredBase + sec.VirtualAddress + (uint)(at - start);
                if (unchecked(va + 6 + (ulong)(long)rel) != iat.Value) continue;

                if (image.AsSpan(at, 6).SequenceEqual(StubIsDebuggerPresent))
                {
                    already++;
                    continue;
                }
                StubIsDebuggerPresent.CopyTo(image, at);
                patched++;
            }
        }
        if (patched > 0 || already > 0)
            log?.Invoke($"IsDebuggerPresent → return 0: patched {patched}, already {already}");
        return patched + already;
    }

    static ulong? FindImportIatVa(PeImage pe, byte[] image, string api)
    {
        uint p = pe.DirRva[PeImage.DirImport];
        if (p == 0) return null;
        while (true)
        {
            int o = pe.RvaToOff(p);
            if (o < 0) return null;
            uint oft = BitConverter.ToUInt32(image, o);
            uint nameRva = BitConverter.ToUInt32(image, o + 12);
            uint ft = BitConverter.ToUInt32(image, o + 16);
            if (oft == 0 && nameRva == 0) break;
            uint thunk = oft != 0 ? oft : ft;
            for (int k = 0; k < 4096; k++)
            {
                int to = pe.RvaToOff(thunk + (uint)(k * 8));
                if (to < 0) break;
                ulong val = BitConverter.ToUInt64(image, to);
                if (val == 0) break;
                if ((val & (1UL << 63)) != 0) continue;
                string nm = pe.ReadCString((uint)val + 2);
                if (nm.Equals(api, StringComparison.Ordinal))
                    return PreferredBase + ft + (uint)(k * 8);
            }
            p += 20;
        }
        return null;
    }

    static bool TryFindStringVa(byte[] image, PeImage pe, string s, out ulong va)
    {
        byte[] needle = Encoding.ASCII.GetBytes(s);
        int idx = IndexOf(image, needle);
        if (idx < 0) { va = 0; return false; }
        va = FileOffToVa(pe, idx);
        return va != 0;
    }

    static ulong FileOffToVa(PeImage pe, int off)
    {
        foreach (var sec in pe.Sections)
        {
            if (off >= sec.PointerToRawData && off < sec.PointerToRawData + sec.SizeOfRawData)
                return PreferredBase + sec.VirtualAddress + (uint)(off - sec.PointerToRawData);
        }
        return 0;
    }

    static List<ulong> FindLeaRefs(byte[] data, PeImage pe, ulong targetVa)
    {
        var refs = new List<ulong>();
        foreach (var sec in pe.Sections)
        {
            if ((sec.Characteristics & ScnMemExecute) == 0) continue;
            int start = (int)sec.PointerToRawData;
            int end = Math.Min(start + (int)sec.SizeOfRawData, data.Length);
            for (int at = start; at + 7 <= end; at++)
            {
                if (data[at] != 0x48 || data[at + 1] != 0x8D) continue;
                byte modrm = data[at + 2];
                if ((modrm & 0xC7) != 0x05) continue; // [rip+disp32] forms: 05/0D/15/1D/25/2D/35/3D
                int disp = BitConverter.ToInt32(data, at + 3);
                ulong va = PreferredBase + sec.VirtualAddress + (uint)(at - start);
                if (unchecked(va + 7 + (ulong)(long)disp) == targetVa)
                    refs.Add(va);
            }
        }
        return refs;
    }

    static ulong? FindFunctionStart(byte[] data, PeImage pe, ulong nearVa)
    {
        int nearOff = pe.RvaToOff((uint)(nearVa - PreferredBase));
        if (nearOff < 0) return null;

        for (int back = 0; back < 0x800; back++)
        {
            int o = nearOff - back;
            if (o < 1) break;

            // int3 padding then next byte is start
            if (back > 0 && data[o] == 0xCC && data[o + 1] != 0xCC)
                return FileOffToVa(pe, o + 1);

            // mov [rsp+..], rbx
            if (o + 4 <= data.Length && data[o] == 0x48 && data[o + 1] == 0x89 && data[o + 2] == 0x5C && data[o + 3] == 0x24)
                return FileOffToVa(pe, o);

            // mov rax, rsp
            if (o + 3 <= data.Length && data[o] == 0x48 && data[o + 1] == 0x8B && data[o + 2] == 0xC4)
                return FileOffToVa(pe, o);

            // sub rsp, imm32
            if (o + 3 <= data.Length && data[o] == 0x48 && data[o + 1] == 0x81 && data[o + 2] == 0xEC)
                return FileOffToVa(pe, o);
        }
        return null;
    }

    static List<int> FindCallsTo(byte[] data, PeImage pe, ulong targetVa)
    {
        var sites = new List<int>();
        foreach (var sec in pe.Sections)
        {
            if ((sec.Characteristics & ScnMemExecute) == 0) continue;
            int start = (int)sec.PointerToRawData;
            int end = Math.Min(start + (int)sec.SizeOfRawData, data.Length);
            for (int at = start; at + 5 <= end; at++)
            {
                if (data[at] != 0xE8) continue;
                int rel = BitConverter.ToInt32(data, at + 1);
                ulong va = PreferredBase + sec.VirtualAddress + (uint)(at - start);
                if (unchecked(va + 5 + (ulong)(long)rel) == targetVa)
                    sites.Add(at);
            }
        }
        return sites;
    }

    static int IndexOfInExecutable(byte[] data, PeImage pe, byte[] needle)
    {
        int found = -1;
        foreach (var sec in pe.Sections)
        {
            if ((sec.Characteristics & ScnMemExecute) == 0) continue;
            int start = (int)sec.PointerToRawData;
            int len = Math.Min((int)sec.SizeOfRawData, data.Length - start);
            if (len <= 0) continue;
            int local = data.AsSpan(start, len).IndexOf(needle);
            if (local < 0) continue;
            if (found >= 0) return -1;
            found = start + local;
        }
        return found;
    }

    static bool ReplaceOnce(byte[] image, byte[] oldBytes, byte[] newBytes)
    {
        if (oldBytes.Length != newBytes.Length) return false;
        int idx = IndexOf(image, oldBytes);
        if (idx < 0) return false;
        newBytes.CopyTo(image, idx);
        return true;
    }

    static byte[] BuildPaddedUrl(string neu, string old)
    {
        var n = Encoding.ASCII.GetBytes(neu);
        var o = Encoding.ASCII.GetBytes(old);
        if (n.Length > o.Length) throw new InvalidOperationException("URL patch grows length");
        var pad = new byte[o.Length];
        n.CopyTo(pad, 0);
        for (int i = n.Length; i < pad.Length; i++) pad[i] = (byte)'/';
        return pad;
    }

    static int IndexOf(byte[] hay, byte[] needle) => hay.AsSpan().IndexOf(needle);
}
