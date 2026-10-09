using System.Text;

namespace TRUnpacker;

/// <summary>
/// HK (and similar) clients whitelist LoadBalance host as lvs.talesrunner.com.hk.
/// TH accepts the host/port from the login server instead.
/// This patch NOPs the hardcoded host + length checks so HK behaves like TH.
/// </summary>
static class LoadBalancePatcher
{
    const ulong PreferredBase = 0x140000000;
    const uint ScnMemExecute = 0x20000000;

    static readonly string[] HostNeedles =
    [
        "lvs.talesrunner.com.hk\0",
        "lvs.talesrunner.com\0",
    ];

    /// <summary>
    /// Returns true if a LoadBalance host whitelist was found and bypassed.
    /// Returns false if no hardcoded host was present (already TH-like) — not an error.
    /// </summary>
    public static bool Apply(byte[] image, PeImage pe, Action<string>? log = null)
    {
        foreach (string needle in HostNeedles)
        {
            if (!TryFindStringVa(image, pe, needle, out ulong strVa))
                continue;

            var refs = FindLeaRefs(image, pe, strVa);
            if (refs.Count == 0)
            {
                log?.Invoke($"LoadBalance host string found but no code refs: {needle.TrimEnd('\0')}");
                continue;
            }

            int patched = 0;
            foreach (ulong leaVa in refs)
            {
                if (BypassWhitelistAfterLea(image, pe, leaVa, log))
                    patched++;
            }

            if (patched > 0)
            {
                log?.Invoke(
                    $"Patched LoadBalance host whitelist ({needle.TrimEnd('\0')}) — " +
                    $"{patched} site(s), now accepts server-provided LVS like TH");
                return true;
            }
        }

        log?.Invoke("LoadBalance patch: no hardcoded LVS host whitelist found (already TH-like)");
        return false;
    }

    /// <summary>
    /// After: lea rdx, [host]; call cmp; test eax,eax; jne fail; cmp rbx,imm; jne fail
    /// NOP both conditional jumps so any host/port from the server is accepted.
    /// </summary>
    static bool BypassWhitelistAfterLea(byte[] image, PeImage pe, ulong leaVa, Action<string>? log)
    {
        int leaOff = pe.RvaToOff((uint)(leaVa - PreferredBase));
        if (leaOff < 0 || leaOff + 7 > image.Length) return false;
        if (image[leaOff] != 0x48 || image[leaOff + 1] != 0x8D) return false;

        // Expect call after LEA (E8 rel32)
        int callOff = leaOff + 7;
        if (callOff + 5 > image.Length || image[callOff] != 0xE8) return false;

        int testOff = callOff + 5;
        if (testOff + 2 > image.Length || image[testOff] != 0x85 || image[testOff + 1] != 0xC0)
            return false;

        int jne1 = testOff + 2;
        if (!IsJccRel32(image, jne1) && !IsJccRel8(image, jne1))
            return false;

        bool already1 = IsNop(image, jne1, JccSize(image, jne1));
        if (!already1)
            Nop(image, jne1, JccSize(image, jne1));

        // Second check: cmp rbx/reg, imm ; jne fail  (within ~16 bytes)
        int scan = jne1 + JccSize(image, jne1);
        int jne2 = FindNextJneAfterCmp(image, scan, scan + 24);
        bool already2 = false;
        if (jne2 >= 0)
        {
            already2 = IsNop(image, jne2, JccSize(image, jne2));
            if (!already2)
                Nop(image, jne2, JccSize(image, jne2));
        }

        if (already1 && (jne2 < 0 || already2))
        {
            log?.Invoke($"LoadBalance whitelist already bypassed @ VA 0x{leaVa:X}");
            return true;
        }

        log?.Invoke($"Bypassed LoadBalance host check @ VA 0x{leaVa:X}");
        return true;
    }

    static int FindNextJneAfterCmp(byte[] image, int start, int end)
    {
        end = Math.Min(end, image.Length - 6);
        for (int i = start; i < end; i++)
        {
            // cmp rbx, imm8 : 48 83 FB xx
            // cmp ebx, imm8 : 83 FB xx
            // cmp rbx, imm32: 48 81 FB xx xx xx xx
            bool cmp =
                (i + 4 <= image.Length && image[i] == 0x48 && image[i + 1] == 0x83 && image[i + 2] == 0xFB) ||
                (i + 3 <= image.Length && image[i] == 0x83 && image[i + 1] == 0xFB) ||
                (i + 7 <= image.Length && image[i] == 0x48 && image[i + 1] == 0x81 && image[i + 2] == 0xFB);
            if (!cmp) continue;

            int after = image[i] == 0x48
                ? (image[i + 1] == 0x83 ? i + 4 : i + 7)
                : i + 3;
            if (IsJccRel32(image, after) || IsJccRel8(image, after))
                return after;
        }
        return -1;
    }

    static bool IsJccRel32(byte[] image, int off) =>
        off + 6 <= image.Length && image[off] == 0x0F && image[off + 1] is >= 0x80 and <= 0x8F;

    static bool IsJccRel8(byte[] image, int off) =>
        off + 2 <= image.Length && image[off] is >= 0x70 and <= 0x7F;

    static int JccSize(byte[] image, int off) => IsJccRel32(image, off) ? 6 : 2;

    static bool IsNop(byte[] image, int off, int len)
    {
        for (int i = 0; i < len; i++)
            if (image[off + i] != 0x90) return false;
        return true;
    }

    static void Nop(byte[] image, int off, int len)
    {
        for (int i = 0; i < len; i++)
            image[off + i] = 0x90;
    }

    static bool TryFindStringVa(byte[] image, PeImage pe, string s, out ulong va)
    {
        byte[] needle = Encoding.ASCII.GetBytes(s);
        int idx = image.AsSpan().IndexOf(needle);
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
                if ((data[at + 2] & 0xC7) != 0x05) continue;
                int disp = BitConverter.ToInt32(data, at + 3);
                ulong va = PreferredBase + sec.VirtualAddress + (uint)(at - start);
                if (unchecked(va + 7 + (ulong)(long)disp) == targetVa)
                    refs.Add(va);
            }
        }
        return refs;
    }
}
