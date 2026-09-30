using System.Text;

namespace TRUnpacker;

static class StubDll
{
    public static byte[] Build(string dllName, IReadOnlyList<string> exports, ulong imageBase)
    {
        var names = exports.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).Distinct().OrderBy(s => s, StringComparer.Ordinal).ToList();
        int nNamed = names.Count;
        int nFuncs = Math.Max(nNamed, 1);

        byte[] gadgetMain = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]; // mov eax,1; ret
        byte[] gadgetApi = [0x48, 0x31, 0xC0, 0xC3]; // xor rax,rax; ret
        var text = new byte[0x200];
        gadgetMain.CopyTo(text, 0);
        gadgetApi.CopyTo(text, 6);

        const uint expRva = 0x2000;
        const uint apiRva = 0x1006;
        uint funcTable = expRva + 40;
        uint nameTable = funcTable + (uint)(4 * nFuncs);
        uint ordTable = nameTable + (uint)(4 * nNamed);
        uint strRva = (ordTable + (uint)(2 * nNamed) + 1) & ~1u;

        var blobs = new List<(uint rva, byte[] bytes)>();
        uint dllStr = strRva;
        blobs.Add((dllStr, Encoding.ASCII.GetBytes(dllName + "\0")));
        uint cur = strRva + (uint)dllName.Length + 1;
        var nameRvas = new List<uint>();
        foreach (var n in names)
        {
            nameRvas.Add(cur);
            var b = Encoding.ASCII.GetBytes(n + "\0");
            blobs.Add((cur, b));
            cur += (uint)b.Length;
        }

        uint rdataRaw = PeImage.Align(Math.Max(cur - expRva, 1), 0x200);
        var rdata = new byte[rdataRaw];
        WriteU32(rdata, 0, 0);
        WriteU32(rdata, 4, 0);
        WriteU16(rdata, 8, 0);
        WriteU16(rdata, 10, 0);
        WriteU32(rdata, 12, dllStr);
        WriteU32(rdata, 16, 1);
        WriteU32(rdata, 20, (uint)nFuncs);
        WriteU32(rdata, 24, (uint)nNamed);
        WriteU32(rdata, 28, funcTable);
        WriteU32(rdata, 32, nameTable);
        WriteU32(rdata, 36, ordTable);
        for (int i = 0; i < nFuncs; i++)
            WriteU32(rdata, (int)(funcTable - expRva) + i * 4, apiRva);
        for (int i = 0; i < nNamed; i++)
        {
            WriteU32(rdata, (int)(nameTable - expRva) + i * 4, nameRvas[i]);
            WriteU16(rdata, (int)(ordTable - expRva) + i * 2, (ushort)i);
        }
        foreach (var (rva, bytes) in blobs)
            bytes.CopyTo(rdata, rva - expRva);

        uint rdataVsize = PeImage.Align(rdataRaw, 0x1000);
        uint sizeOfImage = 0x2000 + rdataVsize;

        var dos = new byte[0x80];
        dos[0] = (byte)'M';
        dos[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(dos, 0x3C);

        var pe = new byte[4 + 20 + 0xF0 + 80];
        pe[0] = (byte)'P'; pe[1] = (byte)'E';
        WriteU16(pe, 4, 0x8664);
        WriteU16(pe, 6, 2);
        WriteU16(pe, 20, 0xF0);
        WriteU16(pe, 22, 0x2022);
        WriteU16(pe, 24, 0x20B);
        WriteU32(pe, 24 + 16, 0x1000);
        BitConverter.GetBytes(imageBase).CopyTo(pe, 24 + 24);
        WriteU32(pe, 24 + 32, 0x1000);
        WriteU32(pe, 24 + 36, 0x200);
        WriteU16(pe, 24 + 40, 6);
        WriteU16(pe, 24 + 48, 6);
        WriteU32(pe, 24 + 56, sizeOfImage);
        WriteU32(pe, 24 + 60, 0x200);
        WriteU16(pe, 24 + 68, 2);
        WriteU16(pe, 24 + 70, 0x100);
        BitConverter.GetBytes(0x100000UL).CopyTo(pe, 24 + 72);
        BitConverter.GetBytes(0x1000UL).CopyTo(pe, 24 + 80);
        BitConverter.GetBytes(0x100000UL).CopyTo(pe, 24 + 88);
        BitConverter.GetBytes(0x1000UL).CopyTo(pe, 24 + 96);
        WriteU32(pe, 24 + 108, 16);
        WriteU32(pe, 24 + 112, expRva);
        WriteU32(pe, 24 + 116, Math.Max(rdataRaw, 40));

        int sh = 24 + 0xF0;
        Encoding.ASCII.GetBytes(".text").CopyTo(pe, sh);
        WriteU32(pe, sh + 8, 0x200);
        WriteU32(pe, sh + 12, 0x1000);
        WriteU32(pe, sh + 16, 0x200);
        WriteU32(pe, sh + 20, 0x200);
        WriteU32(pe, sh + 36, 0xE0000020);
        Encoding.ASCII.GetBytes(".rdata").CopyTo(pe, sh + 40);
        WriteU32(pe, sh + 48, rdataVsize);
        WriteU32(pe, sh + 52, 0x2000);
        WriteU32(pe, sh + 56, rdataRaw);
        WriteU32(pe, sh + 60, 0x400);
        WriteU32(pe, sh + 76, 0x40000040);

        var result = new byte[0x200 + text.Length + rdata.Length];
        dos.CopyTo(result, 0);
        pe.CopyTo(result, 0x80);
        text.CopyTo(result, 0x200);
        rdata.CopyTo(result, 0x400);
        return result;
    }

    static void WriteU16(byte[] b, int o, ushort v) => BitConverter.GetBytes(v).CopyTo(b, o);
    static void WriteU32(byte[] b, int o, uint v) => BitConverter.GetBytes(v).CopyTo(b, o);
}
