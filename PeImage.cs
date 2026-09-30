using System.Buffers.Binary;
using System.Text;

namespace TRUnpacker;

sealed class Section
{
    public string Name = "";
    public uint VirtualAddress;
    public uint VirtualSize;
    public uint PointerToRawData;
    public uint SizeOfRawData;
    public uint Characteristics;
}

sealed class PeImage
{
    public byte[] Data = [];
    public bool VirtualLayout;
    public int E_lfanew;
    public int OptionalHeader;
    public ushort Magic;
    public uint AddressOfEntryPoint;
    public ulong ImageBase;
    public uint SectionAlignment;
    public uint FileAlignment;
    public uint SizeOfImage;
    public uint SizeOfHeaders;
    public ushort DllCharacteristics;
    public uint NumberOfRvaAndSizes;
    public readonly uint[] DirRva = new uint[16];
    public readonly uint[] DirSize = new uint[16];
    public readonly List<Section> Sections = [];

    public const int DirImport = 1;
    public const int DirSecurity = 4;
    public const int DirReloc = 5;
    public const int DirTls = 9;
    public const int DirIat = 12;

    public static PeImage Parse(byte[] data, bool virtualLayout)
    {
        var pe = new PeImage { Data = data, VirtualLayout = virtualLayout };
        pe.E_lfanew = BitConverter.ToInt32(data, 0x3C);
        pe.OptionalHeader = pe.E_lfanew + 24;
        pe.Magic = BitConverter.ToUInt16(data, pe.OptionalHeader);
        if (pe.Magic != 0x20B)
            throw new InvalidDataException("Not a PE32+ image.");
        pe.AddressOfEntryPoint = BitConverter.ToUInt32(data, pe.OptionalHeader + 16);
        pe.ImageBase = BitConverter.ToUInt64(data, pe.OptionalHeader + 24);
        pe.SectionAlignment = BitConverter.ToUInt32(data, pe.OptionalHeader + 32);
        pe.FileAlignment = BitConverter.ToUInt32(data, pe.OptionalHeader + 36);
        pe.SizeOfImage = BitConverter.ToUInt32(data, pe.OptionalHeader + 56);
        pe.SizeOfHeaders = BitConverter.ToUInt32(data, pe.OptionalHeader + 60);
        pe.DllCharacteristics = BitConverter.ToUInt16(data, pe.OptionalHeader + 70);
        pe.NumberOfRvaAndSizes = BitConverter.ToUInt32(data, pe.OptionalHeader + 108);
        int dirs = (int)Math.Min(pe.NumberOfRvaAndSizes, 16);
        for (int i = 0; i < dirs; i++)
        {
            pe.DirRva[i] = BitConverter.ToUInt32(data, pe.OptionalHeader + 112 + i * 8);
            pe.DirSize[i] = BitConverter.ToUInt32(data, pe.OptionalHeader + 112 + i * 8 + 4);
        }
        int num = BitConverter.ToUInt16(data, pe.E_lfanew + 6);
        int optSize = BitConverter.ToUInt16(data, pe.E_lfanew + 20);
        int sh = pe.E_lfanew + 24 + optSize;
        for (int i = 0; i < num; i++)
        {
            int rec = sh + i * 40;
            pe.Sections.Add(new Section
            {
                Name = Encoding.ASCII.GetString(data, rec, 8).TrimEnd('\0'),
                VirtualSize = BitConverter.ToUInt32(data, rec + 8),
                VirtualAddress = BitConverter.ToUInt32(data, rec + 12),
                SizeOfRawData = BitConverter.ToUInt32(data, rec + 16),
                PointerToRawData = BitConverter.ToUInt32(data, rec + 20),
                Characteristics = BitConverter.ToUInt32(data, rec + 36),
            });
        }
        return pe;
    }

    public int RvaToOff(uint rva)
    {
        if (VirtualLayout)
        {
            if (rva >= Data.Length) return -1;
            return (int)rva;
        }
        foreach (var s in Sections)
        {
            uint span = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span)
                return (int)(s.PointerToRawData + (rva - s.VirtualAddress));
        }
        if (rva < SizeOfHeaders) return (int)rva;
        return -1;
    }

    public uint ReadU32(uint rva) => BitConverter.ToUInt32(Data, RvaToOff(rva));
    public ulong ReadU64(uint rva) => BitConverter.ToUInt64(Data, RvaToOff(rva));
    public void WriteU16(int fileOff, ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(Data.AsSpan(fileOff), v);
    public void WriteU32(int fileOff, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(Data.AsSpan(fileOff), v);
    public void WriteU64(int fileOff, ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(Data.AsSpan(fileOff), v);

    public void WriteU32Rva(uint rva, uint v)
    {
        int o = RvaToOff(rva);
        if (o < 0) throw new InvalidDataException($"RVA {rva:X} not mapped.");
        WriteU32(o, v);
    }

    public void WriteU64Rva(uint rva, ulong v)
    {
        int o = RvaToOff(rva);
        if (o < 0) throw new InvalidDataException($"RVA {rva:X} not mapped.");
        WriteU64(o, v);
    }

    public string ReadCString(uint rva, int max = 512)
    {
        int o = RvaToOff(rva);
        if (o < 0) return "";
        int n = 0;
        while (o + n < Data.Length && n < max && Data[o + n] != 0) n++;
        return Encoding.ASCII.GetString(Data, o, n);
    }

    public void SetEntryPoint(uint rva)
    {
        AddressOfEntryPoint = rva;
        WriteU32(OptionalHeader + 16, rva);
    }

    public void SetImageBase(ulong baseAddr)
    {
        ImageBase = baseAddr;
        WriteU64(OptionalHeader + 24, baseAddr);
    }

    public void SetDir(int index, uint rva, uint size)
    {
        DirRva[index] = rva;
        DirSize[index] = size;
        WriteU32(OptionalHeader + 112 + index * 8, rva);
        WriteU32(OptionalHeader + 112 + index * 8 + 4, size);
    }

    public void SetDllCharacteristics(ushort value)
    {
        DllCharacteristics = value;
        WriteU16(OptionalHeader + 70, value);
    }

    public static uint Align(uint value, uint align) => (value + align - 1) & ~(align - 1);

    public byte[] ToVirtualImage()
    {
        var buf = new byte[SizeOfImage];
        int hdr = (int)Math.Min(SizeOfHeaders, (uint)Data.Length);
        if (hdr > 0)
            Buffer.BlockCopy(Data, 0, buf, 0, hdr);
        foreach (var s in Sections)
        {
            int src = VirtualLayout ? (int)s.VirtualAddress : (int)s.PointerToRawData;
            int dst = (int)s.VirtualAddress;
            uint span = Math.Max(s.VirtualSize, s.SizeOfRawData);
            if (src < 0 || dst < 0 || dst >= buf.Length) continue;
            int take = (int)Math.Min(span, (uint)Math.Max(0, Data.Length - src));
            take = Math.Min(take, buf.Length - dst);
            if (take > 0)
                Buffer.BlockCopy(Data, src, buf, dst, take);
        }
        return buf;
    }

    public byte[] ToPeFile()
    {
        uint fileAlign = FileAlignment == 0 ? 0x200u : FileAlignment;
        uint headerSize = Align(SizeOfHeaders, fileAlign);
        int optSize = BitConverter.ToUInt16(Data, E_lfanew + 20);
        int sectionTable = E_lfanew + 24 + optSize;
        var ordered = Sections;

        uint cursor = headerSize;
        var payloads = new List<byte[]>();
        for (int i = 0; i < ordered.Count; i++)
        {
            var s = ordered[i];
            uint payload = Math.Max(s.VirtualSize, 1);
            uint rawSize = Align(payload, fileAlign);
            int src = VirtualLayout ? (int)s.VirtualAddress : (int)s.PointerToRawData;
            var buf = new byte[rawSize];
            int take = src >= 0 ? (int)Math.Min(payload, (uint)Math.Max(0, Data.Length - src)) : 0;
            if (take > 0)
                Buffer.BlockCopy(Data, src, buf, 0, take);

            int rec = sectionTable + i * 40;
            WriteU32(rec + 8, s.VirtualSize);
            WriteU32(rec + 12, s.VirtualAddress);
            WriteU32(rec + 16, rawSize);
            WriteU32(rec + 20, cursor);
            s.SizeOfRawData = rawSize;
            s.PointerToRawData = cursor;
            payloads.Add(buf);
            cursor += rawSize;
        }

        var file = new byte[cursor];
        int hdrCopy = (int)Math.Min(headerSize, (uint)Data.Length);
        Buffer.BlockCopy(Data, 0, file, 0, hdrCopy);
        uint off = headerSize;
        foreach (var buf in payloads)
        {
            Buffer.BlockCopy(buf, 0, file, (int)off, buf.Length);
            off += (uint)buf.Length;
        }
        return file;
    }
}
