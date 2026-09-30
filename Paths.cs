namespace TRUnpacker;

static class Paths
{
    /// <summary>trgame.exe → trgame_unpacked.exe, trgameth.exe → trgameth_unpacked.exe</summary>
    public static string UnpackedOutput(string input)
    {
        string dir = Path.GetDirectoryName(input) ?? Environment.CurrentDirectory;
        string name = Path.GetFileNameWithoutExtension(input);
        string ext = Path.GetExtension(input);
        if (name.EndsWith("_unpacked", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(dir, name + ext);
        return Path.Combine(dir, name + "_unpacked" + ext);
    }

    public static string? FirstExeArg(string[] args)
    {
        foreach (var a in args)
        {
            if (string.IsNullOrWhiteSpace(a) || a.StartsWith('-')) continue;
            string p = a.Trim().Trim('"');
            if (p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(p))
                return Path.GetFullPath(p);
        }
        return null;
    }
}
