namespace TRUnpacker;

static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        bool patchOnly = args.Any(a => a is "--patch-only" or "--repatch");
        bool disableXign = !args.Contains("--no-xigncode");

        // Drop file onto TRUnpacker.exe → unpack (or --patch-only) immediately, no GUI.
        string? dropped = Paths.FirstExeArg(args);
        if (dropped is not null)
        {
            Environment.ExitCode = patchOnly
                ? RunPatchOnly(dropped)
                : RunHeadless(dropped, disableXign);
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }

    static int RunHeadless(string input, bool disableXign)
    {
        string output = Paths.UnpackedOutput(input);
        try
        {
            new Unpacker(input, output, disableXigncode: disableXign).Run();
            return 0;
        }
        catch (Exception ex)
        {
            try
            {
                MessageBox.Show(ex.Message, "TRUnpacker", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch
            {
                // no UI desktop
            }
            return 1;
        }
    }

    /// <summary>Re-apply anti-cheat stubs onto an already-unpacked exe (in place → *_unpacked.exe).</summary>
    static int RunPatchOnly(string input)
    {
        string output = Paths.UnpackedOutput(input);
        try
        {
            byte[] raw = File.ReadAllBytes(input);
            byte[] patched = XigncodePatcher.Apply(raw, Console.WriteLine);
            string tmp = output + ".tmp";
            File.WriteAllBytes(tmp, patched);
            if (File.Exists(output))
                File.Delete(output);
            File.Move(tmp, output);
            Console.WriteLine($"Wrote {output}");
            return 0;
        }
        catch (Exception ex)
        {
            try
            {
                MessageBox.Show(ex.Message, "TRUnpacker", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch { /* no UI */ }
            Console.Error.WriteLine(ex);
            return 1;
        }
    }
}
