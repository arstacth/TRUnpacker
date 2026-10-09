namespace TRUnpacker;

static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        bool patchOnly = args.Any(a => a is "--patch-only" or "--repatch");
        bool disableXign = !args.Contains("--no-xigncode");
        bool patchLvs = args.Any(a => a is "--patch-loadbalance" or "--lvs");

        // Drop file onto TRUnpacker.exe → unpack (or --patch-only) immediately, no GUI.
        string? dropped = Paths.FirstExeArg(args);
        if (dropped is not null)
        {
            Environment.ExitCode = patchOnly
                ? RunPatchOnly(dropped, disableXign, patchLvs)
                : RunHeadless(dropped, disableXign, patchLvs);
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }

    static int RunHeadless(string input, bool disableXign, bool patchLvs)
    {
        string output = Paths.UnpackedOutput(input);
        try
        {
            new Unpacker(input, output, disableXigncode: disableXign, patchLoadBalance: patchLvs).Run();
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

    /// <summary>Re-apply optional patches onto an already-unpacked exe.</summary>
    static int RunPatchOnly(string input, bool disableXign, bool patchLvs)
    {
        string output = Paths.UnpackedOutput(input);
        try
        {
            byte[] raw = File.ReadAllBytes(input);
            byte[] image = (byte[])raw.Clone();
            var pe = PeImage.Parse(image, virtualLayout: false);

            if (disableXign)
                image = XigncodePatcher.Apply(image, Console.WriteLine);
            if (patchLvs)
            {
                pe = PeImage.Parse(image, virtualLayout: false);
                LoadBalancePatcher.Apply(image, pe, Console.WriteLine);
            }
            if (!disableXign && !patchLvs)
            {
                Console.Error.WriteLine("Nothing to patch. Use default XIGNCODE patch and/or --patch-loadbalance.");
                return 1;
            }

            string tmp = output + ".tmp";
            File.WriteAllBytes(tmp, image);
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
