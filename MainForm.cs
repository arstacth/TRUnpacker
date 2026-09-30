using System.Drawing;
using System.Windows.Forms;

namespace TRUnpacker;

public partial class MainForm : Form
{
    static readonly Color Panel = Color.FromArgb(32, 32, 36);
    static readonly Color Border = Color.FromArgb(58, 58, 64);
    static readonly Color Muted = Color.FromArgb(150, 150, 158);
    static readonly Color Accent = Color.FromArgb(88, 166, 255);
    static readonly Color Ok = Color.FromArgb(110, 200, 140);
    static readonly Color Err = Color.FromArgb(232, 110, 110);

    readonly List<string> _log = [];
    Point _dragOffset;
    bool _dragging;
    bool _busy;
    int _barValue;
    int _barMax = 1;

    public MainForm()
    {
        InitializeComponent();
        DoubleBuffered = true;
        xignCheck.BringToFront();

        MouseDown += OnDragStart;
        MouseMove += OnDragMove;
        MouseUp += OnDragEnd;
        foreach (Control c in new Control[] { titleLabel, subtitleLabel, pathCaptionLabel, statusLabel, progressPanel })
        {
            c.MouseDown += OnDragStart;
            c.MouseMove += OnDragMove;
            c.MouseUp += OnDragEnd;
        }
    }

    protected override CreateParams CreateParams
    {
        get
        {
            CreateParams cp = base.CreateParams;
            cp.ClassStyle |= 0x20000;
            return cp;
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        using var pen = new Pen(Border);
        e.Graphics.DrawRectangle(pen, 0, 0, Width - 1, Height - 1);
    }

    void closeButton_Click(object? sender, EventArgs e) => Close();

    void pathBox_TextChanged(object? sender, EventArgs e) => UpdateReady();

    void UpdateReady()
    {
        if (_busy) return;
        string input = (pathBox.Text ?? "").Trim().Trim('"');
        unpackButton.Enabled = File.Exists(input);
    }

    void browseButton_Click(object? sender, EventArgs e)
    {
        if (_busy) return;
        using var dlg = new OpenFileDialog
        {
            Title = "Select trgame.exe",
            Filter = "Executable (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        string cur = (pathBox.Text ?? "").Trim().Trim('"');
        if (File.Exists(cur))
        {
            dlg.FileName = Path.GetFileName(cur);
            string? dir = Path.GetDirectoryName(cur);
            if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                dlg.InitialDirectory = dir;
        }
        if (dlg.ShowDialog(this) == DialogResult.OK)
            pathBox.Text = dlg.FileName;
    }

    void unpackButton_Click(object? sender, EventArgs e) => StartUnpack();

    void MainForm_DragEnter(object? sender, DragEventArgs e)
    {
        if (e.Data is not null && e.Data.GetDataPresent(DataFormats.FileDrop))
            e.Effect = DragDropEffects.Copy;
    }

    void MainForm_DragDrop(object? sender, DragEventArgs e)
    {
        if (_busy) return;
        if (e.Data?.GetData(DataFormats.FileDrop) is not string[] files || files.Length == 0)
            return;
        pathBox.Text = files[0];
    }

    void progressPanel_Paint(object? sender, PaintEventArgs e)
    {
        e.Graphics.Clear(Panel);
        int max = _barMax <= 0 ? 1 : _barMax;
        int w = (int)(progressPanel.Width * ((double)_barValue / max));
        if (w > 0)
        {
            using var b = new SolidBrush(Accent);
            e.Graphics.FillRectangle(b, 0, 0, Math.Min(w, progressPanel.Width), progressPanel.Height);
        }
    }

    void StartUnpack()
    {
        if (_busy) return;
        string input = (pathBox.Text ?? "").Trim().Trim('"');
        if (input.Length == 0 || !File.Exists(input))
        {
            SetStatus("Select a valid .exe first.", Err);
            return;
        }

        string output = Paths.UnpackedOutput(input);
        bool disableXign = xignCheck.Checked;

        _busy = true;
        unpackButton.Enabled = false;
        browseButton.Enabled = false;
        pathBox.Enabled = false;
        xignCheck.Enabled = false;
        _log.Clear();
        fileLogBox.Clear();
        SetProgress(0, 8, null);
        SetStatus("Working...", Muted);

        var thread = new Thread(() =>
        {
            try
            {
                new Unpacker(
                    input,
                    output,
                    disableXigncode: disableXign,
                    log: line => AppendLog(line),
                    progress: (cur, total, name) =>
                    {
                        SetProgress(cur, total, name);
                        if (!string.IsNullOrEmpty(name))
                            SetStatus(name!, Muted);
                    }).Run();
                SetProgress(1, 1, null);
                SetStatus("Done! → " + Path.GetFileName(output), Ok);
                AppendLog("Wrote " + output);
            }
            catch (Exception ex)
            {
                Ui(() => MessageBox.Show(this, ex.Message, "TRUnpacker", MessageBoxButtons.OK, MessageBoxIcon.Error));
                SetStatus("Failed.", Err);
                AppendLog(ex.Message);
            }
            finally
            {
                Ui(() =>
                {
                    _busy = false;
                    pathBox.Enabled = true;
                    xignCheck.Enabled = true;
                    browseButton.Enabled = true;
                    UpdateReady();
                });
            }
        })
        {
            IsBackground = true,
        };
        thread.Start();
    }

    void AppendLog(string line)
    {
        Ui(() =>
        {
            _log.Add(line);
            while (_log.Count > 40)
                _log.RemoveAt(0);
            fileLogBox.Text = string.Join("\r\n", _log);
            fileLogBox.SelectionStart = fileLogBox.TextLength;
            fileLogBox.ScrollToCaret();
        });
    }

    void SetStatus(string text, Color color)
    {
        Ui(() =>
        {
            statusLabel.ForeColor = color;
            statusLabel.Text = text;
        });
    }

    void SetProgress(int value, int max, string? file)
    {
        Ui(() =>
        {
            _barMax = max <= 0 ? 1 : max;
            _barValue = value;
            progressPanel.Invalidate();
            if (!string.IsNullOrEmpty(file))
            {
                _log.Add(file!);
                while (_log.Count > 40)
                    _log.RemoveAt(0);
                fileLogBox.Text = string.Join("\r\n", _log);
            }
        });
    }

    void Ui(Action action)
    {
        if (IsDisposed) return;
        if (InvokeRequired)
        {
            try { BeginInvoke(action); } catch { /* closing */ }
            return;
        }
        action();
    }

    void OnDragStart(object? sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left) return;
        _dragging = true;
        Control? c = sender as Control;
        Point client = e.Location;
        if (c is not null && c != this)
            client = PointToClient(c.PointToScreen(e.Location));
        _dragOffset = client;
    }

    void OnDragMove(object? sender, MouseEventArgs e)
    {
        if (!_dragging) return;
        Point screen = Cursor.Position;
        Location = new Point(screen.X - _dragOffset.X, screen.Y - _dragOffset.Y);
    }

    void OnDragEnd(object? sender, MouseEventArgs e) => _dragging = false;
}
