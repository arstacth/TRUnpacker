#nullable enable
using System.Drawing;
using System.Windows.Forms;

namespace TRUnpacker;

partial class MainForm
{
    System.ComponentModel.IContainer? components = null;
    Label titleLabel = null!;
    Label subtitleLabel = null!;
    Button closeButton = null!;
    Label pathCaptionLabel = null!;
    TextBox pathBox = null!;
    Button browseButton = null!;
    Button unpackButton = null!;
    CheckBox xignCheck = null!;
    Panel progressPanel = null!;
    TextBox fileLogBox = null!;
    Label statusLabel = null!;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            components?.Dispose();
        base.Dispose(disposing);
    }

    void InitializeComponent()
    {
        titleLabel = new Label();
        subtitleLabel = new Label();
        closeButton = new Button();
        pathCaptionLabel = new Label();
        pathBox = new TextBox();
        browseButton = new Button();
        unpackButton = new Button();
        xignCheck = new CheckBox();
        progressPanel = new Panel();
        fileLogBox = new TextBox();
        statusLabel = new Label();
        SuspendLayout();
        // titleLabel
        titleLabel.BackColor = Color.Transparent;
        titleLabel.Font = new Font("Segoe UI", 11F, FontStyle.Bold);
        titleLabel.ForeColor = Color.FromArgb(232, 232, 236);
        titleLabel.Location = new Point(16, 12);
        titleLabel.Name = "titleLabel";
        titleLabel.Size = new Size(360, 22);
        titleLabel.TabIndex = 0;
        titleLabel.Text = "TRUnpacker";
        // subtitleLabel
        subtitleLabel.BackColor = Color.Transparent;
        subtitleLabel.ForeColor = Color.FromArgb(150, 150, 158);
        subtitleLabel.Location = new Point(16, 34);
        subtitleLabel.Name = "subtitleLabel";
        subtitleLabel.Size = new Size(400, 18);
        subtitleLabel.TabIndex = 1;
        subtitleLabel.Text = "TalesRunner Unpack trgame.exe";
        // closeButton
        closeButton.BackColor = Color.FromArgb(32, 32, 36);
        closeButton.Cursor = Cursors.Hand;
        closeButton.FlatAppearance.BorderSize = 0;
        closeButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(180, 60, 60);
        closeButton.FlatStyle = FlatStyle.Flat;
        closeButton.ForeColor = Color.FromArgb(232, 232, 236);
        closeButton.Location = new Point(480, 8);
        closeButton.Name = "closeButton";
        closeButton.Size = new Size(28, 28);
        closeButton.TabIndex = 2;
        closeButton.TabStop = false;
        closeButton.Text = "×";
        closeButton.UseVisualStyleBackColor = false;
        closeButton.Click += closeButton_Click;
        // pathCaptionLabel
        pathCaptionLabel.BackColor = Color.Transparent;
        pathCaptionLabel.ForeColor = Color.FromArgb(150, 150, 158);
        pathCaptionLabel.Location = new Point(16, 64);
        pathCaptionLabel.Name = "pathCaptionLabel";
        pathCaptionLabel.Size = new Size(200, 16);
        pathCaptionLabel.TabIndex = 3;
        pathCaptionLabel.Text = "trgame.exe";
        // pathBox
        pathBox.AllowDrop = true;
        pathBox.BackColor = Color.FromArgb(32, 32, 36);
        pathBox.BorderStyle = BorderStyle.FixedSingle;
        pathBox.ForeColor = Color.FromArgb(232, 232, 236);
        pathBox.Location = new Point(16, 84);
        pathBox.Name = "pathBox";
        pathBox.Size = new Size(390, 26);
        pathBox.TabIndex = 4;
        pathBox.DragDrop += MainForm_DragDrop;
        pathBox.DragEnter += MainForm_DragEnter;
        pathBox.TextChanged += pathBox_TextChanged;
        // browseButton
        browseButton.BackColor = Color.FromArgb(32, 32, 36);
        browseButton.Cursor = Cursors.Hand;
        browseButton.FlatAppearance.BorderSize = 0;
        browseButton.FlatStyle = FlatStyle.Flat;
        browseButton.ForeColor = Color.FromArgb(232, 232, 236);
        browseButton.Location = new Point(414, 83);
        browseButton.Name = "browseButton";
        browseButton.Size = new Size(90, 28);
        browseButton.TabIndex = 5;
        browseButton.TabStop = false;
        browseButton.Text = "Browse";
        browseButton.UseVisualStyleBackColor = false;
        browseButton.Click += browseButton_Click;
        // unpackButton
        unpackButton.BackColor = Color.FromArgb(88, 166, 255);
        unpackButton.Cursor = Cursors.Hand;
        unpackButton.Enabled = false;
        unpackButton.FlatAppearance.BorderSize = 0;
        unpackButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(110, 180, 255);
        unpackButton.FlatStyle = FlatStyle.Flat;
        unpackButton.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
        unpackButton.ForeColor = Color.FromArgb(16, 16, 18);
        unpackButton.Location = new Point(16, 122);
        unpackButton.Name = "unpackButton";
        unpackButton.Size = new Size(488, 28);
        unpackButton.TabIndex = 6;
        unpackButton.Text = "Unpack";
        unpackButton.UseVisualStyleBackColor = false;
        unpackButton.Click += unpackButton_Click;
        // xignCheck
        xignCheck.AutoSize = false;
        xignCheck.BackColor = Color.FromArgb(22, 22, 24);
        xignCheck.Checked = true;
        xignCheck.CheckState = CheckState.Checked;
        xignCheck.Cursor = Cursors.Hand;
        xignCheck.FlatStyle = FlatStyle.Standard;
        xignCheck.ForeColor = Color.FromArgb(180, 180, 188);
        xignCheck.Location = new Point(16, 156);
        xignCheck.Name = "xignCheck";
        xignCheck.Size = new Size(280, 20);
        xignCheck.TabIndex = 7;
        xignCheck.Text = "Disable XIGNCODE";
        xignCheck.UseVisualStyleBackColor = false;
        // progressPanel
        progressPanel.BackColor = Color.FromArgb(32, 32, 36);
        progressPanel.Location = new Point(16, 182);
        progressPanel.Name = "progressPanel";
        progressPanel.Size = new Size(488, 6);
        progressPanel.TabIndex = 8;
        progressPanel.Paint += progressPanel_Paint;
        // fileLogBox
        fileLogBox.BackColor = Color.FromArgb(32, 32, 36);
        fileLogBox.BorderStyle = BorderStyle.FixedSingle;
        fileLogBox.Font = new Font("Consolas", 8.5F);
        fileLogBox.ForeColor = Color.FromArgb(232, 232, 236);
        fileLogBox.Location = new Point(16, 196);
        fileLogBox.Multiline = true;
        fileLogBox.Name = "fileLogBox";
        fileLogBox.ReadOnly = true;
        fileLogBox.ScrollBars = ScrollBars.Vertical;
        fileLogBox.Size = new Size(488, 132);
        fileLogBox.TabIndex = 9;
        fileLogBox.TabStop = false;
        // statusLabel
        statusLabel.BackColor = Color.Transparent;
        statusLabel.ForeColor = Color.FromArgb(150, 150, 158);
        statusLabel.Location = new Point(16, 332);
        statusLabel.Name = "statusLabel";
        statusLabel.Size = new Size(488, 14);
        statusLabel.TabIndex = 10;
        statusLabel.Text = "";
        // MainForm
        AllowDrop = true;
        AutoScaleDimensions = new SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        BackColor = Color.FromArgb(22, 22, 24);
        ClientSize = new Size(520, 352);
        Controls.Add(statusLabel);
        Controls.Add(fileLogBox);
        Controls.Add(progressPanel);
        Controls.Add(xignCheck);
        Controls.Add(unpackButton);
        Controls.Add(browseButton);
        Controls.Add(pathBox);
        Controls.Add(pathCaptionLabel);
        Controls.Add(closeButton);
        Controls.Add(subtitleLabel);
        Controls.Add(titleLabel);
        Font = new Font("Segoe UI", 9F);
        ForeColor = Color.FromArgb(232, 232, 236);
        FormBorderStyle = FormBorderStyle.None;
        MaximizeBox = false;
        MinimizeBox = false;
        Name = "MainForm";
        ShowInTaskbar = true;
        StartPosition = FormStartPosition.CenterScreen;
        Text = "TRUnpacker";
        DragDrop += MainForm_DragDrop;
        DragEnter += MainForm_DragEnter;
        ResumeLayout(false);
        PerformLayout();
    }
}
