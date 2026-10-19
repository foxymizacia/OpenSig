using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace OpenSig;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm(args));
    }
}

internal sealed class AppSettings
{
    public string PrivateKeyPath { get; set; } = "";
    public string PublicKeyPath { get; set; } = "";
    public string EdPrivateKeyPath { get; set; } = "";
    public string EdPublicKeyPath { get; set; } = "";
    public string Algorithm { get; set; } = "RSA";
}

internal enum SignatureAlgorithm { RsaSha256, Ed25519 }

internal sealed record OperationResult(string Source, string Status, string Detail, bool IsSuccess);

internal sealed class MainForm : Form
{
    private static readonly Color BackgroundColor = Color.FromArgb(246, 248, 251);
    private static readonly Color AccentColor = Color.FromArgb(50, 92, 210);
    private static readonly Color PrimaryText = Color.FromArgb(32, 43, 60);
    private static readonly Color MutedText = Color.FromArgb(98, 111, 128);

    private readonly string _applicationFolder = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpenSig");

    private readonly RadioButton _signMode = new();
    private readonly RadioButton _verifyMode = new();
    private readonly ComboBox _algorithmBox = new();
    private readonly Label _headerSubtitle = new();
    private readonly TextBox _privateKeyBox = new();
    private readonly TextBox _publicKeyBox = new();
    private readonly Button _pickPrivateButton = new();
    private readonly Button _pickPublicButton = new();
    private readonly Button _createKeysButton = new();
    private readonly Button _openKeysButton = new();
    private readonly Button _pickFilesButton = new();
    private readonly ListView _results = new();
    private readonly Label _dropTitle = new();
    private readonly Label _dropSubtitle = new();
    private readonly Label _status = new();
    private readonly Panel _dropZone = new();
    private readonly ProgressBar _progress = new();

    private readonly string[] _startupFiles;
    private readonly ToolTip _pathToolTip = new();
    private string _privateKeyPath = "";
    private string _publicKeyPath = "";
    private string _rsaPrivateKeyPath = "";
    private string _rsaPublicKeyPath = "";
    private string _edPrivateKeyPath = "";
    private string _edPublicKeyPath = "";
    private SignatureAlgorithm _selectedAlgorithm = SignatureAlgorithm.RsaSha256;
    private bool _settingsLoaded;
    private bool _busy;

    public MainForm(string[] startupFiles)
    {
        _startupFiles = startupFiles;
        Text = "OpenSig — подписи OpenSSL";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(920, 685);
        MinimumSize = new Size(780, 700);
        BackColor = BackgroundColor;
        Font = new Font("Segoe UI", 10f);
        AutoScaleMode = AutoScaleMode.Dpi;

        BuildInterface();
        LoadSettings();
        _settingsLoaded = true;
        RefreshKeyPaths();
        UpdateModeAppearance();
        RegisterDropTargets(this);

        Shown += async (_, _) =>
        {
            await InitializeOnFirstLaunchAsync();
            // Windows passes paths as arguments when files are dropped onto the .exe/shortcut.
            if (_startupFiles.Length > 0)
                await ProcessFilesAsync(_startupFiles);
        };
    }

    private void BuildInterface()
    {
        var header = new Panel { Dock = DockStyle.Top, Height = 88, BackColor = Color.White };
        header.Controls.Add(new Label
        {
            Text = "OpenSig",
            ForeColor = PrimaryText,
            Font = new Font("Segoe UI Semibold", 22f, FontStyle.Bold),
            Location = new Point(24, 11),
            Size = new Size(240, 40)
        });
        _headerSubtitle.Text = "Создание и проверка подписей • RSA / SHA-256 и Ed25519 • OpenSSL";
        _headerSubtitle.ForeColor = MutedText;
        _headerSubtitle.Location = new Point(26, 53);
        _headerSubtitle.AutoSize = true;
        header.Controls.Add(_headerSubtitle);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 5,
            Padding = new Padding(24, 14, 24, 12),
            BackColor = BackgroundColor
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 143));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 169));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        Controls.Add(layout);
        // Dock the header after the filling layout so it reserves its own space.
        Controls.Add(header);

        var modeRow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(0, 0, 0, 5)
        };
        modeRow.Controls.Add(new Label
        {
            Text = "Режим:", AutoSize = true,
            ForeColor = PrimaryText,
            Padding = new Padding(0, 9, 8, 0)
        });
        _signMode.Text = "Создать подпись";
        _signMode.AutoSize = true;
        _signMode.Checked = true;
        _signMode.Margin = new Padding(5, 8, 28, 0);
        _signMode.CheckedChanged += (_, _) => UpdateModeAppearance();
        modeRow.Controls.Add(_signMode);

        _verifyMode.Text = "Проверить подпись";
        _verifyMode.AutoSize = true;
        _verifyMode.Margin = new Padding(0, 8, 0, 0);
        _verifyMode.CheckedChanged += (_, _) => UpdateModeAppearance();
        modeRow.Controls.Add(_verifyMode);
        modeRow.Controls.Add(new Label
        {
            Text = "Алгоритм:", AutoSize = true, ForeColor = PrimaryText,
            Padding = new Padding(12, 9, 5, 0)
        });
        _algorithmBox.DropDownStyle = ComboBoxStyle.DropDownList;
        _algorithmBox.Width = 205;
        _algorithmBox.Margin = new Padding(3, 5, 0, 0);
        _algorithmBox.Items.AddRange(new object[] { "RSA-3072 / SHA-256", "Ed25519" });
        _algorithmBox.SelectedIndex = 0;
        _algorithmBox.SelectedIndexChanged += async (_, _) => await ChangeAlgorithmAsync();
        modeRow.Controls.Add(_algorithmBox);
        layout.Controls.Add(modeRow, 0, 0);

        var keySurface = new Panel
        {
            Dock = DockStyle.Fill, BackColor = Color.White,
            Margin = new Padding(0, 0, 0, 9), Padding = new Padding(12, 6, 12, 5)
        };
        layout.Controls.Add(keySurface, 0, 1);

        var keyGrid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 3 };
        keyGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 132));
        keyGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        keyGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 105));
        keyGrid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
        keyGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 43));
        keyGrid.RowStyles.Add(new RowStyle(SizeType.Absolute, 43));
        keyGrid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        keySurface.Controls.Add(keyGrid);

        AddKeyLabel(keyGrid, "Закрытый ключ", 0);
        AddKeyLabel(keyGrid, "Открытый ключ", 1);
        ConfigurePathBox(_privateKeyBox);
        ConfigurePathBox(_publicKeyBox);
        keyGrid.Controls.Add(_privateKeyBox, 1, 0);
        keyGrid.Controls.Add(_publicKeyBox, 1, 1);
        ConfigureButton(_pickPrivateButton, "Выбрать…", false);
        ConfigureButton(_pickPublicButton, "Выбрать…", false);
        ConfigureButton(_createKeysButton, "Создать ключи", true);
        ConfigureButton(_openKeysButton, "Папка ключей", false);
        keyGrid.Controls.Add(_pickPrivateButton, 2, 0);
        keyGrid.Controls.Add(_pickPublicButton, 2, 1);
        keyGrid.Controls.Add(_createKeysButton, 3, 0);
        keyGrid.Controls.Add(_openKeysButton, 3, 1);

        var keyFootnote = new Label
        {
            Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft,
            AutoEllipsis = true,
            Text = "Закрытый ключ не передавайте другим. Для проверки подписи нужен соответствующий открытый ключ.",
            ForeColor = MutedText, Font = new Font("Segoe UI", 8.7f),
            Margin = new Padding(6, 0, 0, 0)
        };
        keyGrid.Controls.Add(keyFootnote, 0, 2);
        keyGrid.SetColumnSpan(keyFootnote, 4);

        _pickPrivateButton.Click += (_, _) => ChooseKey(isPrivate: true);
        _pickPublicButton.Click += (_, _) => ChooseKey(isPrivate: false);
        _createKeysButton.Click += async (_, _) => await CreateKeysByUserAsync();
        _openKeysButton.Click += (_, _) => OpenKeysFolder();

        _dropZone.Dock = DockStyle.Fill;
        _dropZone.BackColor = Color.White;
        _dropZone.Margin = new Padding(0, 0, 0, 12);
        _dropZone.Paint += (_, e) =>
        {
            using var outline = new Pen(AccentColor, 2f) { DashStyle = DashStyle.Dash };
            var bounds = new Rectangle(2, 2, _dropZone.ClientSize.Width - 5, _dropZone.ClientSize.Height - 5);
            if (bounds.Width > 0 && bounds.Height > 0) e.Graphics.DrawRectangle(outline, bounds);
        };
        layout.Controls.Add(_dropZone, 0, 2);

        _dropTitle.Font = new Font("Segoe UI Semibold", 18f, FontStyle.Bold);
        _dropTitle.ForeColor = PrimaryText;
        _dropTitle.TextAlign = ContentAlignment.MiddleCenter;
        _dropTitle.AutoSize = false;
        _dropZone.Controls.Add(_dropTitle);
        _dropSubtitle.ForeColor = MutedText;
        _dropSubtitle.TextAlign = ContentAlignment.MiddleCenter;
        _dropSubtitle.AutoSize = false;
        _dropZone.Controls.Add(_dropSubtitle);
        ConfigureButton(_pickFilesButton, "Выбрать файлы", true);
        _dropZone.Controls.Add(_pickFilesButton);
        _pickFilesButton.Click += async (_, _) => await PickFilesAsync();
        _dropZone.Resize += (_, _) => PlaceDropZoneContents();
        PlaceDropZoneContents();

        var resultsSurface = new Panel
        {
            Dock = DockStyle.Fill, BackColor = Color.White,
            Margin = new Padding(0), Padding = new Padding(12, 9, 12, 9)
        };
        layout.Controls.Add(resultsSurface, 0, 3);
        var resultLayout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2,
            Margin = Padding.Empty, Padding = Padding.Empty
        };
        resultLayout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        resultLayout.RowStyles.Add(new RowStyle(SizeType.Absolute, 29));
        resultLayout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        resultsSurface.Controls.Add(resultLayout);
        resultLayout.Controls.Add(new Label
        {
            Text = "Результаты", Dock = DockStyle.Fill,
            ForeColor = PrimaryText, Font = new Font("Segoe UI Semibold", 11f, FontStyle.Bold)
        }, 0, 0);
        _results.Dock = DockStyle.Fill;
        _results.View = View.Details;
        _results.FullRowSelect = true;
        _results.MultiSelect = false;
        _results.HeaderStyle = ColumnHeaderStyle.Nonclickable;
        _results.GridLines = false;
        _results.BorderStyle = BorderStyle.None;
        _results.Columns.Add("Файл", 290);
        _results.Columns.Add("Результат", 142);
        _results.Columns.Add("Подпись / примечание", 350);
        _results.Resize += (_, _) => ResizeResultColumns();
        _results.DoubleClick += (_, _) => RevealSelectedFile();
        resultLayout.Controls.Add(_results, 0, 1);
        ResizeResultColumns();

        var footer = new Panel { Dock = DockStyle.Fill, Margin = new Padding(0, 5, 0, 0) };
        _status.Dock = DockStyle.Fill;
        _status.ForeColor = MutedText;
        _status.TextAlign = ContentAlignment.MiddleLeft;
        _status.AutoEllipsis = true;
        _status.Text = "Готово. Перетащите файл в окно приложения.";
        footer.Controls.Add(_status);
        _progress.Dock = DockStyle.Right;
        _progress.Width = 130;
        _progress.Style = ProgressBarStyle.Marquee;
        _progress.MarqueeAnimationSpeed = 30;
        _progress.Visible = false;
        footer.Controls.Add(_progress);
        layout.Controls.Add(footer, 0, 4);
    }

    private static void AddKeyLabel(TableLayoutPanel grid, string text, int row)
    {
        grid.Controls.Add(new Label
        {
            Text = text,
            ForeColor = PrimaryText,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            Margin = new Padding(6, 0, 0, 0)
        }, 0, row);
    }

    private static void ConfigurePathBox(TextBox textBox)
    {
        textBox.Dock = DockStyle.Fill;
        textBox.ReadOnly = true;
        textBox.BorderStyle = BorderStyle.FixedSingle;
        textBox.BackColor = Color.FromArgb(250, 251, 253);
        textBox.Margin = new Padding(0, 9, 9, 8);
    }

    private static void ConfigureButton(Button button, string text, bool primary)
    {
        button.Text = text;
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = primary ? 0 : 1;
        button.FlatAppearance.BorderColor = Color.FromArgb(208, 216, 229);
        button.BackColor = primary ? AccentColor : Color.White;
        button.ForeColor = primary ? Color.White : PrimaryText;
        button.Font = new Font("Segoe UI Semibold", 9.4f, FontStyle.Bold);
        button.Cursor = Cursors.Hand;
        button.Margin = new Padding(5, 6, 0, 6);
        button.Dock = DockStyle.Fill;
    }

    private void PlaceDropZoneContents()
    {
        var width = _dropZone.ClientSize.Width;
        var height = _dropZone.ClientSize.Height;
        var top = Math.Max(4, (height - 135) / 2);
        _dropTitle.SetBounds(12, top, Math.Max(0, width - 24), 43);
        _dropSubtitle.SetBounds(12, top + 43, Math.Max(0, width - 24), 28);
        _pickFilesButton.Dock = DockStyle.None;
        _pickFilesButton.SetBounds(Math.Max(8, (width - 190) / 2), top + 80, 190, 39);
    }

    private void ResizeResultColumns()
    {
        if (_results.Columns.Count != 3) return;
        var available = Math.Max(420, _results.ClientSize.Width - SystemInformation.VerticalScrollBarWidth - 4);
        _results.Columns[0].Width = (int)(available * 0.36);
        _results.Columns[1].Width = 146;
        _results.Columns[2].Width = Math.Max(100, available - _results.Columns[0].Width - 146);
    }

    private void UpdateModeAppearance()
    {
        if (_signMode.Checked)
        {
            _dropTitle.Text = "Перетащите файлы сюда";
            _dropSubtitle.Text = "Создадим рядом с каждым файлом отдельную подпись .sig";
            _pickFilesButton.Text = "Выбрать файлы";
        }
        else
        {
            _dropTitle.Text = "Перетащите файл или .sig";
            _dropSubtitle.Text = "Проверим подпись по открытому ключу; файл и .sig должны лежать рядом";
            _pickFilesButton.Text = "Выбрать для проверки";
        }
        _headerSubtitle.Text = _selectedAlgorithm == SignatureAlgorithm.Ed25519
            ? "Создание и проверка подписей • Ed25519 • совместимо с OpenSSL"
            : "Создание и проверка подписей • RSA / SHA-256 • совместимо с OpenSSL";
        _dropZone.Invalidate();
    }

    private void RegisterDropTargets(Control control)
    {
        control.AllowDrop = true;
        control.DragEnter += (_, e) =>
        {
            e.Effect = !_busy && e.Data?.GetDataPresent(DataFormats.FileDrop) == true
                ? DragDropEffects.Copy : DragDropEffects.None;
        };
        control.DragDrop += (_, e) =>
        {
            if (_busy || e.Data?.GetDataPresent(DataFormats.FileDrop) != true) return;
            if (e.Data.GetData(DataFormats.FileDrop) is string[] files)
                _ = ProcessFilesAsync(files);
        };
        foreach (Control child in control.Controls) RegisterDropTargets(child);
    }

    private void LoadSettings()
    {
        try
        {
            var file = Path.Combine(_applicationFolder, "settings.json");
            if (!File.Exists(file)) return;
            var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(file));
            if (settings is null) return;
            // Backwards compatible with old versions that had only RSA key paths.
            _rsaPrivateKeyPath = settings.PrivateKeyPath ?? "";
            _rsaPublicKeyPath = settings.PublicKeyPath ?? "";
            _edPrivateKeyPath = settings.EdPrivateKeyPath ?? "";
            _edPublicKeyPath = settings.EdPublicKeyPath ?? "";
            _selectedAlgorithm = settings.Algorithm == "Ed25519"
                ? SignatureAlgorithm.Ed25519 : SignatureAlgorithm.RsaSha256;
            RestoreSelectedKeyPaths();
            _algorithmBox.SelectedIndex = _selectedAlgorithm == SignatureAlgorithm.Ed25519 ? 1 : 0;
        }
        catch (Exception)
        {
            _status.Text = "Не удалось прочитать настройки. Ключи можно выбрать вручную.";
        }
    }

    private void RememberSelectedKeyPaths()
    {
        if (_selectedAlgorithm == SignatureAlgorithm.RsaSha256)
        {
            _rsaPrivateKeyPath = _privateKeyPath;
            _rsaPublicKeyPath = _publicKeyPath;
        }
        else
        {
            _edPrivateKeyPath = _privateKeyPath;
            _edPublicKeyPath = _publicKeyPath;
        }
    }

    private void RestoreSelectedKeyPaths()
    {
        _privateKeyPath = _selectedAlgorithm == SignatureAlgorithm.RsaSha256
            ? _rsaPrivateKeyPath : _edPrivateKeyPath;
        _publicKeyPath = _selectedAlgorithm == SignatureAlgorithm.RsaSha256
            ? _rsaPublicKeyPath : _edPublicKeyPath;
    }

    private void SaveSettings()
    {
        try
        {
            RememberSelectedKeyPaths();
            Directory.CreateDirectory(_applicationFolder);
            var data = JsonSerializer.Serialize(new AppSettings
            {
                PrivateKeyPath = _rsaPrivateKeyPath,
                PublicKeyPath = _rsaPublicKeyPath,
                EdPrivateKeyPath = _edPrivateKeyPath,
                EdPublicKeyPath = _edPublicKeyPath,
                Algorithm = _selectedAlgorithm == SignatureAlgorithm.Ed25519 ? "Ed25519" : "RSA"
            }, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(Path.Combine(_applicationFolder, "settings.json"), data, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            _status.Text = "Ключи выбраны, но не удалось сохранить настройки: " + ex.Message;
        }
    }

    private async Task ChangeAlgorithmAsync()
    {
        if (!_settingsLoaded || _busy) return;
        var requested = _algorithmBox.SelectedIndex == 1
            ? SignatureAlgorithm.Ed25519 : SignatureAlgorithm.RsaSha256;
        if (requested == _selectedAlgorithm) return;

        RememberSelectedKeyPaths();
        _selectedAlgorithm = requested;
        RestoreSelectedKeyPaths();
        RefreshKeyPaths();
        UpdateModeAppearance();
        SaveSettings();
        // One-time convenience: create a distinct key pair when first selecting
        // a new algorithm. Never overwrite previously chosen keys.
        if (string.IsNullOrWhiteSpace(_privateKeyPath) && string.IsNullOrWhiteSpace(_publicKeyPath))
            await InitializeOnFirstLaunchAsync();
        else
            _status.Text = "Алгоритм переключён. Используются ключи выбранного алгоритма.";
    }

    private void RefreshKeyPaths()
    {
        _privateKeyBox.Text = _privateKeyPath;
        _publicKeyBox.Text = _publicKeyPath;
        _pathToolTip.SetToolTip(_privateKeyBox, _privateKeyPath);
        _pathToolTip.SetToolTip(_publicKeyBox, _publicKeyPath);
    }

    private async Task InitializeOnFirstLaunchAsync()
    {
        // Never silently replace a previously selected (perhaps missing) key.
        if (!string.IsNullOrWhiteSpace(_privateKeyPath) || !string.IsNullOrWhiteSpace(_publicKeyPath))
        {
            _status.Text = "Ключи загружены из настроек. Можно перетаскивать файлы.";
            return;
        }

        var dir = Path.Combine(_applicationFolder, "keys");
        var suffix = _selectedAlgorithm == SignatureAlgorithm.Ed25519 ? "_ed25519" : "";
        var oldPrivate = Path.Combine(dir, "private" + suffix + ".pem");
        var oldPublic = Path.Combine(dir, "public" + suffix + ".pem");
        if (File.Exists(oldPrivate) && File.Exists(oldPublic))
        {
            _privateKeyPath = oldPrivate;
            _publicKeyPath = oldPublic;
            RefreshKeyPaths();
            SaveSettings();
            _status.Text = "Найдена ранее созданная пара ключей. Готово.";
            return;
        }

        await GenerateKeysAsync(dir, firstLaunch: true);
    }

    private async Task CreateKeysByUserAsync()
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = _selectedAlgorithm == SignatureAlgorithm.Ed25519
                ? "Куда сохранить новую пару Ed25519-ключей?"
                : "Куда сохранить новую пару RSA-ключей?",
            UseDescriptionForTitle = true,
            SelectedPath = Path.Combine(_applicationFolder, "keys")
        };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        await GenerateKeysAsync(dialog.SelectedPath, firstLaunch: false);
    }

    private async Task GenerateKeysAsync(string directory, bool firstLaunch)
    {
        var algorithm = _selectedAlgorithm;
        SetBusy(true, algorithm == SignatureAlgorithm.Ed25519
            ? "Создаём пару Ed25519…" : "Создаём пару RSA-3072…");
        try
        {
            var paths = await Task.Run(() =>
            {
                Directory.CreateDirectory(directory);
                var suffix = algorithm == SignatureAlgorithm.Ed25519 ? "_ed25519" : "";
                var plainPrivate = Path.Combine(directory, "private" + suffix + ".pem");
                var plainPublic = Path.Combine(directory, "public" + suffix + ".pem");
                var privatePath = plainPrivate;
                var publicPath = plainPublic;

                // A new key pair must not destroy old keys needed to verify old signatures.
                if (File.Exists(privatePath) || File.Exists(publicPath))
                {
                    var suffix = DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" + Guid.NewGuid().ToString("N")[..6];
                    privatePath = Path.Combine(directory, "private" + (algorithm == SignatureAlgorithm.Ed25519 ? "_ed25519" : "") + "_" + suffix + ".pem");
                    publicPath = Path.Combine(directory, "public" + (algorithm == SignatureAlgorithm.Ed25519 ? "_ed25519" : "") + "_" + suffix + ".pem");
                }

                string privatePem, publicPem;
                if (algorithm == SignatureAlgorithm.Ed25519)
                {
                    (privatePem, publicPem) = Ed25519Crypto.GeneratePemPair();
                }
                else
                {
                    using var rsa = RSA.Create();
                    rsa.KeySize = 3072;
                    privatePem = rsa.ExportPkcs8PrivateKeyPem();
                    publicPem = rsa.ExportSubjectPublicKeyInfoPem();
                }

                // CreateNew prevents overwriting any file, including in race conditions.
                using (var stream = new FileStream(privatePath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                    writer.Write(privatePem);
                try
                {
                    using var stream = new FileStream(publicPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                    using var writer = new StreamWriter(stream, new UTF8Encoding(false));
                    writer.Write(publicPem);
                }
                catch
                {
                    try { File.Delete(privatePath); } catch { /* best effort */ }
                    throw;
                }
                return (privatePath, publicPath);
            });

            _privateKeyPath = paths.privatePath;
            _publicKeyPath = paths.publicPath;
            RefreshKeyPaths();
            SaveSettings();
            _status.Text = firstLaunch
                ? "Создана первая пара ключей. Теперь можно перетаскивать файлы."
                : "Новая пара ключей создана. Старые ключи не затронуты.";
        }
        catch (Exception ex)
        {
            _status.Text = "Не удалось создать ключи.";
            MessageBox.Show(this, "Не удалось создать ключи:\n" + ex.Message,
                "OpenSig", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally { SetBusy(false); }
    }

    private void ChooseKey(bool isPrivate)
    {
        using var dialog = new OpenFileDialog
        {
            Title = (isPrivate ? "Выберите закрытый ключ " : "Выберите открытый ключ ")
                + (_selectedAlgorithm == SignatureAlgorithm.Ed25519 ? "Ed25519" : "RSA"),
            Filter = "Ключи PEM (*.pem;*.key)|*.pem;*.key|Все файлы (*.*)|*.*",
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        if (isPrivate) _privateKeyPath = dialog.FileName;
        else _publicKeyPath = dialog.FileName;
        RefreshKeyPaths();
        SaveSettings();
        _status.Text = "Ключ выбран. Готово к работе.";
    }

    private void OpenKeysFolder()
    {
        var folder = !string.IsNullOrWhiteSpace(_privateKeyPath)
            ? Path.GetDirectoryName(_privateKeyPath) : Path.Combine(_applicationFolder, "keys");
        folder ??= Path.Combine(_applicationFolder, "keys");
        if (!Directory.Exists(folder))
        {
            MessageBox.Show(this, "Папка с ключами не найдена.", "OpenSig",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        Process.Start(new ProcessStartInfo("explorer.exe", "\"" + folder + "\"") { UseShellExecute = true });
    }

    private async Task PickFilesAsync()
    {
        if (_busy) return;
        using var dialog = new OpenFileDialog
        {
            Title = "Выберите файлы",
            Filter = "Все файлы (*.*)|*.*",
            Multiselect = true,
            CheckFileExists = true
        };
        if (dialog.ShowDialog(this) == DialogResult.OK)
            await ProcessFilesAsync(dialog.FileNames);
    }

    private async Task ProcessFilesAsync(IEnumerable<string> droppedFiles)
    {
        if (_busy) return;
        var files = droppedFiles.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (files.Length == 0) return;

        var signing = _signMode.Checked;
        var keyFile = signing ? _privateKeyPath : _publicKeyPath;
        if (string.IsNullOrWhiteSpace(keyFile) || !File.Exists(keyFile))
        {
            MessageBox.Show(this,
                signing ? "Укажите закрытый ключ для создания подписей."
                        : "Укажите открытый ключ для проверки подписей.",
                "OpenSig", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        string pem;
        try { pem = File.ReadAllText(keyFile, Encoding.UTF8); }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Не удалось прочитать ключ:\n" + ex.Message,
                "OpenSig", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        string password = "";
        if (pem.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal))
        {
            using var dialog = new PasswordDialog();
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            password = dialog.Password;
        }

        var algorithm = _selectedAlgorithm;
        SetBusy(true, signing ? "Создание подписей…" : "Проверка подписей…");
        _results.Items.Clear();
        var good = 0;
        var bad = 0;

        RSA? rsa = null;
        Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters? edPrivate = null;
        Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters? edPublic = null;
        try
        {
            if (algorithm == SignatureAlgorithm.Ed25519)
            {
                if (signing)
                    edPrivate = await Task.Run(() => Ed25519Crypto.LoadPrivateKey(pem, password));
                else
                    edPublic = await Task.Run(() => Ed25519Crypto.LoadPublicKey(pem));
            }
            else
            {
                rsa = await Task.Run(() => LoadRsa(pem, password));
            }
            foreach (var file in files)
            {
                OperationResult result;
                if (!File.Exists(file))
                {
                    result = new OperationResult(file, "Ошибка", "Это не файл или файл недоступен", false);
                }
                else if (signing)
                {
                    var signaturePath = file + ".sig";
                    var overwrite = true;
                    if (File.Exists(signaturePath))
                    {
                        overwrite = MessageBox.Show(this,
                            "Подпись уже существует:\n" + signaturePath + "\n\nПерезаписать её?",
                            "OpenSig", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes;
                    }
                    result = !overwrite
                        ? new OperationResult(file, "Пропущен", "Существующая подпись сохранена", false)
                        : await Task.Run(() => algorithm == SignatureAlgorithm.Ed25519
                            ? Ed25519Crypto.SignFile(edPrivate!, file, signaturePath)
                            : SignFile(rsa!, file, signaturePath));
                }
                else
                {
                    result = await Task.Run(() => algorithm == SignatureAlgorithm.Ed25519
                        ? Ed25519Crypto.VerifyFile(edPublic!, file)
                        : VerifyFile(rsa!, file));
                }

                AddResult(result);
                if (result.IsSuccess) good++;
                else bad++;
            }
            _status.Text = signing
                ? $"Подписано: {good}. Не обработано: {bad}. Подписи находятся рядом с файлами."
                : $"Подписей верно: {good}. Не удалось проверить: {bad}.";
        }
        catch (Exception ex)
        {
            _status.Text = "Операция прервана из-за ошибки ключа.";
            MessageBox.Show(this,
                "Не удалось загрузить ключ выбранного алгоритма. Проверьте PEM и пароль.\n\n" + ex.Message,
                "OpenSig", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            rsa?.Dispose();
            SetBusy(false);
        }
    }

    private static RSA LoadRsa(string pem, string password)
    {
        var rsa = RSA.Create();
        try
        {
            if (pem.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", StringComparison.Ordinal))
                rsa.ImportFromEncryptedPem(pem, password);
            else
                rsa.ImportFromPem(pem);
            return rsa;
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    private static OperationResult SignFile(RSA rsa, string filePath, string signaturePath)
    {
        try
        {
            byte[] signature;
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                signature = rsa.SignData(stream, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // Atomic write: an interrupted process will not leave a partially written .sig.
            var tempPath = signaturePath + ".tmp_" + Guid.NewGuid().ToString("N");
            try
            {
                File.WriteAllBytes(tempPath, signature);
                File.Move(tempPath, signaturePath, overwrite: true);
            }
            finally
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { /* best effort */ }
            }
            return new OperationResult(filePath, "Подписан", signaturePath, true);
        }
        catch (Exception ex)
        {
            return new OperationResult(filePath, "Ошибка", ex.Message, false);
        }
    }

    private static OperationResult VerifyFile(RSA rsa, string droppedPath)
    {
        string filePath;
        string signaturePath;
        if (droppedPath.EndsWith(".sig", StringComparison.OrdinalIgnoreCase))
        {
            signaturePath = droppedPath;
            filePath = droppedPath[..^4];
        }
        else
        {
            filePath = droppedPath;
            signaturePath = droppedPath + ".sig";
        }

        if (!File.Exists(filePath))
            return new OperationResult(droppedPath, "Не найден файл", filePath, false);
        if (!File.Exists(signaturePath))
            return new OperationResult(droppedPath, "Нет .sig", signaturePath, false);

        try
        {
            // Raw RSA signatures always have the length of the modulus.
            // Reject wrong sizes before reading an untrusted .sig into memory.
            var expectedSize = (rsa.KeySize + 7) / 8;
            if (new FileInfo(signaturePath).Length != expectedSize)
                return new OperationResult(droppedPath, "НЕВЕРНА", "Неверный размер подписи для выбранного RSA-ключа", false);

            var signature = File.ReadAllBytes(signaturePath);
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var valid = rsa.VerifyData(stream, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return valid
                ? new OperationResult(droppedPath, "Подпись верна", signaturePath, true)
                : new OperationResult(droppedPath, "НЕВЕРНА", "Файл, подпись или открытый ключ не совпадают", false);
        }
        catch (Exception ex)
        {
            return new OperationResult(droppedPath, "Ошибка", ex.Message, false);
        }
    }

    private void AddResult(OperationResult result)
    {
        var item = new ListViewItem(Path.GetFileName(result.Source));
        item.SubItems.Add(result.Status);
        item.SubItems.Add(result.Detail);
        item.ForeColor = result.IsSuccess ? Color.FromArgb(28, 119, 73) : Color.FromArgb(170, 57, 49);
        item.Tag = result.Source;
        _results.Items.Add(item);
        item.EnsureVisible();
    }

    private void RevealSelectedFile()
    {
        if (_results.SelectedItems.Count == 0) return;
        if (_results.SelectedItems[0].Tag is not string path || !File.Exists(path)) return;
        Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + path + "\"")
        {
            UseShellExecute = true
        });
    }

    private void SetBusy(bool busy, string? message = null)
    {
        _busy = busy;
        _signMode.Enabled = !busy;
        _verifyMode.Enabled = !busy;
        _algorithmBox.Enabled = !busy;
        _pickPrivateButton.Enabled = !busy;
        _pickPublicButton.Enabled = !busy;
        _createKeysButton.Enabled = !busy;
        _openKeysButton.Enabled = !busy;
        _pickFilesButton.Enabled = !busy;
        _progress.Visible = busy;
        if (message is not null) _status.Text = message;
    }
}

internal sealed class PasswordDialog : Form
{
    private readonly TextBox _passwordBox = new();
    public string Password => _passwordBox.Text;

    public PasswordDialog()
    {
        Text = "Пароль от закрытого ключа";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(410, 152);
        Font = new Font("Segoe UI", 10f);

        Controls.Add(new Label
        {
            Text = "Введите пароль зашифрованного PEM-ключа:",
            Location = new Point(17, 17), AutoSize = true
        });
        _passwordBox.Location = new Point(18, 51);
        _passwordBox.Width = 374;
        _passwordBox.UseSystemPasswordChar = true;
        Controls.Add(_passwordBox);

        var ok = new Button { Text = "Продолжить", DialogResult = DialogResult.OK,
            Location = new Point(184, 103), Size = new Size(106, 32) };
        var cancel = new Button { Text = "Отмена", DialogResult = DialogResult.Cancel,
            Location = new Point(298, 103), Size = new Size(94, 32) };
        Controls.Add(ok);
        Controls.Add(cancel);
        AcceptButton = ok;
        CancelButton = cancel;
    }
}
