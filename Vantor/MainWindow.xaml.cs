using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Data.Sqlite;
using System.Threading.Tasks;
using IOPath = System.IO.Path;
using MediaColor = System.Windows.Media.Color;
using SolidColorBrush = System.Windows.Media.SolidColorBrush;
using Button = System.Windows.Controls.Button;
using MessageBox = System.Windows.MessageBox;
using Application = System.Windows.Application;
using Canvas = System.Windows.Controls.Canvas;

namespace Vantor
{
    public partial class MainWindow : Window
    {
        private DispatcherTimer _logUpdateTimer;
        private Process? _backendProcess;
        private string _exePath, _dbPath, _quarantineDbPath;
        private string _currentScanSubFolder = "qs";
        private long _lastFilePosition = 0;
        private bool _isCollapsed = false;
        private string? _activeSID = null;
        private HashSet<string> _uniqueFilesScanned = new HashSet<string>();
        private int _totalScanned = 0, _maliciousCount = 0, _suspiciousCount = 0, _quarantineCount = 0;
        private int _totalFilesToScan = 0;
        private bool _isCountingFiles = false;

        public MainWindow()
        {
            InitializeComponent();
            InitializeDotRing();

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            _exePath = IOPath.Combine(baseDir, "VantorBackend.exe");
            _dbPath = IOPath.Combine(baseDir, "scan_history.db");
            _quarantineDbPath = IOPath.Combine(baseDir, "quarantine", "quarantine.db");

            _logUpdateTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
            _logUpdateTimer.Tick += LogUpdateTimer_Tick;

            CheckAndAttachToExistingScan();
            LoadQuarantineData();
        }

        private void InitializeDotRing()
        {
            double radius = 100;
            for (int i = 0; i < 72; i++)
            {
                double angle = i * 5 * Math.PI / 180;
                Ellipse dot = new Ellipse
                {
                    Width = 2,
                    Height = 2,
                    Fill = new SolidColorBrush(MediaColor.FromRgb(40, 40, 40))
                };
                Canvas.SetLeft(dot, 110 + radius * Math.Cos(angle) - 1);
                Canvas.SetTop(dot, 110 + radius * Math.Sin(angle) - 1);
                DotRingCanvas.Children.Add(dot);
            }
        }

        private async void RunEngine(string mode, string arg, bool isAttach = false)
        {
            _activeSID = null;
            _totalScanned = 0;
            _maliciousCount = 0;
            _suspiciousCount = 0;
            _quarantineCount = 0;
            _uniqueFilesScanned.Clear();
            _totalFilesToScan = 0;

            _currentScanSubFolder = mode.ToLower() switch
            {
                "full" => "fs",
                "quick" => "qs",
                "custom" => "cs",
                _ => "qs"
            };

            HideAllViews();
            ScanView.Visibility = Visibility.Visible;
            txtScanPath.Text = isAttach ? "Reconnecting..." : "Calculating total files...";
            txtScanPercent.Text = "0%";

            ((Storyboard)FindResource("RotateScanner")).Begin();

            if (!isAttach)
            {
                _isCountingFiles = true;
                _totalFilesToScan = await Task.Run(() => GetTotalFileCount(mode));
                _isCountingFiles = false;
            }

            try
            {
                if (!isAttach)
                {
                    _backendProcess = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = _exePath,
                            Arguments = $"{mode} \"{arg}\"",
                            CreateNoWindow = true,
                            UseShellExecute = false
                        },
                        EnableRaisingEvents = true
                    };
                    _backendProcess.Exited += (s, e) => Dispatcher.Invoke(OnScanComplete);
                    _backendProcess.Start();
                }

                _lastFilePosition = 0;
                _logUpdateTimer.Start();
            }
            catch
            {
                NavDashboard_Click(null, null);
            }
        }

        private int GetTotalFileCount(string mode)
        {
            int count = 0;
            List<string> pathsToScan = new List<string>();

            if (mode.ToLower() == "quick")
            {
                pathsToScan.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + "\\Downloads");
                pathsToScan.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop));
                pathsToScan.Add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));

                foreach (var path in pathsToScan)
                {
                    if (Directory.Exists(path))
                    {
                        try
                        {
                            count += Directory.EnumerateFiles(path, "*.*", SearchOption.AllDirectories).Count();
                        }
                        catch { }
                    }
                }
            }
            else if (mode.ToLower() == "full")
            {
                var drives = DriveInfo.GetDrives().Where(d => d.IsReady && d.DriveType == DriveType.Fixed);
                foreach (var drive in drives)
                {
                    count += CountFilesSafe(drive.RootDirectory.FullName);
                }
            }

            return count > 0 ? count : 100;
        }

        private int CountFilesSafe(string path)
        {
            int total = 0;
            try
            {
                foreach (var file in Directory.EnumerateFiles(path))
                    total++;

                foreach (var dir in Directory.EnumerateDirectories(path))
                    total += CountFilesSafe(dir);
            }
            catch { }
            return total;
        }

        private void LogUpdateTimer_Tick(object? sender, EventArgs e)
        {
            string logDir = IOPath.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs", _currentScanSubFolder);
            if (!Directory.Exists(logDir)) return;

            var latestFile = new DirectoryInfo(logDir)
                .GetFiles("*.jsonl")
                .OrderByDescending(f => f.CreationTime)
                .FirstOrDefault();

            if (latestFile == null) return;

            try
            {
                using var fs = new FileStream(latestFile.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                if (fs.Length < _lastFilePosition) _lastFilePosition = 0;

                fs.Seek(_lastFilePosition, SeekOrigin.Begin);
                using var reader = new StreamReader(fs);

                string? line;
                while ((line = reader.ReadLine()) != null)
                {
                    var log = JsonSerializer.Deserialize<LogEntry>(line);
                    if (log == null || log.SID == "SYS-0000") continue;

                    if (_activeSID == null) _activeSID = log.SID;

                    if (log.filePath != null)
                    {
                        if (_uniqueFilesScanned.Add(log.filePath))
                            _totalScanned++;

                        string v = log.verdict?.ToLower() ?? "";
                        if (v.Contains("malicious")) _maliciousCount++;
                        else if (v.Contains("suspicious")) _suspiciousCount++;
                        else if (v.Contains("quarantined")) _quarantineCount++;

                        txtScanPath.Text = IOPath.GetFileName(log.filePath);

                        if (!_isCountingFiles && _totalFilesToScan > 0)
                        {
                            int progress = (int)((double)_totalScanned / _totalFilesToScan * 100);
                            if (progress > 99) progress = 99;
                            txtScanPercent.Text = $"{progress}%";
                        }
                    }
                }

                _lastFilePosition = fs.Position;
            }
            catch { }
        }

        private void OnScanComplete()
        {
            _logUpdateTimer.Stop();

            Dispatcher.Invoke(() =>
            {
                ((Storyboard)FindResource("RotateScanner")).Stop();
                txtScanPercent.Text = "100%";
                countSafe.Text = Math.Max(0, _totalScanned - _maliciousCount).ToString();
                countMalicious.Text = _maliciousCount.ToString();
                countQuarantined.Text = _quarantineCount.ToString();

                HideAllViews();
                ScanSummaryView.Visibility = Visibility.Visible;
                LoadQuarantineData();
            });
        }

        private void CheckAndAttachToExistingScan()
        {
            var existing = Process.GetProcessesByName("VantorBackend").FirstOrDefault();
            if (existing != null)
            {
                _backendProcess = existing;
                _backendProcess.EnableRaisingEvents = true;
                _backendProcess.Exited += (s, e) => Dispatcher.Invoke(OnScanComplete);
                RunEngine("EXISTING", "", true);
            }
        }

        private void LoadQuarantineData()
        {
            var items = new List<QuarantineItem>();

            if (File.Exists(_quarantineDbPath))
            {
                try
                {
                    using var conn = new SqliteConnection($"Data Source={_quarantineDbPath}");
                    conn.Open();

                    var cmd = conn.CreateCommand();
                    cmd.CommandText = "SELECT original_path, timestamp FROM quarantined_files";

                    using var reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        string fullPath = reader.GetString(0);
                        items.Add(new QuarantineItem
                        {
                            FileName = IOPath.GetFileName(fullPath).ToUpper(),
                            OriginalPath = fullPath,
                            Date = reader.GetString(1)
                        });
                    }
                }
                catch { }
            }

            dgQuarantine.ItemsSource = items;
            txtEmptyQuarantineMsg.Visibility = items.Count == 0
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        private void ActionDelete_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is QuarantineItem item)
            {
                if (MessageBox.Show($"Delete {item.FileName}?", "Confirm", MessageBoxButton.YesNo) == MessageBoxResult.Yes)
                {
                    try
                    {
                        using var conn = new SqliteConnection($"Data Source={_quarantineDbPath}");
                        conn.Open();

                        var cmd = conn.CreateCommand();
                        cmd.CommandText = "DELETE FROM quarantined_files WHERE original_path = @path";
                        cmd.Parameters.AddWithValue("@path", item.OriginalPath);
                        cmd.ExecuteNonQuery();

                        string encryptedName = item.FileName.ToLower() + ".enc";
                        string filePath = IOPath.Combine(
                            AppDomain.CurrentDomain.BaseDirectory,
                            "quarantine",
                            encryptedName
                        );

                        if (File.Exists(filePath))
                            File.Delete(filePath);

                        LoadQuarantineData();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(ex.Message);
                    }
                }
            }
        }

        private void ActionRestore_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.DataContext is QuarantineItem item)
            {
                string qFolder = IOPath.Combine(AppDomain.CurrentDomain.BaseDirectory, "quarantine");
                string decryptor = IOPath.Combine(AppDomain.CurrentDomain.BaseDirectory, "decrypt.exe");
                if (!File.Exists(decryptor)) return;

                Process.Start(new ProcessStartInfo
                {
                    FileName = decryptor,
                    Arguments = $"--file \"{item.FileName.ToLower()}.enc\" --path \"{qFolder}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                });

                LoadQuarantineData();
            }
        }

        private void LoadHistoryData()
        {
            var history = new List<ScanHistoryItem>();

            if (File.Exists(_dbPath))
            {
                try
                {
                    using var conn = new SqliteConnection($"Data Source={_dbPath}");
                    conn.Open();

                    var cmd = conn.CreateCommand();
                    cmd.CommandText = "SELECT sid_string, timestamp, type FROM scan_sessions ORDER BY id DESC";

                    using var reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        string rawTs = reader.GetString(1);
                        int threats = 0;
                        string displayTs = rawTs.Replace("Scanned:", "FILES:").Replace("Threats:", "⚠");

                        if (rawTs.Contains("Threats: "))
                            int.TryParse(rawTs.Split("Threats: ").Last().Trim(), out threats);

                        history.Add(new ScanHistoryItem
                        {
                            SID = reader.GetString(0).ToUpper(),
                            Timestamp = displayTs,
                            Malicious = threats,
                            Status = reader.GetString(2).ToUpper()
                        });
                    }
                }
                catch { }
            }

            dgHistory.ItemsSource = history;
        }

        private void HideAllViews()
        {
            DashboardView.Visibility =
                ScanView.Visibility =
                ScanSummaryView.Visibility =
                HistoryView.Visibility =
                Visibility.Collapsed;
        }

        private void NavDashboard_Click(object? sender, RoutedEventArgs? e)
        {
            HideAllViews();
            DashboardView.Visibility = Visibility.Visible;
            LoadQuarantineData();
        }

        private void NavHistory_Click(object? sender, RoutedEventArgs? e)
        {
            HideAllViews();
            HistoryView.Visibility = Visibility.Visible;
            LoadHistoryData();
        }

        private void ToggleSidebar_Click(object sender, RoutedEventArgs e)
        {
            _isCollapsed = !_isCollapsed;
            SidebarUI.BeginAnimation(
                WidthProperty,
                new DoubleAnimation(_isCollapsed ? 55 : 220, TimeSpan.FromMilliseconds(250))
            );
        }

        private void StartScan_Click(object sender, RoutedEventArgs e) =>
            RunEngine((sender as Button)?.Tag?.ToString() ?? "quick", "");

        private void MinimizeButton_Click(object sender, RoutedEventArgs e) =>
            WindowState = WindowState.Minimized;

        private void CloseButton_Click(object sender, RoutedEventArgs e) =>
            Application.Current.Shutdown();

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
                DragMove();
        }

        private void SummaryDone_Click(object sender, RoutedEventArgs e) =>
            NavDashboard_Click(null, null);

        private void CancelScan_Click(object sender, RoutedEventArgs e)
        {
            foreach (var p in Process.GetProcessesByName("VantorBackend"))
            {
                try { p.Kill(); } catch { }
            }

            _logUpdateTimer.Stop();
            NavDashboard_Click(null, null);
        }
    }

    public class QuarantineItem
    {
        public string FileName { get; set; } = "";
        public string OriginalPath { get; set; } = "";
        public string Date { get; set; } = "";
    }

    public class LogEntry
    {
        public string? SID { get; set; }
        [System.Text.Json.Serialization.JsonPropertyName("file path")]
        public string? filePath { get; set; }
        public string? verdict { get; set; }
    }

    public class ScanHistoryItem
    {
        public string SID { get; set; } = "";
        public string Timestamp { get; set; } = "";
        public int Malicious { get; set; }
        public string Status { get; set; } = "";
    }
}
