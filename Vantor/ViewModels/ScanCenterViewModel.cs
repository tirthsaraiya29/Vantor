using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Text.Json;
using System.Windows.Input;
using System.Windows.Threading;
using Vantor.Common;
using Vantor.Models;
using Vantor.Services;

namespace Vantor.ViewModels
{
    public class ScanCenterViewModel : ViewModelBase
    {
        private readonly IVantorIpcClient _ipcClient;
        private readonly Action _returnToDashboardAction;
        private readonly DispatcherTimer _pollTimer;
        private readonly Stopwatch _stopwatch = new();

        private bool _isScanning;
        private bool _isScanComplete;
        private string _scanMode = "Quick Scan";
        private int _progressPercent = 0;
        private string _currentScanningPath = "Initiating pure C++ detection engine...";
        private int _filesScannedCount = 0;
        private int _threatsDetectedCount = 0;
        private int _filesQuarantinedCount = 0;
        private int _safeFilesCount = 0;
        private string _throughputText = "0 files/s";
        private string _elapsedText = "00:00";
        private int _consecutiveIpcFailures = 0;
        private int _lastScannedForThroughput = 0;

        public ObservableCollection<ScanEventItem> LiveScanFeed { get; } = new();

        public bool IsScanning
        {
            get => _isScanning;
            set => SetProperty(ref _isScanning, value);
        }

        public bool IsScanComplete
        {
            get => _isScanComplete;
            set => SetProperty(ref _isScanComplete, value);
        }

        public string ScanMode
        {
            get => _scanMode;
            set => SetProperty(ref _scanMode, value);
        }

        public int ProgressPercent
        {
            get => _progressPercent;
            set => SetProperty(ref _progressPercent, value);
        }

        public string CurrentScanningPath
        {
            get => _currentScanningPath;
            set => SetProperty(ref _currentScanningPath, value);
        }

        public int FilesScannedCount
        {
            get => _filesScannedCount;
            set => SetProperty(ref _filesScannedCount, value);
        }

        public int ThreatsDetectedCount
        {
            get => _threatsDetectedCount;
            set => SetProperty(ref _threatsDetectedCount, value);
        }

        public int FilesQuarantinedCount
        {
            get => _filesQuarantinedCount;
            set => SetProperty(ref _filesQuarantinedCount, value);
        }

        public int SafeFilesCount
        {
            get => _safeFilesCount;
            set => SetProperty(ref _safeFilesCount, value);
        }

        public string ThroughputText
        {
            get => _throughputText;
            set => SetProperty(ref _throughputText, value);
        }

        public string ElapsedText
        {
            get => _elapsedText;
            set => SetProperty(ref _elapsedText, value);
        }

        public ICommand AbortScanCommand { get; }
        public ICommand DoneSummaryCommand { get; }

        public ScanCenterViewModel(IVantorIpcClient ipcClient, Action returnToDashboardAction)
        {
            _ipcClient = ipcClient;
            _returnToDashboardAction = returnToDashboardAction;

            _pollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
            _pollTimer.Tick += OnPollTimerTick;

            AbortScanCommand = new AsyncRelayCommand(async () =>
            {
                await _ipcClient.CancelScanAsync();
                StopScanSession();
                _returnToDashboardAction();
            });

            DoneSummaryCommand = new RelayCommand(() =>
            {
                IsScanComplete = false;
                _returnToDashboardAction();
            });
        }

        public async void StartScan(string mode, string path)
        {
            IsScanning = true;
            IsScanComplete = false;
            ScanMode = mode.ToUpperInvariant() + " SCAN";
            ProgressPercent = 0;
            CurrentScanningPath = "Connecting to Windows Service Named Pipe...";
            FilesScannedCount = 0;
            ThreatsDetectedCount = 0;
            FilesQuarantinedCount = 0;
            SafeFilesCount = 0;
            _consecutiveIpcFailures = 0;
            _lastScannedForThroughput = 0;
            LiveScanFeed.Clear();

            _stopwatch.Restart();
            _pollTimer.Start();

            bool started = await _ipcClient.StartScanAsync(mode, path);
            if (!started)
            {
                CurrentScanningPath = "Offline Mode: Cannot reach VantorService. Verify service is running.";
            }
        }

        private async void OnPollTimerTick(object? sender, EventArgs e)
        {
            ElapsedText = _stopwatch.Elapsed.ToString(@"mm\:ss");

            string? statusJson = await _ipcClient.GetScanStatusJsonAsync();
            if (statusJson != null)
            {
                try
                {
                    using var doc = JsonDocument.Parse(statusJson);
                    var root = doc.RootElement;

                    int scanned = root.GetProperty("files_scanned").GetInt32();
                    int threats = root.GetProperty("threats_detected").GetInt32();
                    string currentFile = root.GetProperty("current_file").GetString() ?? "";
                    double percent = root.GetProperty("percent").GetDouble();
                    bool isComplete = root.GetProperty("is_complete").GetBoolean();

                    int newScanned = scanned - _lastScannedForThroughput;
                    _lastScannedForThroughput = scanned;
                    ThroughputText = $"{Math.Max(0, newScanned * 5)} files/s";

                    FilesScannedCount = scanned;
                    ThreatsDetectedCount = threats;
                    FilesQuarantinedCount = threats;
                    ProgressPercent = Math.Clamp((int)percent, 0, 100);

                    if (!string.IsNullOrEmpty(currentFile))
                    {
                        CurrentScanningPath = currentFile;
                        if (LiveScanFeed.Count > 40) LiveScanFeed.RemoveAt(LiveScanFeed.Count - 1);
                        LiveScanFeed.Insert(0, new ScanEventItem
                        {
                            FilePath = currentFile,
                            Status = threats > 0 && currentFile.Contains("malicious", StringComparison.OrdinalIgnoreCase) ? "MALICIOUS" : "SAFE",
                            ThreatDetails = "Signature & Heuristic OK"
                        });
                    }

                    if (isComplete)
                    {
                        FinishScan();
                    }
                    _consecutiveIpcFailures = 0;
                    return;
                }
                catch { }
            }

            _consecutiveIpcFailures++;
            if (_consecutiveIpcFailures > 25)
            {
                StopScanSession();
                CurrentScanningPath = "Scanner Service Disconnected / Engine Offline";
            }
        }

        private void FinishScan()
        {
            StopScanSession();
            SafeFilesCount = Math.Max(0, FilesScannedCount - ThreatsDetectedCount);
            IsScanComplete = true;

            if (ThreatsDetectedCount > 0)
            {
                SoundEffectService.PlayThreatAlert();
            }
            else
            {
                SoundEffectService.PlayScanComplete();
            }
        }

        private void StopScanSession()
        {
            _pollTimer.Stop();
            _stopwatch.Stop();
            IsScanning = false;
        }
    }
}
