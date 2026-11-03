using System;
using System.IO;
using System.Windows.Input;
using System.Windows.Media;
using Vantor.Common;
using Vantor.Services;

namespace Vantor.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private readonly IVantorIpcClient _ipcClient;

        private ViewModelBase _currentViewModel = null!;
        private bool _isEngineOnline;
        private string _engineStatusText = "Connecting...";
        private SolidColorBrush _engineStatusColor = new(Color.FromRgb(245, 158, 11)); // Amber

        public DashboardViewModel DashboardVM { get; }
        public ScanCenterViewModel ScanCenterVM { get; }
        public QuarantineVaultViewModel QuarantineVaultVM { get; }
        public AntiTamperViewModel AntiTamperVM { get; }
        public ZipBombViewModel ZipBombVM { get; }
        public SignaturesViewModel SignaturesVM { get; }
        public SettingsViewModel SettingsVM { get; }

        public ViewModelBase CurrentViewModel
        {
            get => _currentViewModel;
            set => SetProperty(ref _currentViewModel, value);
        }

        public bool IsEngineOnline
        {
            get => _isEngineOnline;
            set => SetProperty(ref _isEngineOnline, value);
        }

        public string EngineStatusText
        {
            get => _engineStatusText;
            set => SetProperty(ref _engineStatusText, value);
        }

        public SolidColorBrush EngineStatusColor
        {
            get => _engineStatusColor;
            set => SetProperty(ref _engineStatusColor, value);
        }

        public ICommand NavigateDashboardCommand { get; }
        public ICommand NavigateScanCenterCommand { get; }
        public ICommand NavigateQuarantineCommand { get; }
        public ICommand NavigateAntiTamperCommand { get; }
        public ICommand NavigateZipBombCommand { get; }
        public ICommand NavigateSignaturesCommand { get; }
        public ICommand NavigateSettingsCommand { get; }

        public MainViewModel(
            IVantorIpcClient ipcClient,
            string backendExe,
            string serviceExe,
            string workingDir,
            string quarantineDbPath)
        {
            _ipcClient = ipcClient;

            ScanCenterVM = new ScanCenterViewModel(_ipcClient, () =>
            {
                if (DashboardVM != null) CurrentViewModel = DashboardVM;
            });

            DashboardVM = new DashboardViewModel(
                _ipcClient,
                (mode, path) =>
                {
                    CurrentViewModel = ScanCenterVM;
                    ScanCenterVM.StartScan(mode, path);
                },
                () =>
                {
                    if (AntiTamperVM != null) CurrentViewModel = AntiTamperVM;
                });

            QuarantineVaultVM = new QuarantineVaultViewModel(_ipcClient, quarantineDbPath);
            AntiTamperVM = new AntiTamperViewModel(backendExe, workingDir);
            ZipBombVM = new ZipBombViewModel(backendExe, workingDir);
            SignaturesVM = new SignaturesViewModel(backendExe, workingDir);
            SettingsVM = new SettingsViewModel(_ipcClient);

            _currentViewModel = DashboardVM;

            NavigateDashboardCommand = new RelayCommand(() =>
            {
                DashboardVM.UpdateStats(QuarantineVaultVM.AllItems.Count, SignaturesVM.TotalSignatures);
                CurrentViewModel = DashboardVM;
            });

            NavigateScanCenterCommand = new RelayCommand(() => CurrentViewModel = ScanCenterVM);
            NavigateQuarantineCommand = new RelayCommand(() =>
            {
                QuarantineVaultVM.LoadQuarantine();
                CurrentViewModel = QuarantineVaultVM;
            });
            NavigateAntiTamperCommand = new RelayCommand(() => CurrentViewModel = AntiTamperVM);
            NavigateZipBombCommand = new RelayCommand(() => CurrentViewModel = ZipBombVM);
            NavigateSignaturesCommand = new RelayCommand(() =>
            {
                SignaturesVM.RefreshStatsAsync();
                CurrentViewModel = SignaturesVM;
            });
            NavigateSettingsCommand = new RelayCommand(() => CurrentViewModel = SettingsVM);

            // Subscribe to IPC connection state
            _ipcClient.ConnectionStateChanged += OnConnectionStateChanged;
            _ipcClient.StartHeartbeat();
        }

        private void OnConnectionStateChanged(bool isConnected)
        {
            IsEngineOnline = isConnected;
            if (isConnected)
            {
                EngineStatusText = "Real-Time Active";
                EngineStatusColor = new SolidColorBrush(Color.FromRgb(16, 185, 129)); // Emerald
            }
            else
            {
                EngineStatusText = "Engine Disconnected";
                EngineStatusColor = new SolidColorBrush(Color.FromRgb(244, 63, 94)); // Crimson
            }
        }
    }
}
