using System.Windows.Input;
using Vantor.Common;
using Vantor.Services;

namespace Vantor.ViewModels
{
    public class SettingsViewModel : ViewModelBase
    {
        private readonly IVantorIpcClient _ipcClient;

        private bool _isRtpEnabled = true;
        private bool _isAntiTamperEnabled = true;
        private double _heuristicThreshold = 75;
        private double _zipBombRatioLimit = 10;
        private bool _isSoundEnabled = true;
        private string _statusNotice = "";

        public bool IsRtpEnabled
        {
            get => _isRtpEnabled;
            set => SetProperty(ref _isRtpEnabled, value);
        }

        public bool IsAntiTamperEnabled
        {
            get => _isAntiTamperEnabled;
            set => SetProperty(ref _isAntiTamperEnabled, value);
        }

        public double HeuristicThreshold
        {
            get => _heuristicThreshold;
            set => SetProperty(ref _heuristicThreshold, value);
        }

        public double ZipBombRatioLimit
        {
            get => _zipBombRatioLimit;
            set => SetProperty(ref _zipBombRatioLimit, value);
        }

        public bool IsSoundEnabled
        {
            get => _isSoundEnabled;
            set
            {
                if (SetProperty(ref _isSoundEnabled, value))
                {
                    SoundEffectService.SoundEnabled = value;
                }
            }
        }

        public string StatusNotice
        {
            get => _statusNotice;
            set => SetProperty(ref _statusNotice, value);
        }

        public ICommand SaveSettingsCommand { get; }

        public SettingsViewModel(IVantorIpcClient ipcClient)
        {
            _ipcClient = ipcClient;
            _isSoundEnabled = SoundEffectService.SoundEnabled;

            SaveSettingsCommand = new AsyncRelayCommand(async () =>
            {
                StatusNotice = "Applying security policies to Win32 Service...";
                bool ok = await _ipcClient.UpdateConfigAsync(
                    IsRtpEnabled,
                    IsAntiTamperEnabled,
                    HeuristicThreshold / 100.0,
                    ZipBombRatioLimit);

                StatusNotice = ok
                    ? "✓ Security policies synchronized with Vantor Service successfully."
                    : "Settings saved locally. Service IPC pending.";
                SoundEffectService.PlayActionBeep();
            });
        }
    }
}
