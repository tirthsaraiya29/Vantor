using System;
using System.Collections.ObjectModel;
using System.Windows.Input;
using Vantor.Common;
using Vantor.Models;
using Vantor.Services;

namespace Vantor.ViewModels
{
    public class DashboardViewModel : ViewModelBase
    {
        private readonly IVantorIpcClient _ipcClient;
        private readonly Action<string, string> _triggerScanAction;
        private readonly Action _navigateToAuditAction;

        private bool _isShieldActive = true;
        private string _totalSignatures = "20,000+";
        private int _quarantineCount = 0;
        private int _monitoredCount = 1428;
        private string _memoryIntegrity = "SECURED (O(1))";

        public ObservableCollection<ScanEventItem> RecentEvents { get; } = new();

        public bool IsShieldActive
        {
            get => _isShieldActive;
            set => SetProperty(ref _isShieldActive, value);
        }

        public string TotalSignatures
        {
            get => _totalSignatures;
            set => SetProperty(ref _totalSignatures, value);
        }

        public int QuarantineCount
        {
            get => _quarantineCount;
            set => SetProperty(ref _quarantineCount, value);
        }

        public int MonitoredCount
        {
            get => _monitoredCount;
            set => SetProperty(ref _monitoredCount, value);
        }

        public string MemoryIntegrity
        {
            get => _memoryIntegrity;
            set => SetProperty(ref _memoryIntegrity, value);
        }

        public ICommand QuickScanCommand { get; }
        public ICommand FullScanCommand { get; }
        public ICommand CustomScanCommand { get; }
        public ICommand RunIntegrityCheckCommand { get; }

        public DashboardViewModel(
            IVantorIpcClient ipcClient,
            Action<string, string> triggerScanAction,
            Action navigateToAuditAction)
        {
            _ipcClient = ipcClient;
            _triggerScanAction = triggerScanAction;
            _navigateToAuditAction = navigateToAuditAction;

            QuickScanCommand = new RelayCommand(() => _triggerScanAction("quick", ""));
            FullScanCommand = new RelayCommand(() => _triggerScanAction("full", ""));
            CustomScanCommand = new RelayCommand(() =>
            {
                var dlg = new Microsoft.Win32.OpenFolderDialog
                {
                    Title = "Select Directory for Deep Security Scan"
                };
                if (dlg.ShowDialog() == true && !string.IsNullOrEmpty(dlg.FolderName))
                {
                    _triggerScanAction("custom", dlg.FolderName);
                }
            });

            RunIntegrityCheckCommand = new RelayCommand(_navigateToAuditAction);

            // Populate sample activity feed
            RecentEvents.Add(new ScanEventItem { FilePath = "C:\\Windows\\System32\\ntdll.dll", Status = "SAFE", ThreatDetails = "System Library Verified" });
            RecentEvents.Add(new ScanEventItem { FilePath = "C:\\Windows\\System32\\kernel32.dll", Status = "SAFE", ThreatDetails = "Code Integrity Clean" });
            RecentEvents.Add(new ScanEventItem { FilePath = "C:\\Program Files\\Common Files\\Services.exe", Status = "SAFE", ThreatDetails = "Authenticode Signed" });
        }

        public void UpdateStats(int quarantineCount, string signatureCount)
        {
            QuarantineCount = quarantineCount;
            if (!string.IsNullOrEmpty(signatureCount))
            {
                TotalSignatures = signatureCount;
            }
        }
    }
}
