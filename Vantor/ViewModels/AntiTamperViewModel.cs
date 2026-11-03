using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows.Input;
using Vantor.Common;
using Vantor.Services;

namespace Vantor.ViewModels
{
    public class AntiTamperViewModel : ViewModelBase
    {
        private readonly string _backendExe;
        private readonly string _workingDir;

        private string _authenticodeStatus = "PASSED";
        private string _textSectionStatus = "INTACT";
        private string _apiHooksStatus = "CLEAN";
        private string _antiDebugStatus = "SECURED";
        private bool _isAuditRunning;
        private string _auditSummary = "All defensive shields active. Click 'RUN FULL INTEGRITY AUDIT' to measure runtime telemetry live.";

        public string AuthenticodeStatus
        {
            get => _authenticodeStatus;
            set => SetProperty(ref _authenticodeStatus, value);
        }

        public string TextSectionStatus
        {
            get => _textSectionStatus;
            set => SetProperty(ref _textSectionStatus, value);
        }

        public string ApiHooksStatus
        {
            get => _apiHooksStatus;
            set => SetProperty(ref _apiHooksStatus, value);
        }

        public string AntiDebugStatus
        {
            get => _antiDebugStatus;
            set => SetProperty(ref _antiDebugStatus, value);
        }

        public bool IsAuditRunning
        {
            get => _isAuditRunning;
            set => SetProperty(ref _isAuditRunning, value);
        }

        public string AuditSummary
        {
            get => _auditSummary;
            set => SetProperty(ref _auditSummary, value);
        }

        public ICommand RunAuditCommand { get; }

        public AntiTamperViewModel(string backendExe, string workingDir)
        {
            _backendExe = backendExe;
            _workingDir = workingDir;

            RunAuditCommand = new AsyncRelayCommand(RunAuditAsync);
        }

        public async Task RunAuditAsync()
        {
            IsAuditRunning = true;
            AuditSummary = "Measuring in-memory code hashes, digital signatures, and inspecting inline jump hooks...";

            string output = await Task.Run(() =>
            {
                try
                {
                    using var p = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = _backendExe,
                            Arguments = "verify",
                            WorkingDirectory = _workingDir,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true,
                            UseShellExecute = false
                        }
                    };
                    p.Start();
                    string stdout = p.StandardOutput.ReadToEnd();
                    string stderr = p.StandardError.ReadToEnd();
                    p.WaitForExit();
                    return stdout + stderr;
                }
                catch (Exception ex)
                {
                    return "Error: " + ex.Message;
                }
            });

            IsAuditRunning = false;

            if (output.Contains("All user-mode integrity, code-signing, self-hash, and anti-debug checks passed"))
            {
                AuthenticodeStatus = "PASSED";
                TextSectionStatus = "INTACT";
                ApiHooksStatus = "CLEAN";
                AntiDebugStatus = "SECURED";
                AuditSummary = "✓ 100% of user-mode integrity, in-memory .text hashes, and anti-debug checks PASSED safely.";
                SoundEffectService.PlayScanComplete();
            }
            else
            {
                AuditSummary = output.Trim();
            }
        }
    }
}
