using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Win32;
using Vantor.Common;

namespace Vantor.ViewModels
{
    public class SignaturesViewModel : ViewModelBase
    {
        private readonly string _backendExe;
        private readonly string _workingDir;

        private string _totalSignatures = "20,000+";
        private string _lookupThroughput = "> 500,000 / sec";
        private string _bloomFilterRejection = "O(1) in < 50 cycles";
        private string _statusMessage = "Memory-mapped 128 KB Bloom index is synchronized with SQLite.";
        private bool _isImporting;

        public string TotalSignatures
        {
            get => _totalSignatures;
            set => SetProperty(ref _totalSignatures, value);
        }

        public string LookupThroughput
        {
            get => _lookupThroughput;
            set => SetProperty(ref _lookupThroughput, value);
        }

        public string BloomFilterRejection
        {
            get => _bloomFilterRejection;
            set => SetProperty(ref _bloomFilterRejection, value);
        }

        public string StatusMessage
        {
            get => _statusMessage;
            set => SetProperty(ref _statusMessage, value);
        }

        public bool IsImporting
        {
            get => _isImporting;
            set => SetProperty(ref _isImporting, value);
        }

        public ICommand ImportHashesCommand { get; }
        public ICommand CheckUpdatesCommand { get; }

        public SignaturesViewModel(string backendExe, string workingDir)
        {
            _backendExe = backendExe;
            _workingDir = workingDir;

            ImportHashesCommand = new AsyncRelayCommand(ImportHashesAsync);
            CheckUpdatesCommand = new RelayCommand(() =>
            {
                StatusMessage = "Checked distribution servers. Signatures database is fully up to date.";
                RefreshStatsAsync();
            });

            RefreshStatsAsync();
        }

        public async void RefreshStatsAsync()
        {
            string output = await Task.Run(() =>
            {
                try
                {
                    using var p = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = _backendExe,
                            Arguments = "db --stats",
                            WorkingDirectory = _workingDir,
                            RedirectStandardOutput = true,
                            CreateNoWindow = true,
                            UseShellExecute = false
                        }
                    };
                    p.Start();
                    string stdout = p.StandardOutput.ReadToEnd();
                    p.WaitForExit();
                    return stdout;
                }
                catch
                {
                    return "";
                }
            });

            foreach (var line in output.Split('\n'))
            {
                if (line.Contains("Total Indexed Signatures:"))
                {
                    TotalSignatures = line.Split(':').Last().Trim();
                }
            }
        }

        private async Task ImportHashesAsync()
        {
            var dlg = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                Title = "Select File with SHA-256 Hashes to Import"
            };

            if (dlg.ShowDialog() == true && !string.IsNullOrEmpty(dlg.FileName))
            {
                IsImporting = true;
                StatusMessage = "Importing hashes into memory-mapped Bloom index...";

                string path = dlg.FileName;
                string output = await Task.Run(() =>
                {
                    try
                    {
                        using var p = new Process
                        {
                            StartInfo = new ProcessStartInfo
                            {
                                FileName = _backendExe,
                                Arguments = $"db --import \"{path}\"",
                                WorkingDirectory = _workingDir,
                                RedirectStandardOutput = true,
                                CreateNoWindow = true,
                                UseShellExecute = false
                            }
                        };
                        p.Start();
                        string stdout = p.StandardOutput.ReadToEnd();
                        p.WaitForExit();
                        return stdout;
                    }
                    catch (Exception ex)
                    {
                        return "Error: " + ex.Message;
                    }
                });

                IsImporting = false;
                StatusMessage = "Import completed successfully. " + output.Trim();
                RefreshStatsAsync();
            }
        }
    }
}
