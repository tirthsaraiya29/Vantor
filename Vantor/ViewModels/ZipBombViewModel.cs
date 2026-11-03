using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.Win32;
using Vantor.Common;
using Vantor.Models;

namespace Vantor.ViewModels
{
    public class ZipBombViewModel : ViewModelBase
    {
        private readonly string _backendExe;
        private readonly string _workingDir;

        private string _archiveFileName = "No archive selected";
        private string _verdictText = "WAITING";
        private string _compressionRatioText = "—";
        private string _uncompressedSizeText = "—";
        private string _totalEntriesText = "—";
        private string _verdictReason = "Drag and drop any .zip, .jar, or .apk archive onto this window or click below to audit without decompressing.";
        private bool _isAnalyzing;

        public ObservableCollection<ZipEntryModel> FlaggedEntries { get; } = new();

        public string ArchiveFileName
        {
            get => _archiveFileName;
            set => SetProperty(ref _archiveFileName, value);
        }

        public string VerdictText
        {
            get => _verdictText;
            set => SetProperty(ref _verdictText, value);
        }

        public string CompressionRatioText
        {
            get => _compressionRatioText;
            set => SetProperty(ref _compressionRatioText, value);
        }

        public string UncompressedSizeText
        {
            get => _uncompressedSizeText;
            set => SetProperty(ref _uncompressedSizeText, value);
        }

        public string TotalEntriesText
        {
            get => _totalEntriesText;
            set => SetProperty(ref _totalEntriesText, value);
        }

        public string VerdictReason
        {
            get => _verdictReason;
            set => SetProperty(ref _verdictReason, value);
        }

        public bool IsAnalyzing
        {
            get => _isAnalyzing;
            set => SetProperty(ref _isAnalyzing, value);
        }

        public ICommand BrowseArchiveCommand { get; }

        public ZipBombViewModel(string backendExe, string workingDir)
        {
            _backendExe = backendExe;
            _workingDir = workingDir;

            BrowseArchiveCommand = new RelayCommand(() =>
            {
                var dlg = new OpenFileDialog
                {
                    Filter = "Archive Files (*.zip;*.jar;*.apk)|*.zip;*.jar;*.apk|All Files (*.*)|*.*",
                    Title = "Select Archive to Audit for Zip-Bombs"
                };
                if (dlg.ShowDialog() == true && !string.IsNullOrEmpty(dlg.FileName))
                {
                    InspectArchive(dlg.FileName);
                }
            });
        }

        public async void InspectArchive(string archivePath)
        {
            ArchiveFileName = Path.GetFileName(archivePath);
            VerdictText = "ANALYZING...";
            IsAnalyzing = true;
            FlaggedEntries.Clear();

            string output = await Task.Run(() =>
            {
                try
                {
                    using var p = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = _backendExe,
                            Arguments = $"inspect-zip \"{archivePath}\"",
                            WorkingDirectory = _workingDir,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
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

            IsAnalyzing = false;

            string verdict = "UNKNOWN";
            string ratio = "1.0x";
            string uncompressed = "—";
            string entries = "—";
            string reason = output;

            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("Verdict:")) verdict = trimmed.Replace("Verdict:", "").Trim();
                else if (trimmed.StartsWith("Compression Ratio:")) ratio = trimmed.Replace("Compression Ratio:", "").Trim();
                else if (trimmed.StartsWith("Total Uncompressed:")) uncompressed = FormatBytes(trimmed.Replace("Total Uncompressed:", "").Trim());
                else if (trimmed.StartsWith("Total Entries:")) entries = trimmed.Replace("Total Entries:", "").Trim();
                else if (trimmed.StartsWith("Evaluation Reason:")) reason = trimmed.Replace("Evaluation Reason:", "").Trim();
            }

            VerdictText = verdict.ToUpperInvariant();
            CompressionRatioText = ratio;
            UncompressedSizeText = uncompressed;
            TotalEntriesText = entries;
            VerdictReason = reason;
        }

        private static string FormatBytes(string bytesRaw)
        {
            if (long.TryParse(bytesRaw.Replace("bytes", "").Trim(), out long b))
            {
                if (b > 1024 * 1024 * 1024) return $"{b / (1024.0 * 1024 * 1024):0.0} GB";
                if (b > 1024 * 1024) return $"{b / (1024.0 * 1024):0.0} MB";
                if (b > 1024) return $"{b / 1024.0:0.0} KB";
                return $"{b} B";
            }
            return bytesRaw;
        }
    }
}
