using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Data.Sqlite;
using Vantor.Common;
using Vantor.Models;
using Vantor.Services;

namespace Vantor.ViewModels
{
    public class QuarantineVaultViewModel : ViewModelBase
    {
        private readonly IVantorIpcClient _ipcClient;
        private readonly string _dbPath;

        private string _searchQuery = "";
        private QuarantineItemModel? _selectedItem;
        private bool _isDetailDrawerOpen;
        private bool _isEmpty = true;
        private string _statusNotice = "";

        public ObservableCollection<QuarantineItemModel> AllItems { get; } = new();
        public ObservableCollection<QuarantineItemModel> FilteredItems { get; } = new();

        public string SearchQuery
        {
            get => _searchQuery;
            set
            {
                if (SetProperty(ref _searchQuery, value))
                {
                    ApplyFilter();
                }
            }
        }

        public QuarantineItemModel? SelectedItem
        {
            get => _selectedItem;
            set
            {
                if (SetProperty(ref _selectedItem, value))
                {
                    IsDetailDrawerOpen = value != null;
                }
            }
        }

        public bool IsDetailDrawerOpen
        {
            get => _isDetailDrawerOpen;
            set => SetProperty(ref _isDetailDrawerOpen, value);
        }

        public bool IsEmpty
        {
            get => _isEmpty;
            set => SetProperty(ref _isEmpty, value);
        }

        public string StatusNotice
        {
            get => _statusNotice;
            set => SetProperty(ref _statusNotice, value);
        }

        public ICommand RefreshCommand { get; }
        public ICommand RestoreItemCommand { get; }
        public ICommand DeleteItemCommand { get; }
        public ICommand CloseDrawerCommand { get; }

        public QuarantineVaultViewModel(IVantorIpcClient ipcClient, string dbPath)
        {
            _ipcClient = ipcClient;
            _dbPath = dbPath;

            RefreshCommand = new RelayCommand(LoadQuarantine);
            RestoreItemCommand = new AsyncRelayCommand(async item =>
            {
                if (item is QuarantineItemModel q)
                {
                    var confirm = MessageBox.Show(
                        $"Are you sure you want to restore {q.FileName} to its original location?\n\nIf a file already exists, it will be restored with an '_restored' suffix to avoid collisions.",
                        "Confirm Quarantine Restoration", MessageBoxButton.YesNo, MessageBoxImage.Warning);

                    if (confirm == MessageBoxResult.Yes)
                    {
                        bool ok = await _ipcClient.RestoreQuarantineAsync(q.Id, q.OriginalPath);
                        StatusNotice = ok ? $"Successfully restored {q.FileName}." : $"Restoration requested for {q.FileName}.";
                        LoadQuarantine();
                    }
                }
            });

            DeleteItemCommand = new AsyncRelayCommand(async item =>
            {
                if (item is QuarantineItemModel q)
                {
                    var confirm = MessageBox.Show(
                        $"Permanently shred and delete {q.FileName} from the containment vault?\nThis operation is irreversible.",
                        "Confirm Permanent Deletion", MessageBoxButton.YesNo, MessageBoxImage.Question);

                    if (confirm == MessageBoxResult.Yes)
                    {
                        await _ipcClient.DeleteQuarantineAsync(q.Id);
                        StatusNotice = $"Permanently purged {q.FileName}.";
                        LoadQuarantine();
                        IsDetailDrawerOpen = false;
                    }
                }
            });

            CloseDrawerCommand = new RelayCommand(() => IsDetailDrawerOpen = false);

            LoadQuarantine();
        }

        public void LoadQuarantine()
        {
            AllItems.Clear();

            if (File.Exists(_dbPath))
            {
                try
                {
                    using var conn = new SqliteConnection($"Data Source={_dbPath}");
                    conn.Open();
                    using var cmd = conn.CreateCommand();
                    cmd.CommandText = "SELECT id, timestamp, scan_id, original_path, encrypted_filename, sha256, sha512, threat_name, file_size FROM quarantined_files ORDER BY id DESC";
                    using var reader = cmd.ExecuteReader();
                    while (reader.Read())
                    {
                        AllItems.Add(new QuarantineItemModel
                        {
                            Id = reader.GetInt64(0),
                            Timestamp = reader.IsDBNull(1) ? "" : reader.GetString(1),
                            ScanId = reader.IsDBNull(2) ? "" : reader.GetString(2),
                            OriginalPath = reader.IsDBNull(3) ? "" : reader.GetString(3),
                            EncryptedFilename = reader.IsDBNull(4) ? "" : reader.GetString(4),
                            Sha256 = reader.IsDBNull(5) ? "" : reader.GetString(5),
                            Sha512 = reader.IsDBNull(6) ? "" : reader.GetString(6),
                            ThreatName = reader.IsDBNull(7) ? "Trojan.Generic.Vantor" : reader.GetString(7),
                            FileSizeBytes = reader.IsDBNull(8) ? 0 : reader.GetInt64(8)
                        });
                    }
                }
                catch { }
            }

            ApplyFilter();
        }

        private void ApplyFilter()
        {
            FilteredItems.Clear();
            string q = SearchQuery.Trim().ToLowerInvariant();

            foreach (var item in AllItems)
            {
                if (string.IsNullOrEmpty(q) ||
                    item.FileName.ToLowerInvariant().Contains(q) ||
                    item.ThreatName.ToLowerInvariant().Contains(q) ||
                    item.OriginalPath.ToLowerInvariant().Contains(q) ||
                    item.Sha256.ToLowerInvariant().Contains(q))
                {
                    FilteredItems.Add(item);
                }
            }

            IsEmpty = FilteredItems.Count == 0;
        }
    }
}
