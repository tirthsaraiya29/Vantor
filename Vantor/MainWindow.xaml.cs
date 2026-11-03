using System;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Vantor.Services;
using Vantor.ViewModels;
using IOPath = System.IO.Path;

namespace Vantor
{
    public partial class MainWindow : Window
    {
        private readonly MainViewModel _mainViewModel;
        private readonly VantorIpcClient _ipcClient;

        public MainWindow()
        {
            InitializeComponent();

            string baseDir = AppDomain.CurrentDomain.BaseDirectory;

            // Search root repository directory or bin directory dynamically
            string repoRoot = baseDir;
            string? current = baseDir;
            while (!string.IsNullOrEmpty(current))
            {
                if (File.Exists(IOPath.Combine(current, "VantorBackend.exe")) ||
                    File.Exists(IOPath.Combine(current, "CMakeLists.txt")) ||
                    File.Exists(IOPath.Combine(current, "signatures.db")))
                {
                    repoRoot = current;
                    break;
                }
                var parent = Directory.GetParent(current);
                if (parent == null || parent.FullName == current) break;
                current = parent.FullName;
            }

            string backendExe = FindFile("VantorBackend.exe", baseDir, repoRoot, IOPath.Combine(repoRoot, "build", "backend", "Release"));
            string serviceExe = FindFile("VantorService.exe", baseDir, repoRoot, IOPath.Combine(repoRoot, "build", "service", "Release"));
            string workingDir = IOPath.GetDirectoryName(backendExe) ?? repoRoot;

            string quarantineDbPath = FindFile("quarantine.db",
                IOPath.Combine(repoRoot, "quarantine"),
                IOPath.Combine(baseDir, "quarantine"));

            if (!File.Exists(quarantineDbPath))
            {
                string qDir = IOPath.Combine(repoRoot, "quarantine");
                Directory.CreateDirectory(qDir);
                quarantineDbPath = IOPath.Combine(qDir, "quarantine.db");
            }

            _ipcClient = new VantorIpcClient();
            _mainViewModel = new MainViewModel(_ipcClient, backendExe, serviceExe, workingDir, quarantineDbPath);

            DataContext = _mainViewModel;
        }

        private static string FindFile(string filename, params string[] searchPaths)
        {
            foreach (var path in searchPaths)
            {
                if (string.IsNullOrEmpty(path)) continue;
                string full = IOPath.Combine(path, filename);
                if (File.Exists(full)) return full;
            }
            return IOPath.Combine(AppDomain.CurrentDomain.BaseDirectory, filename);
        }

        // ======================== WINDOW DRAG & CONTROLS ========================

        private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ClickCount == 2)
            {
                MaximizeButton_Click(sender, e);
            }
            else if (e.LeftButton == MouseButtonState.Pressed)
            {
                DragMove();
            }
        }

        private void MinimizeButton_Click(object sender, RoutedEventArgs e) =>
            WindowState = WindowState.Minimized;

        private void MaximizeButton_Click(object sender, RoutedEventArgs e) =>
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            _ipcClient.StopHeartbeat();
            _ipcClient.Dispose();
            Application.Current.Shutdown();
        }

        // ======================== DRAG & DROP ROUTING ========================

        private void Window_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effects = DragDropEffects.Copy;
            }
        }

        private void Window_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files.Length > 0)
                {
                    string file = files[0];
                    string ext = IOPath.GetExtension(file).ToLowerInvariant();

                    if (ext is ".zip" or ".jar" or ".apk")
                    {
                        _mainViewModel.CurrentViewModel = _mainViewModel.ZipBombVM;
                        _mainViewModel.ZipBombVM.InspectArchive(file);
                    }
                    else
                    {
                        _mainViewModel.CurrentViewModel = _mainViewModel.ScanCenterVM;
                        _mainViewModel.ScanCenterVM.StartScan("custom", file);
                    }
                }
            }
        }
    }
}
