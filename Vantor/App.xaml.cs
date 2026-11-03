using System;
using System.Diagnostics;
using System.Windows;

namespace Vantor
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : System.Windows.Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                Debug.WriteLine($"[CRITICAL] Unhandled AppDomain exception: {args.ExceptionObject}");
            };

            DispatcherUnhandledException += (s, args) =>
            {
                Debug.WriteLine($"[CRITICAL] Unhandled Dispatcher exception: {args.Exception.Message}");
                args.Handled = true;
                MessageBox.Show($"An unexpected UI error occurred: {args.Exception.Message}", "Vantor UI Alert", MessageBoxButton.OK, MessageBoxImage.Warning);
            };
        }
    }
}
