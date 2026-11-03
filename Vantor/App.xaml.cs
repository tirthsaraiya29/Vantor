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
        private static bool _hasShownErrorDialog = false;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                Debug.WriteLine($"[CRITICAL] Unhandled AppDomain exception: {args.ExceptionObject}");
            };

            DispatcherUnhandledException += (s, args) =>
            {
                Debug.WriteLine($"[CRITICAL] Unhandled Dispatcher exception: {args.Exception}");
                args.Handled = true;

                if (!_hasShownErrorDialog)
                {
                    _hasShownErrorDialog = true;
                    MessageBox.Show(
                        $"Vantor encountered a UI exception: {args.Exception.Message}",
                        "Vantor UI Alert",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }
            };
        }
    }
}
