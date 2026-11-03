using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace Vantor.Common
{
    public class BooleanToVisibilityConverter : IValueConverter
    {
        public bool Invert { get; set; } = false;

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            bool b = value is true;
            if (Invert) b = !b;
            return b ? Visibility.Visible : Visibility.Collapsed;
        }

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            value is Visibility.Visible;
    }

    public class BytesToStringConverter : IValueConverter
    {
        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            if (value is long bytes || (value != null && long.TryParse(value.ToString(), out bytes)))
            {
                if (bytes >= 1024L * 1024L * 1024L) return $"{bytes / (1024.0 * 1024.0 * 1024.0):0.0} GB";
                if (bytes >= 1024L * 1024L) return $"{bytes / (1024.0 * 1024.0):0.0} MB";
                if (bytes >= 1024L) return $"{bytes / 1024.0:0.0} KB";
                return $"{bytes} B";
            }
            return value?.ToString() ?? "0 B";
        }

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            throw new NotImplementedException();
    }

    public class VerdictToBrushConverter : IValueConverter
    {
        private static readonly SolidColorBrush SafeBrush = new(Color.FromRgb(16, 185, 129));
        private static readonly SolidColorBrush ThreatBrush = new(Color.FromRgb(244, 63, 94));
        private static readonly SolidColorBrush WarningBrush = new(Color.FromRgb(245, 158, 11));
        private static readonly SolidColorBrush NeutralBrush = new(Color.FromRgb(148, 163, 184));

        public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            string? verdict = value?.ToString()?.ToUpperInvariant();
            return verdict switch
            {
                "SAFE" or "INTACT" or "PASSED" or "SECURED" or "CLEAN" => SafeBrush,
                "THREAT" or "MALICIOUS" or "FAIL" or "COMPROMISED" or "ZIP-BOMB DETECTED" => ThreatBrush,
                "SUSPICIOUS" or "WARNING" or "NESTED ARCHIVE RISK" => WarningBrush,
                _ => NeutralBrush
            };
        }

        public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            throw new NotImplementedException();
    }
}
