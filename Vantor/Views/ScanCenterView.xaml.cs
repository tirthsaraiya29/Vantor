using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;

namespace Vantor.Views
{
    public partial class ScanCenterView : UserControl
    {
        public ScanCenterView()
        {
            InitializeComponent();
            Loaded += (s, e) =>
            {
                try
                {
                    if (FindResource("RadarSweepStoryboard") is Storyboard sb)
                    {
                        sb.Begin(this, true);
                    }
                }
                catch { }
            };
        }
    }
}
