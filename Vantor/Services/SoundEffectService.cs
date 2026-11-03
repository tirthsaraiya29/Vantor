using System;
using System.Media;
using System.Threading.Tasks;

namespace Vantor.Services
{
    public class SoundEffectService
    {
        public static bool SoundEnabled { get; set; } = true;

        public static void PlayThreatAlert()
        {
            if (!SoundEnabled) return;
            Task.Run(() =>
            {
                try
                {
                    SystemSounds.Hand.Play();
                }
                catch { }
            });
        }

        public static void PlayScanComplete()
        {
            if (!SoundEnabled) return;
            Task.Run(() =>
            {
                try
                {
                    SystemSounds.Asterisk.Play();
                }
                catch { }
            });
        }

        public static void PlayActionBeep()
        {
            if (!SoundEnabled) return;
            Task.Run(() =>
            {
                try
                {
                    SystemSounds.Beep.Play();
                }
                catch { }
            });
        }
    }
}
