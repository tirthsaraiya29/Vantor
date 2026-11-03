using System;

namespace Vantor.Models
{
    public class ScanEventItem
    {
        public string Time { get; set; } = DateTime.Now.ToString("HH:mm:ss");
        public string FilePath { get; set; } = "";
        public string FileName => System.IO.Path.GetFileName(FilePath);
        public string Status { get; set; } = "SAFE"; // SAFE, SUSPICIOUS, MALICIOUS
        public string ThreatDetails { get; set; } = "";
        public bool IsThreat => Status == "MALICIOUS" || Status == "SUSPICIOUS";
    }
}
