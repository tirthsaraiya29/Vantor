using System;
using System.IO;

namespace Vantor.Models
{
    public class QuarantineItemModel
    {
        public long Id { get; set; }
        public string Timestamp { get; set; } = "";
        public string ScanId { get; set; } = "";
        public string OriginalPath { get; set; } = "";
        public string FileName => Path.GetFileName(OriginalPath);
        public string EncryptedFilename { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public string Sha512 { get; set; } = "";
        public string ThreatName { get; set; } = "Trojan.Generic.Vantor";
        public long FileSizeBytes { get; set; } = 0;
        public double ShannonEntropy { get; set; } = 7.64;
    }
}
