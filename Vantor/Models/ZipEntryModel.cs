namespace Vantor.Models
{
    public class ZipEntryModel
    {
        public string EntryName { get; set; } = "";
        public long CompressedBytes { get; set; }
        public long UncompressedBytes { get; set; }
        public double Ratio { get; set; }
        public bool IsDangerous { get; set; }
        public string Status => IsDangerous ? "EXTREME RATIO" : "SAFE";
    }
}
