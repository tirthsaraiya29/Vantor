namespace Vantor.Models
{
    public class SecurityAuditItem
    {
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public string Status { get; set; } = "UNKNOWN"; // PASSED, COMPROMISED, PENDING
        public string Details { get; set; } = "";
    }
}
