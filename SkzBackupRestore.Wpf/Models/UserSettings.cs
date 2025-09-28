namespace SkzBackupRestore.Wpf.Models
{
    public class UserSettings
    {
        // "Auto" | "Light" | "Dark"
        public string Theme { get; set; } = "Auto";
        // New: when system is Light, allow forcing Dark
        public bool PreferDarkOnLight { get; set; } = false;

        // Backup verification settings
        // When true, new backups default to "verify after image" checked in the wizard
        public bool AutoVerifyImages { get; set; } = true;
        // "Full" | "Quick"
        public string VerificationMode { get; set; } = "Full";
    }
}
