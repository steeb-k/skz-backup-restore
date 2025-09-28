using SkzBackupRestore.Wpf.Models;
using System;
using System.IO;
using System.Text.Json;

namespace SkzBackupRestore.Wpf.Services
{
    public static class SettingsService
    {
        private static readonly string AppDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "skz-backup-restore");
        private static readonly string SettingsPath = Path.Combine(AppDir, "settings.json");

        public static UserSettings Settings { get; private set; } = new();

        public static void Load()
        {
            try
            {
                if (File.Exists(SettingsPath))
                {
                    var json = File.ReadAllText(SettingsPath);
                    var s = JsonSerializer.Deserialize<UserSettings>(json);
                    if (s != null) Settings = s;
                }
            }
            catch { /* ignore */ }
        }

        public static void Save()
        {
            try
            {
                Directory.CreateDirectory(AppDir);
                var json = JsonSerializer.Serialize(Settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(SettingsPath, json);
            }
            catch { /* ignore */ }
        }
    }
}
