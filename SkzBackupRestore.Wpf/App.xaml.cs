using System.Windows;
using SkzBackupRestore.Wpf.Services;
using ModernWpf;
using Microsoft.Win32;
using System;
using System.Threading;

namespace SkzBackupRestore.Wpf
{
    public partial class App : System.Windows.Application
    {
        private System.Threading.Timer? _themeWatcher;
        private RegistryThemeWatcher? _registryWatcher;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            // Load user settings
            SettingsService.Load();
            // Apply current policy
            ThemeService.ApplyCurrentPolicy(SettingsService.Settings.PreferDarkOnLight, animate: false);

            // One-time migration: reset legacy Theme field to Auto if not already
            if (SettingsService.Settings.Theme != "Auto")
            {
                SettingsService.Settings.Theme = "Auto";
                SettingsService.Save();
            }

            // Watch for system theme changes (AppsUseLightTheme) and re-apply policy
            SystemEvents.UserPreferenceChanged += SystemEvents_UserPreferenceChanged;
            SystemEvents.UserPreferenceChanging += SystemEvents_UserPreferenceChanging;
            // Debounce via timer (for system events and registry watcher)
            _themeWatcher = new System.Threading.Timer(_ =>
            {
                Dispatcher?.Invoke(() => ThemeService.ApplyCurrentPolicy(SettingsService.Settings.PreferDarkOnLight, animate: true));
            }, null, System.Threading.Timeout.Infinite, System.Threading.Timeout.Infinite);

            // Start registry watcher for HKCU Personalize changes
            _registryWatcher = new RegistryThemeWatcher();
            _registryWatcher.Start(() => _themeWatcher?.Change(200, System.Threading.Timeout.Infinite));
        }

        private void SystemEvents_UserPreferenceChanged(object? sender, UserPreferenceChangedEventArgs e)
        {
            if (e.Category == UserPreferenceCategory.General || e.Category == UserPreferenceCategory.Color)
            {
                // schedule a re-apply shortly after change
                _themeWatcher?.Change(250, System.Threading.Timeout.Infinite);
            }
        }

        private void SystemEvents_UserPreferenceChanging(object? sender, UserPreferenceChangingEventArgs e)
        {
            if (e.Category == UserPreferenceCategory.General || e.Category == UserPreferenceCategory.Color)
            {
                _themeWatcher?.Change(250, System.Threading.Timeout.Infinite);
            }
        }

        protected override void OnExit(ExitEventArgs e)
        {
            SystemEvents.UserPreferenceChanged -= SystemEvents_UserPreferenceChanged;
            SystemEvents.UserPreferenceChanging -= SystemEvents_UserPreferenceChanging;
            _registryWatcher?.Dispose();
            _themeWatcher?.Dispose();
            base.OnExit(e);
        }
    }
}
