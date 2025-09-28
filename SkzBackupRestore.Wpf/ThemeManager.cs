using Microsoft.Win32;
using System;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Threading;

namespace SkzBackupRestore.Wpf
{
    public enum ThemePreference { Auto, Light, Dark }

    public static class ThemeManager
    {
        private static ResourceDictionary? _light;
        private static ResourceDictionary? _dark;
        private static ThemePreference _preference = ThemePreference.Auto;
        private static DispatcherTimer? _poll;
        private static int _lastAppsLightTheme = -1;

        public static ThemePreference Preference => _preference;

        public static void Initialize()
        {
            // Load theme dictionaries once
            _light = new ResourceDictionary { Source = new Uri("Themes/Light.xaml", UriKind.Relative) };
            _dark = new ResourceDictionary { Source = new Uri("Themes/Dark.xaml", UriKind.Relative) };

            // Default to Auto (follow system)
            SetPreference(ThemePreference.Auto);

            // Poll for system theme changes every 2 seconds when in Auto mode
            _poll = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _poll.Tick += (s, e) =>
            {
                if (_preference != ThemePreference.Auto) return;
                int val = ReadAppsUseLightTheme();
                if (val != _lastAppsLightTheme)
                {
                    _lastAppsLightTheme = val;
                    ApplyCurrent();
                }
            };
            _poll.Start();
        }

        public static void SetPreference(ThemePreference pref)
        {
            _preference = pref;
            // Reset cache to force apply
            _lastAppsLightTheme = -1;
            ApplyCurrent();
        }

        private static void ApplyCurrent()
        {
            bool useLight = _preference switch
            {
                ThemePreference.Light => true,
                ThemePreference.Dark => false,
                _ => ReadAppsUseLightTheme() == 1
            };
            var app = System.Windows.Application.Current;
            if (app == null) return;
            var md = app.Resources.MergedDictionaries;

            // Remove existing theme dictionaries
            foreach (var existing in md.ToList())
            {
                if (existing.Source != null && existing.Source.OriginalString.StartsWith("Themes/", StringComparison.OrdinalIgnoreCase))
                {
                    md.Remove(existing);
                }
            }

            if (useLight && _light != null) md.Add(_light);
            else if (!useLight && _dark != null) md.Add(_dark);
        }

        private static int ReadAppsUseLightTheme()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize");
                object? val = key?.GetValue("AppsUseLightTheme");
                if (val is int i) return i; // 1=light, 0=dark
                if (val is byte b) return b; // defensive
            }
            catch { }
            return 1; // default to light if unknown
        }
    }
}
