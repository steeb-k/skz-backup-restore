using ModernWpf;
using System.Linq;
using System.Windows;
using Microsoft.Win32;
using System;
using System.Windows.Media.Animation;

namespace SkzBackupRestore.Wpf.Services
{
    public static class ThemeService
    {
        /// <summary>
        /// Apply theme using current Windows Apps theme and user preference (PreferDarkOnLight)
        /// </summary>
        public static void ApplyCurrentPolicy(bool preferDarkOnLight, bool animate = false)
        {
            bool windowsIsLight = ReadAppsUseLightTheme() == 1;
            Action apply = () =>
            {
                if (preferDarkOnLight && windowsIsLight)
                    SetRequestedTheme(ApplicationTheme.Dark);
                else if (windowsIsLight)
                    SetRequestedTheme(ApplicationTheme.Light);
                else
                    SetRequestedTheme(ApplicationTheme.Dark);
            };

            if (animate)
                FadeApply(apply);
            else
                apply();
        }

        private static void FadeApply(Action apply)
        {
            var win = System.Windows.Application.Current?.MainWindow;
            if (win?.Content is FrameworkElement fe)
            {
                // Stop any current animations
                fe.BeginAnimation(UIElement.OpacityProperty, null);
                double start = fe.Opacity;
                var fadeOut = new DoubleAnimation(start, 0.0, TimeSpan.FromMilliseconds(120)) { FillBehavior = FillBehavior.Stop };
                fadeOut.Completed += (s, e) =>
                {
                    // Apply theme at darkest point
                    apply();
                    // Fade back in
                    var fadeIn = new DoubleAnimation(0.0, 1.0, TimeSpan.FromMilliseconds(160)) { FillBehavior = FillBehavior.Stop };
                    fadeIn.Completed += (_, __) => fe.Opacity = 1.0;
                    fe.BeginAnimation(UIElement.OpacityProperty, fadeIn);
                };
                fe.BeginAnimation(UIElement.OpacityProperty, fadeOut);
            }
            else
            {
                apply();
            }
        }

        public static ApplicationTheme? GetRequestedTheme()
        {
            var tr = GetThemeResources();
            // When following system, RequestedTheme may not be explicitly set
            // and returns default(ApplicationTheme) which is Light. We treat absence as null.
            // To detect Auto reliably, we track a marker via ResourceDictionary?
            // Simpler: if ThemeResources instance was created without RequestedTheme,
            // it will be the default we create in SetRequestedTheme when theme == null.
            return tr?.RequestedTheme;
        }

        public static void SetRequestedTheme(ApplicationTheme? theme)
        {
            var app = System.Windows.Application.Current;
            if (app == null) return;
            var md = app.Resources.MergedDictionaries;
            var tr = md.OfType<ThemeResources>().FirstOrDefault();
            if (theme.HasValue)
            {
                if (tr == null)
                {
                    tr = new ThemeResources();
                    md.Insert(0, tr);
                }
                tr.RequestedTheme = theme.Value;
            }
            else
            {
                // Follow system: replace ThemeResources with a fresh one that does not set RequestedTheme
                if (tr != null)
                {
                    var idx = md.IndexOf(tr);
                    md[idx] = new ThemeResources();
                }
                else
                {
                    md.Insert(0, new ThemeResources());
                }
            }
        }

        public static int ReadAppsUseLightTheme()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize");
                object? val = key?.GetValue("AppsUseLightTheme");
                if (val is int i) return i; // 1=light, 0=dark
                if (val is byte b) return b;
            }
            catch { }
            return 1;
        }

        private static ThemeResources? GetThemeResources()
        {
            return System.Windows.Application.Current?.Resources.MergedDictionaries.OfType<ThemeResources>().FirstOrDefault();
        }
    }
}
