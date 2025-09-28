using System.Windows.Controls;
using ModernWpf;
using System.Linq;
using System.Windows;
using SkzBackupRestore.Wpf.Services;
using Microsoft.Win32;

namespace SkzBackupRestore.Wpf.Pages
{
    public partial class SettingsPage : Page
    {
        public SettingsPage()
        {
            InitializeComponent();
            Loaded += SettingsPage_Loaded;
        }

        private void SettingsPage_Loaded(object sender, System.Windows.RoutedEventArgs e)
        {
            // Initialize toggle without firing Toggled handler
            var handler = new RoutedEventHandler(PreferDarkToggle_Toggled);
            PreferDarkToggle.Toggled -= handler;
            PreferDarkToggle.IsOn = SettingsService.Settings.PreferDarkOnLight;
            PreferDarkToggle.Toggled += handler;

            // Initialize auto-verify
            var autoHandler = new RoutedEventHandler(AutoVerifyToggle_Toggled);
            AutoVerifyToggle.Toggled -= autoHandler;
            AutoVerifyToggle.IsOn = SettingsService.Settings.AutoVerifyImages;
            AutoVerifyToggle.Toggled += autoHandler;

            // Initialize verification mode
            var items = VerificationModeCombo.Items.Cast<ComboBoxItem>().ToList();
            var mode = (SettingsService.Settings.VerificationMode ?? "Full").ToLowerInvariant();
            VerificationModeCombo.SelectedIndex = mode == "quick" ? items.FindIndex(i => (string)i.Content == "Quick") : items.FindIndex(i => (string)i.Content == "Full");
        }

        private void PreferDarkToggle_Toggled(object sender, RoutedEventArgs e)
        {
            SettingsService.Settings.PreferDarkOnLight = PreferDarkToggle.IsOn;
            SettingsService.Save();
            // Re-apply current policy immediately with a subtle fade
            ThemeService.ApplyCurrentPolicy(SettingsService.Settings.PreferDarkOnLight, animate: true);
        }

        private void AutoVerifyToggle_Toggled(object sender, RoutedEventArgs e)
        {
            SettingsService.Settings.AutoVerifyImages = AutoVerifyToggle.IsOn;
            SettingsService.Save();
        }

        private void VerificationModeCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (VerificationModeCombo.SelectedItem is ComboBoxItem item && item.Content is string label)
            {
                SettingsService.Settings.VerificationMode = label;
                SettingsService.Save();
            }
        }
    }
}
