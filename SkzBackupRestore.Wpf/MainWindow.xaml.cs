using ModernWpf.Controls;
using System.Linq;
using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Threading;
using SkzBackupRestore.Wpf.Services;

namespace SkzBackupRestore.Wpf
{
    public partial class MainWindow : Window
    {
        private HwndSource? _hwndSource;
        private DispatcherTimer? _themeMsgDebounce;

        public MainWindow()
        {
            InitializeComponent();
            Nav.SelectionChanged += Nav_SelectionChanged;
            // Ensure the Backup item is selected in the sidebar on startup
            var initial = Nav.MenuItems.OfType<NavigationViewItem>().FirstOrDefault(i => (i.Tag as string) == "Backup");
            if (initial != null)
            {
                Nav.SelectedItem = initial;
            }
            // Default page
            ContentFrame.Navigate(new Pages.BackupPage());

            // DragGrid is marked as a drag target via XAML (ui:TitleBar.SetIsDragTarget="True").
            // Debounce timer for theme change notifications from WndProc
            _themeMsgDebounce = new DispatcherTimer(TimeSpan.FromMilliseconds(250), DispatcherPriority.Normal, (s, e) =>
            {
                try
                {
                    _themeMsgDebounce?.Stop();
                    ThemeService.ApplyCurrentPolicy(Services.SettingsService.Settings.PreferDarkOnLight, animate: true);
                }
                catch { }
            }, Dispatcher.CurrentDispatcher);
        }

        private void Nav_ItemInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs args)
        {
            if (args.IsSettingsInvoked)
            {
                ContentFrame.Navigate(new Pages.SettingsPage());
            }
        }

        private void Nav_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            // Ensure icons remain visible by never letting the NavigationView fall into Minimal mode.
            // Compact mode shows icons; Minimal hides the pane entirely.
            const double compactThreshold = 800; // tweak as desired
            if (Nav.ActualWidth < compactThreshold)
            {
                // Compact mode; keep the pane closed but icons visible
                if (Nav.PaneDisplayMode != NavigationViewPaneDisplayMode.LeftCompact)
                    Nav.PaneDisplayMode = NavigationViewPaneDisplayMode.LeftCompact;
                Nav.IsPaneOpen = false;
            }
            else
            {
                if (Nav.PaneDisplayMode != NavigationViewPaneDisplayMode.Left)
                    Nav.PaneDisplayMode = NavigationViewPaneDisplayMode.Left;
                Nav.IsPaneOpen = true;
            }
        }

        protected override void OnSourceInitialized(EventArgs e)
        {
            base.OnSourceInitialized(e);
            _hwndSource = (HwndSource?)PresentationSource.FromVisual(this);
            _hwndSource?.AddHook(WndProc);

            // Compute OpenPaneLength so it is roughly 200 physical pixels on the current display.
            try
            {
                var dpi = _hwndSource?.CompositionTarget?.TransformToDevice.M11 ?? 1.0; // scale factor
                // WPF device-independent units are 1/96th inch; convert desired physical px to DIU
                double desiredPhysicalPixels = 200.0;
                double diu = desiredPhysicalPixels / dpi; // DIU units for OpenPaneLength
                Nav.OpenPaneLength = diu;
            }
            catch { /* ignore - if we can't compute DPI, keep default */ }
        }

        private void DragGrid_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed)
            {
                try { DragMove(); } catch { /* ignore - occasionally throws if called during window state changes */ }
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            _hwndSource?.RemoveHook(WndProc);
            _hwndSource = null;
            base.OnClosed(e);
        }

        private const int WM_SETTINGCHANGE = 0x001A;
        private const int WM_THEMECHANGED = 0x031A;

        private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
        {
            if (msg == WM_SETTINGCHANGE)
            {
                // lParam points to a Unicode string identifying the setting
                string? param = Marshal.PtrToStringUni(lParam);
                if (string.IsNullOrEmpty(param) ||
                    param.Equals("ImmersiveColorSet", StringComparison.OrdinalIgnoreCase) ||
                    param.Equals("WindowsTheme", StringComparison.OrdinalIgnoreCase) ||
                    param.Equals("AppsUseLightTheme", StringComparison.OrdinalIgnoreCase) ||
                    param.Equals("SystemUsesLightTheme", StringComparison.OrdinalIgnoreCase))
                {
                    // Schedule a single apply shortly after the system finishes updating
                    _themeMsgDebounce?.Stop();
                    _themeMsgDebounce?.Start();
                }
            }
            else if (msg == WM_THEMECHANGED)
            {
                _themeMsgDebounce?.Stop();
                _themeMsgDebounce?.Start();
            }
            return IntPtr.Zero;
        }

        private void Nav_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            if (args.SelectedItem is NavigationViewItem item)
            {
                switch (item.Tag as string)
                {
                    case "Backup": ContentFrame.Navigate(new Pages.BackupPage()); break;
                    case "Restore": ContentFrame.Navigate(new Pages.RestorePage()); break;
                    case "Images": ContentFrame.Navigate(new Pages.ImagesPage()); break;
                    case "Utilities": ContentFrame.Navigate(new Pages.UtilitiesPage()); break;
                }
            }
        }

        // Back/Forward buttons removed while title bar changes are rolled back.
    }
}
