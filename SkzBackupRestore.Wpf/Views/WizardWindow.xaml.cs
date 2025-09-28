using System.Windows;
using System.Windows.Interop;
using System;
using System.Runtime.InteropServices;

namespace SkzBackupRestore.Wpf.Views
{
    public partial class WizardWindow : Window
    {
        public WizardWindow()
        {
            InitializeComponent();
            // Optional: layout rounding for crisp lines
            UseLayoutRounding = true;
            SnapsToDevicePixels = true;
            Loaded += WizardWindow_Loaded;
        }

        private void WizardWindow_Loaded(object sender, RoutedEventArgs e)
        {
            // Ensure window tightly sizes to content after template/layout is applied
            SizeToContent = SizeToContent.WidthAndHeight;

            // Defensive: clamp to device pixels and remove any stray padding
            var source = PresentationSource.FromVisual(this) as HwndSource;
            if (source != null && source.CompositionTarget != null)
            {
                var m = source.CompositionTarget.TransformToDevice;
                double dx = m.M11, dy = m.M22;
                Left = System.Math.Round(Left * dx) / dx;
                Top = System.Math.Round(Top * dy) / dy;
                Width = System.Math.Round(ActualWidth * dx) / dx;
                Height = System.Math.Round(ActualHeight * dy) / dy;

                // Apply dark title bar for standard framed window (Win10 1809+)
                TrySetDarkTitleBar(source.Handle, true);

                // Ensure the wizard window shows the same icon as the main application.
                // Previously we removed the title bar icon; that hides the app icon. Copy the
                // main window's Icon (if available) so wizard windows match the main app.
                try
                {
                    var mainIcon = System.Windows.Application.Current?.MainWindow?.Icon;
                    if (mainIcon != null)
                        this.Icon = mainIcon;
                }
                catch { }
            }
        }

        private static void TrySetDarkTitleBar(IntPtr hwnd, bool enabled)
        {
            if (hwnd == IntPtr.Zero) return;
            int useDark = enabled ? 1 : 0;
            // 20 works on Win10 1903+ / Win11
            const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
            // 19 works on Win10 1809
            const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;
            try
            {
                _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref useDark, sizeof(int));
                _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, ref useDark, sizeof(int));
            }
            catch
            {
                // ignore if unavailable
            }
        }

        [DllImport("dwmapi.dll", EntryPoint = "DwmSetWindowAttribute", PreserveSig = true)]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int dwAttribute, ref int pvAttribute, int cbAttribute);

        private static void TryHideTitleBarIcon(IntPtr hwnd)
        {
            if (hwnd == IntPtr.Zero) return;
            const int WM_SETICON = 0x0080;
            const int ICON_SMALL = 0;
            const int ICON_BIG = 1;
            const int GCLP_HICON = -14;
            const int GCLP_HICONSM = -34;
            const int GWL_EXSTYLE = -20;
            const int WS_EX_DLGMODALFRAME = 0x0001;
            const int SWP_NOSIZE = 0x0001;
            const int SWP_NOMOVE = 0x0002;
            const int SWP_NOZORDER = 0x0004;
            const int SWP_FRAMECHANGED = 0x0020;

            try
            {
                // Clear window icons
                SendMessage(hwnd, WM_SETICON, (IntPtr)ICON_SMALL, IntPtr.Zero);
                SendMessage(hwnd, WM_SETICON, (IntPtr)ICON_BIG, IntPtr.Zero);

                // Clear class icons
                if (Environment.Is64BitProcess)
                {
                    SetClassLongPtr(hwnd, GCLP_HICON, IntPtr.Zero);
                    SetClassLongPtr(hwnd, GCLP_HICONSM, IntPtr.Zero);
                }
                else
                {
                    SetClassLong(hwnd, GCLP_HICON, 0);
                    SetClassLong(hwnd, GCLP_HICONSM, 0);
                }

                // Add dialog modal frame style to hide icon reliably on standard framed windows
                IntPtr ex = Environment.Is64BitProcess ? GetWindowLongPtr(hwnd, GWL_EXSTYLE) : (IntPtr)GetWindowLong(hwnd, GWL_EXSTYLE);
                IntPtr newEx = (IntPtr)((ex.ToInt64()) | WS_EX_DLGMODALFRAME);
                if (Environment.Is64BitProcess)
                    SetWindowLongPtr(hwnd, GWL_EXSTYLE, newEx);
                else
                    SetWindowLong(hwnd, GWL_EXSTYLE, newEx.ToInt32());

                // Notify the window to recalc non-client area
                SetWindowPos(hwnd, IntPtr.Zero, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE | SWP_NOZORDER | SWP_FRAMECHANGED);
            }
            catch { }
        }

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

    // 64-bit safe Get/Set class long
    [DllImport("user32.dll", EntryPoint = "SetClassLongPtrW", SetLastError = true)]
    private static extern IntPtr SetClassLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);
    [DllImport("user32.dll", EntryPoint = "SetClassLongW", SetLastError = true)]
    private static extern int SetClassLong(IntPtr hWnd, int nIndex, int dwNewLong);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll", EntryPoint = "GetWindowLongW", SetLastError = true)]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);
    [DllImport("user32.dll", EntryPoint = "SetWindowLongPtrW", SetLastError = true)]
    private static extern IntPtr SetWindowLongPtr(IntPtr hWnd, int nIndex, IntPtr dwNewLong);
    [DllImport("user32.dll", EntryPoint = "SetWindowLongW", SetLastError = true)]
    private static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, int uFlags);
    }
}
