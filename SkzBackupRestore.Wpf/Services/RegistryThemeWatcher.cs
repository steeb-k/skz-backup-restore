using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;

namespace SkzBackupRestore.Wpf.Services
{
    /// <summary>
    /// Watches the Windows personalization registry key for theme changes and invokes a callback on the UI thread.
    /// </summary>
    internal sealed class RegistryThemeWatcher : IDisposable
    {
        private Thread? _thread;
        private volatile bool _stop;

        public void Start(Action onChanged)
        {
            if (_thread != null) return;
            _stop = false;
            _thread = new Thread(() => Run(onChanged))
            {
                IsBackground = true,
                Name = "RegistryThemeWatcher"
            };
            _thread.Start();
        }

        public void Stop()
        {
            _stop = true;
            // Closing the key will break RegNotifyChangeKeyValue
            if (_hKey != IntPtr.Zero)
            {
                RegCloseKey(_hKey);
                _hKey = IntPtr.Zero;
            }
            _thread?.Join(TimeSpan.FromSeconds(1));
            _thread = null;
        }

        private void Run(Action onChanged)
        {
            try
            {
                if (OpenPersonalizeKey(out _hKey) != 0 || _hKey == IntPtr.Zero)
                    return;

                while (!_stop)
                {
                    // Wait for any value change under the key
                    int rc = RegNotifyChangeKeyValue(_hKey, false, REG_NOTIFY_CHANGE_LAST_SET, IntPtr.Zero, false);
                    if (_stop) break;
                    // rc == 0 on success; schedule apply on UI thread
                    try
                    {
                        var dispatcher = System.Windows.Application.Current?.Dispatcher;
                        if (dispatcher != null)
                        {
                            dispatcher.InvokeAsync(() => onChanged());
                        }
                        else
                        {
                            onChanged();
                        }
                    }
                    catch { /* ignore */ }
                }
            }
            catch { /* ignore */ }
            finally
            {
                if (_hKey != IntPtr.Zero)
                {
                    RegCloseKey(_hKey);
                    _hKey = IntPtr.Zero;
                }
            }
        }

        private static int OpenPersonalizeKey(out IntPtr hKey)
        {
            return RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", 0, KEY_NOTIFY, out hKey);
        }

        private IntPtr _hKey = IntPtr.Zero;

        private static readonly IntPtr HKEY_CURRENT_USER = new IntPtr(unchecked((int)0x80000001));
        private const int KEY_NOTIFY = 0x0010;
        private const uint REG_NOTIFY_CHANGE_LAST_SET = 0x00000004;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegOpenKeyEx(IntPtr hKey, string subKey, int ulOptions, int samDesired, out IntPtr phkResult);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegNotifyChangeKeyValue(IntPtr hKey, bool bWatchSubtree, uint dwNotifyFilter, IntPtr hEvent, bool fAsynchronous);

        [DllImport("advapi32.dll")] 
        private static extern int RegCloseKey(IntPtr hKey);

        public void Dispose()
        {
            Stop();
        }
    }
}
