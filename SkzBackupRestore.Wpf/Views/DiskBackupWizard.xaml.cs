using System;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Forms;
using System.Management; // for WMI disk enumeration
using System.Runtime.InteropServices;
using ModernWpf.Controls;
using System.Windows.Media;
using System.Text.RegularExpressions;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Globalization;

namespace SkzBackupRestore.Wpf.Views
{
    public partial class DiskBackupWizard : System.Windows.Controls.UserControl
    {
        private CancellationTokenSource? _runCts;
        private Process? _currentProcess;
        private string? _runLogPath;
        private volatile bool _sawConsoleHandleIssue;
        private volatile bool _cancelRequested;
        private string? _originalWindowTitle;
        public ObservableCollection<PhysicalDiskItem> Disks { get; } = new();
        public IReadOnlyList<int> SelectedDiskNumbers => Disks.Where(d => d.IsSelected).Select(d => d.DiskNumber).ToList();
        public static readonly DependencyProperty ErrorMessageProperty =
            DependencyProperty.Register(nameof(ErrorMessage), typeof(string), typeof(DiskBackupWizard), new PropertyMetadata(string.Empty));
        public string ErrorMessage
        {
            get => (string)GetValue(ErrorMessageProperty);
            private set => SetValue(ErrorMessageProperty, value);
        }
        public bool PerformValidation => ValidateAfterCheckbox?.IsChecked == true;
        public static readonly DependencyProperty LogTextProperty =
            DependencyProperty.Register(nameof(LogText), typeof(string), typeof(DiskBackupWizard), new PropertyMetadata(string.Empty));
        public string LogText
        {
            get => (string)GetValue(LogTextProperty);
            private set => SetValue(LogTextProperty, value);
        }

        public static readonly DependencyProperty StatusTextProperty =
            DependencyProperty.Register(nameof(StatusText), typeof(string), typeof(DiskBackupWizard), new PropertyMetadata(string.Empty));
        public string StatusText
        {
            get => (string)GetValue(StatusTextProperty);
            private set => SetValue(StatusTextProperty, value);
        }

        public static readonly DependencyProperty SpeedTextProperty =
            DependencyProperty.Register(nameof(SpeedText), typeof(string), typeof(DiskBackupWizard), new PropertyMetadata(string.Empty));
        public string SpeedText
        {
            get => (string)GetValue(SpeedTextProperty);
            private set => SetValue(SpeedTextProperty, value);
        }

        public static readonly DependencyProperty EtaTextProperty =
            DependencyProperty.Register(nameof(EtaText), typeof(string), typeof(DiskBackupWizard), new PropertyMetadata(string.Empty));
        public string EtaText
        {
            get => (string)GetValue(EtaTextProperty);
            private set => SetValue(EtaTextProperty, value);
        }

        public DiskBackupWizard()
        {
            InitializeComponent();
            DataContext = this;
            // DisksList is bound in XAML (ItemsSource="{Binding Disks}")
            LoadPhysicalDisks();
            Loaded += DiskBackupWizard_Loaded;
        }

        private void DiskBackupWizard_Loaded(object sender, RoutedEventArgs e)
        {
            // Default validation checkbox from user settings
            try
            {
                ValidateAfterCheckbox.IsChecked = Services.SettingsService.Settings.AutoVerifyImages;
            }
            catch { /* ignore if settings not available */ }
            // Reflect IsSelected into ListBox selection for initial state (all unchecked by default)
            SyncListBoxSelectionFromModel();
            if (DisksList != null)
            {
                DisksList.SelectionChanged += DisksList_SelectionChanged;
                DisksList.PreviewKeyDown += DisksList_PreviewKeyDown;
                DisksList.MouseUp += DisksList_MouseUp;
            }
        }

        private void LoadPhysicalDisks()
        {
            Disks.Clear();
            ErrorMessage = string.Empty;
            bool any = false;
            try { any = FillFromWin32DiskDrive(); }
            catch (Exception ex)
            {
                ErrorMessage = $"Win32_DiskDrive failed: {ex.Message}";
            }
            if (!any)
            {
                try { any = FillFromMsftDisk(); }
                catch (Exception ex)
                {
                    ErrorMessage = string.IsNullOrEmpty(ErrorMessage)
                        ? $"MSFT_Disk failed: {ex.Message}"
                        : ErrorMessage + " | " + $"MSFT_Disk failed: {ex.Message}";
                }
            }
            if (!any)
            {
                try { any = FillFromPhysicalDrivesRaw(); }
                catch (Exception ex)
                {
                    ErrorMessage = string.IsNullOrEmpty(ErrorMessage)
                        ? $"Raw drive enumeration failed: {ex.Message}"
                        : ErrorMessage + " | " + $"Raw drive enumeration failed: {ex.Message}";
                }
            }
            if (any)
            {
                var sorted = Disks.OrderBy(d => d.DiskNumber).ToList();
                Disks.Clear();
                foreach (var d in sorted) Disks.Add(d);
                ErrorMessage = string.Empty;
                // Update ListBox selection to match model
                SyncListBoxSelectionFromModel();
            }
            else if (string.IsNullOrWhiteSpace(ErrorMessage))
            {
                ErrorMessage = "No disks returned by providers (Win32_DiskDrive, MSFT_Disk, Raw).";
            }
        }

        

        private void Refresh_Click(object sender, RoutedEventArgs e)
        {
            LoadPhysicalDisks();
        }

        private void SyncListBoxSelectionFromModel()
        {
            if (DisksList == null) return;
            DisksList.SelectionChanged -= DisksList_SelectionChanged;
            var sel = DisksList.SelectedItems;
            if (sel != null)
            {
                sel.Clear();
                foreach (var item in Disks.Where(d => d.IsSelected))
                {
                    sel.Add(item);
                }
            }
            DisksList.SelectionChanged += DisksList_SelectionChanged;
        }

        private void DisksList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            foreach (PhysicalDiskItem removed in e.RemovedItems)
                removed.IsSelected = false;
            foreach (PhysicalDiskItem added in e.AddedItems)
                added.IsSelected = true;
        }

        private void DisksList_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == System.Windows.Input.Key.Space && DisksList?.SelectedItem is PhysicalDiskItem item)
            {
                item.IsSelected = !item.IsSelected;
                var sel = DisksList.SelectedItems;
                if (sel != null)
                {
                    if (item.IsSelected)
                        sel.Add(item);
                    else
                        sel.Remove(item);
                }
                e.Handled = true;
            }
        }

        private void DisksList_MouseUp(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            // Ensure click anywhere in the row toggles selection (standard ListBox behavior is select-on-click)
            // Multi-select supported with Ctrl/Shift; IsSelected mirrors selection via SelectionChanged handler.
        }

        private bool FillFromWin32DiskDrive()
        {
            var scope = new ManagementScope(@"\\.\\root\\cimv2", BuildConnOptions());
            scope.Connect();
            using var diskSearcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Index, Model, Size FROM Win32_DiskDrive"));
            var result = diskSearcher.Get();
            int count = 0;
            foreach (ManagementObject mo in result)
            {
                uint index = 0; try { index = (uint)(mo["Index"] ?? 0u); } catch { }
                string model = (mo["Model"] as string) ?? "Unknown";
                long sizeBytes = 0;
                try
                {
                    var sizeObj = mo["Size"]; // often string or numeric
                    if (sizeObj != null)
                    {
                        if (sizeObj is ulong ul) sizeBytes = unchecked((long)ul);
                        else if (sizeObj is long l) sizeBytes = l;
                        else if (long.TryParse(sizeObj.ToString(), out var parsed)) sizeBytes = parsed;
                    }
                }
                catch { }

                Disks.Add(new PhysicalDiskItem
                {
                    DiskNumber = (int)index,
                    Model = model,
                    SizeBytes = sizeBytes,
                    DriveLetters = new List<string>(),
                });
                count++;
            }
            if (count == 0)
            {
                ErrorMessage = string.IsNullOrEmpty(ErrorMessage) ? "Win32_DiskDrive returned 0 results" : ErrorMessage;
            }
            return count > 0;
        }

        private bool FillFromMsftDisk()
        {
            // Windows 8+ storage API WMI provider
            var scope = new ManagementScope(@"\\.\\root\\Microsoft\\Windows\\Storage", BuildConnOptions());
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Number, FriendlyName, Size FROM MSFT_Disk"));
            var result = searcher.Get();
            int count = 0;
            foreach (ManagementObject mo in result)
            {
                int number = -1;
                try { number = Convert.ToInt32(mo["Number"]); } catch { }
                string model = (mo["FriendlyName"] as string) ?? "Disk";
                long sizeBytes = 0;
                try
                {
                    var sizeObj = mo["Size"]; if (sizeObj != null)
                    {
                        if (sizeObj is ulong ul) sizeBytes = unchecked((long)ul);
                        else if (sizeObj is long l) sizeBytes = l;
                        else if (long.TryParse(sizeObj.ToString(), out var parsed)) sizeBytes = parsed;
                    }
                }
                catch { }

                if (number >= 0)
                {
                    Disks.Add(new PhysicalDiskItem
                    {
                        DiskNumber = number,
                        Model = model,
                        SizeBytes = sizeBytes,
                        DriveLetters = new List<string>(),
                    });
                    count++;
                }
            }
            if (count == 0)
            {
                ErrorMessage = string.IsNullOrEmpty(ErrorMessage) ? "MSFT_Disk returned 0 results" : ErrorMessage;
            }
            return count > 0;
        }

        // WMI-free fallback: iterate PhysicalDrive0..PhysicalDrive63 using DeviceIoControl
        private bool FillFromPhysicalDrivesRaw()
        {
            int count = 0;
            for (int n = 0; n < 64; n++)
            {
                if (TryGetPhysicalDriveInfo(n, out string model, out long size))
                {
                    Disks.Add(new PhysicalDiskItem
                    {
                        DiskNumber = n,
                        Model = string.IsNullOrWhiteSpace(model) ? $"PhysicalDrive {n}" : model,
                        SizeBytes = size,
                    });
                    count++;
                }
            }
            if (count == 0)
            {
                ErrorMessage = string.IsNullOrEmpty(ErrorMessage) ? "Raw PhysicalDrive enumeration found 0 drives" : ErrorMessage;
            }
            return count > 0;
        }

        private static bool TryGetPhysicalDriveInfo(int number, out string model, out long sizeBytes)
        {
            model = string.Empty;
            sizeBytes = 0;
            string path = $"\\\\.\\PhysicalDrive{number}";
            using var handle = CreateFile(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            if (handle.IsInvalid)
                return false;

            // Query size
            var lengthInfo = new DISK_LONG_INFO();
            int bytesReturned = 0;
            if (DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, IntPtr.Zero, 0,
                ref lengthInfo, Marshal.SizeOf<DISK_LONG_INFO>(), ref bytesReturned, IntPtr.Zero))
            {
                sizeBytes = lengthInfo.Length;
            }

            // Query model via STORAGE_PROPERTY_QUERY
            var query = new STORAGE_PROPERTY_QUERY
            {
                PropertyId = STORAGE_PROPERTY_ID.StorageDeviceProperty,
                QueryType = STORAGE_QUERY_TYPE.PropertyStandardQuery,
                AdditionalParameters = 0
            };
            int bufSize = 1024;
            IntPtr outBuf = Marshal.AllocHGlobal(bufSize);
            try
            {
                bytesReturned = 0;
                // First, write query into input buffer region of outBuf
                Marshal.StructureToPtr(query, outBuf, false);
                if (DeviceIoControl(handle, IOCTL_STORAGE_QUERY_PROPERTY, outBuf, Marshal.SizeOf<STORAGE_PROPERTY_QUERY>(),
                    outBuf, bufSize, ref bytesReturned, IntPtr.Zero) && bytesReturned > 0)
                {
                    var desc = Marshal.PtrToStructure<STORAGE_DEVICE_DESCRIPTOR>(outBuf);
                    model = GetStringFromOffset(outBuf, desc.ProductIdOffset);
                    if (string.IsNullOrWhiteSpace(model))
                    {
                        // Try Vendor + Product as fallback
                        var vendor = GetStringFromOffset(outBuf, desc.VendorIdOffset);
                        var product = GetStringFromOffset(outBuf, desc.ProductIdOffset);
                        model = string.Join(" ", new[] { vendor, product }.Where(s => !string.IsNullOrWhiteSpace(s)));
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(outBuf);
            }

            return true;
        }

        private static string GetStringFromOffset(IntPtr basePtr, uint offset)
        {
            if (offset == 0 || basePtr == IntPtr.Zero) return string.Empty;
            try
            {
                IntPtr strPtr = IntPtr.Add(basePtr, (int)offset);
                // ANSI string terminated by '\0'
                var bytes = new List<byte>();
                byte b;
                int i = 0;
                while ((b = Marshal.ReadByte(strPtr, i)) != 0 && i < 512)
                {
                    bytes.Add(b);
                    i++;
                }
                return System.Text.Encoding.ASCII.GetString(bytes.ToArray()).Trim();
            }
            catch { return string.Empty; }
        }

        #region Native interop
        private const int FILE_SHARE_READ = 0x00000001;
        private const int FILE_SHARE_WRITE = 0x00000002;
        private const int FILE_SHARE_DELETE = 0x00000004;
        private const int OPEN_EXISTING = 3;
        private const int FILE_ATTRIBUTE_NORMAL = 0x00000080;
        private const int GENERIC_READ = unchecked((int)0x80000000);

        private const int IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C;
        private const int IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;

        [StructLayout(LayoutKind.Sequential)]
        private struct DISK_LONG_INFO
        {
            public long Length;
        }

        private enum STORAGE_PROPERTY_ID
        {
            StorageDeviceProperty = 0,
        }

        private enum STORAGE_QUERY_TYPE
        {
            PropertyStandardQuery = 0,
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STORAGE_PROPERTY_QUERY
        {
            public STORAGE_PROPERTY_ID PropertyId;
            public STORAGE_QUERY_TYPE QueryType;
            public uint AdditionalParameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STORAGE_DEVICE_DESCRIPTOR
        {
            public uint Version;
            public uint Size;
            public byte DeviceType;
            public byte DeviceTypeModifier;
            [MarshalAs(UnmanagedType.U1)] public bool RemovableMedia;
            [MarshalAs(UnmanagedType.U1)] public bool CommandQueueing;
            public uint VendorIdOffset;
            public uint ProductIdOffset;
            public uint ProductRevisionOffset;
            public uint SerialNumberOffset;
            public byte BusType;
            public uint RawPropertiesLength;
            // Followed by RawDeviceProperties[1]; we treat buffer generically
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFile(
            string lpFileName,
            int dwDesiredAccess,
            int dwShareMode,
            IntPtr lpSecurityAttributes,
            int dwCreationDisposition,
            int dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            Microsoft.Win32.SafeHandles.SafeFileHandle hDevice,
            int dwIoControlCode,
            IntPtr lpInBuffer,
            int nInBufferSize,
            ref DISK_LONG_INFO lpOutBuffer,
            int nOutBufferSize,
            ref int lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            Microsoft.Win32.SafeHandles.SafeFileHandle hDevice,
            int dwIoControlCode,
            IntPtr lpInBuffer,
            int nInBufferSize,
            IntPtr lpOutBuffer,
            int nOutBufferSize,
            ref int lpBytesReturned,
            IntPtr lpOverlapped);
        #endregion

        private static ConnectionOptions BuildConnOptions()
        {
            var opts = new ConnectionOptions
            {
                Impersonation = ImpersonationLevel.Impersonate,
                Authentication = AuthenticationLevel.PacketPrivacy,
                EnablePrivileges = true, // SeManageVolumePrivilege etc
                Timeout = TimeSpan.FromSeconds(3),
            };
            return opts;
        }

        private void BrowseFolder_Click(object sender, RoutedEventArgs e)
        {
            using var dlg = new FolderBrowserDialog
            {
                Description = "Select a backup folder",
                UseDescriptionForTitle = true,
                ShowNewFolderButton = true
            };
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                BackupLocationTextBox.Text = dlg.SelectedPath;
            }
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
            // If a run is in progress, cancel it; otherwise, close dialog
            if (RunPanel != null && RunPanel.Visibility == Visibility.Visible && _runCts != null)
            {
                TryCancelRun();
            }
            else
            {
                var window = System.Windows.Window.GetWindow(this);
                window?.Close();
            }
        }

        private void TryCancelRun()
        {
            if (_cancelRequested) return;
            _cancelRequested = true;
            try
            {
                _runCts?.Cancel();
                OnUI(() => StatusText = "Cancelling...");
                AppendFriendlyLog("Attempt to cancel operation");
                // Graceful wait: give the process a short window to exit before forcing termination
                Task.Run(async () =>
                {
                    const int timeoutMs = 7000; // configurable grace period
                    const int pollMs = 150;
                    int waited = 0;
                    try
                    {
                        while (waited < timeoutMs)
                        {
                            var p = _currentProcess;
                            if (p != null)
                            {
                                try { if (p.HasExited) return; } catch { return; }
                            }
                            await Task.Delay(pollMs).ConfigureAwait(false);
                            waited += pollMs;
                        }
                    }
                    catch { return; }
                    // Timeout elapsed; force kill the current process if still running
                    var toKill = _currentProcess;
                    if (toKill != null)
                    {
                        AppendFriendlyLog("Cancellation timeout elapsed. Forcing termination...");
                        try { if (!toKill.HasExited) toKill.Kill(entireProcessTree: true); } catch (Exception ex) { AppendFriendlyLog($"Failed to force terminate: {ex.Message}"); }
                    }
                });
            }
            catch { }
        }

        private async void Start_Click(object sender, RoutedEventArgs e)
        {
            // Basic validation for now; wiring to engine will come next
            var name = BackupNameTextBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(name))
            {
                var dlg = new ContentDialog
                {
                    Title = "Validation",
                    Content = "Please enter a backup name.",
                    CloseButtonText = "OK"
                };
                await dlg.ShowAsync();
                BackupNameTextBox.Focus();
                return;
            }
            var dest = BackupLocationTextBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(dest) || !Directory.Exists(dest))
            {
                var dlg = new ContentDialog
                {
                    Title = "Validation",
                    Content = "Please choose a valid backup location.",
                    CloseButtonText = "OK"
                };
                await dlg.ShowAsync();
                return;
            }
            var selected = Disks.Where(d => d.IsSelected).ToList();
            if (selected.Count == 0)
            {
                var dlg = new ContentDialog
                {
                    Title = "Validation",
                    Content = "Select at least one disk to back up.",
                    CloseButtonText = "OK"
                };
                await dlg.ShowAsync();
                return;
            }
            // Transition UI into run mode
            EnterRunMode();

            try
            {
                // Determine ImagingUtility path (win-arm64 preferred on ARM64 OS; otherwise win-x64)
                var (exePath, exeArch, exeNote) = ResolveImagingUtilityPath();
                if (!File.Exists(exePath))
                {
                    var dlg = new ContentDialog
                    {
                        Title = "ImagingUtility not found",
                        Content = $"Expected at: {exePath}\nEnsure ThirdParty binaries are copied (now included for Debug/Release).",
                        CloseButtonText = "OK"
                    };
                    await dlg.ShowAsync();
                    return;
                }

                string outDir = System.IO.Path.Combine(dest, name);
                bool doVerify = PerformValidation;
                bool quick = string.Equals(Services.SettingsService.Settings.VerificationMode, "Quick", StringComparison.OrdinalIgnoreCase);

                try { Directory.CreateDirectory(outDir); }
                catch (Exception dex)
                {
                    AppendLog($"Failed to create output directory '{outDir}': {dex.Message}");
                    await new ContentDialog { Title = "Output folder error", Content = dex.Message, CloseButtonText = "OK" }.ShowAsync();
                    return;
                }

                _runCts = new CancellationTokenSource();
                var ct = _runCts.Token;

                // Header info
                var header = new List<string>();
                header.Add($"ImagingUtility: {exePath}");
                if (!string.IsNullOrEmpty(exeArch)) header.Add($"Architecture chosen: {exeArch}");
                if (!string.IsNullOrEmpty(exeNote)) header.Add($"Note: {exeNote}");
                header.Add("");
                AppendLog(string.Join("\r\n", header));

                // Initialize per-run log file next to output directory
                try
                {
                    _runLogPath = System.IO.Path.Combine(outDir, $"backup_{DateTime.Now:yyyyMMdd_HHmmss}.log");
                    File.AppendAllText(_runLogPath, $"=== Backup Session {DateTime.Now:O} ===\r\n");
                }
                catch { _runLogPath = null; }

                bool allOk = true;
                foreach (var disk in selected)
                {
                    if (ct.IsCancellationRequested) { allOk = false; break; }
                    OnUI(() => { Progress.IsIndeterminate = true; Progress.Value = 0; StatusText = $"Backing up disk {disk.DiskNumber}..."; SpeedText = string.Empty; EtaText = string.Empty; UpdateWindowTitlePercent(null, prefix:$"Disk {disk.DiskNumber} backup"); });
                    AppendFriendlyLog($"Starting backup of Disk {disk.DiskNumber} to '{outDir}' (VSS enabled)...");
                    AppendLog($"Backing up Disk {disk.DiskNumber} to '{outDir}' (with VSS)...");
                    string backupArgs = $"backup-disk --disk {disk.DiskNumber} --out-dir \"{outDir}\" --use-vss";
                    AppendFriendlyLog($"> {exePath} {backupArgs}");
                    _sawConsoleHandleIssue = false;
                    (bool ok, int exitCode) res;
                    if (ExternalConsoleCheckbox.IsChecked == true)
                    {
                        AppendFriendlyLog("External console requested by user.");
                        res = await RunInExternalConsoleAsync(exePath, backupArgs, ct);
                    }
                    else
                    {
                        res = await RunProcessWithProgressAsync(exePath, backupArgs, ct, phase: "backup");
                    }
                    var (ok, exitCode) = res;
                    if (!ok && _sawConsoleHandleIssue)
                    {
                        AppendFriendlyLog("Detected console handle issue; retrying in an external console window (progress will not be captured in-app)...");
                        var (ok2, exit2) = await RunInExternalConsoleAsync(exePath, backupArgs, ct);
                        ok = ok2; exitCode = exit2;
                    }
                    if (!ok)
                    {
                        AppendFriendlyLog($"Backup failed for Disk {disk.DiskNumber} (exit code {exitCode}).");
                        allOk = false; break;
                    }
                    AppendFriendlyLog($"Backup completed for Disk {disk.DiskNumber}.");

                    if (doVerify)
                    {
                        if (ct.IsCancellationRequested) { allOk = false; break; }
                        OnUI(() => { Progress.IsIndeterminate = true; Progress.Value = 0; StatusText = $"Verifying set in '{outDir}'{(quick ? " (quick)" : string.Empty)}..."; SpeedText = string.Empty; EtaText = string.Empty; UpdateWindowTitlePercent(null, prefix:"Verify set"); });
                        AppendFriendlyLog($"Starting verification for '{outDir}'{(quick ? " (quick)" : string.Empty)}...");
                        AppendLog($"Verifying backup set in '{outDir}'{(quick ? " (quick)" : string.Empty)}...");
                        string verifyArgs = $"verify-set --set-dir \"{outDir}\"" + (quick ? " --quick" : string.Empty);
                        AppendFriendlyLog($"> {exePath} {verifyArgs}");
                        _sawConsoleHandleIssue = false;
                        (bool okv, int exitv) vres;
                        if (ExternalConsoleCheckbox.IsChecked == true)
                        {
                            AppendFriendlyLog("External console requested by user (verify).");
                            vres = await RunInExternalConsoleAsync(exePath, verifyArgs, ct);
                        }
                        else
                        {
                            vres = await RunProcessWithProgressAsync(exePath, verifyArgs, ct, phase: "verify");
                        }
                        var (vok, vexit) = vres;
                        if (!vok && _sawConsoleHandleIssue)
                        {
                            AppendFriendlyLog("Detected console handle issue; retrying verification in an external console window...");
                            var (ok2, exit2) = await RunInExternalConsoleAsync(exePath, verifyArgs, ct);
                            vok = ok2; vexit = exit2;
                        }
                        if (!vok)
                        {
                            AppendFriendlyLog($"Verification failed (exit code {vexit}).");
                            allOk = false; break;
                        }
                        AppendFriendlyLog("Verification completed.");
                    }
                    AppendLog("");
                }

                if (allOk && !ct.IsCancellationRequested) { OnUI(() => StatusText = "All operations completed successfully."); AppendFriendlyLog("All operations completed successfully."); }
                else if (ct.IsCancellationRequested) { OnUI(() => StatusText = "Operation cancelled."); AppendFriendlyLog("Operation cancelled."); }
            }
            catch (Exception ex)
            {
                AppendFriendlyLog($"Exception: {ex.Message}");
                await new ContentDialog { Title = "Unexpected error", Content = ex.Message, CloseButtonText = "OK" }.ShowAsync();
            }
            finally
            {
                _cancelRequested = false;
                // Mark completion: change Cancel to Close
                if (FindParentWindow() is System.Windows.Window wnd)
                {
                    try { if (!string.IsNullOrEmpty(_originalWindowTitle)) wnd.Title = _originalWindowTitle; } catch { }
                    if (TryFindChild<System.Windows.Controls.Button>(this, "StartButton") is System.Windows.Controls.Button startBtn)
                    {
                        startBtn.IsEnabled = false;
                    }
                    if (TryFindChild<System.Windows.Controls.Button>(this, "CancelButton") is System.Windows.Controls.Button cancelBtn)
                    {
                        cancelBtn.Content = "Close";
                        cancelBtn.IsCancel = false;
                        cancelBtn.Click -= Cancel_Click;
                        cancelBtn.Click += (s, _) => { try { wnd.DialogResult = true; } catch { } wnd.Close(); };
                    }
                }
            }
        }

        private void EnterRunMode()
        {
            // Fix window width (keep it static)
            if (FindParentWindow() is System.Windows.Window wnd)
            {
                _originalWindowTitle = wnd.Title;
                wnd.MinWidth = wnd.ActualWidth;
                wnd.MaxWidth = wnd.ActualWidth;
            }
            // Hide input panels
            NamePanel.Visibility = Visibility.Collapsed;
            DisksPanel.Visibility = Visibility.Collapsed;
            RefreshPanel.Visibility = Visibility.Collapsed;
            LocationPanel.Visibility = Visibility.Collapsed;
            // Show run panel
            RunPanel.Visibility = Visibility.Visible;
            // Disable validation toggle but keep it visible
            ValidateAfterCheckbox.IsEnabled = false;
            // Disable external console toggle once a process is about to start
            if (ExternalConsoleCheckbox != null)
            {
                ExternalConsoleCheckbox.IsEnabled = false;
            }
            // Hide Start button during run
            if (StartButton != null)
            {
                StartButton.Visibility = Visibility.Collapsed;
            }
        }

        private static T? TryFindChild<T>(DependencyObject parent, string? name) where T : FrameworkElement
        {
            int count = VisualTreeHelper.GetChildrenCount(parent);
            for (int i = 0; i < count; i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is T fe && (name == null || fe.Name == name))
                    return fe;
                var result = TryFindChild<T>(child, name);
                if (result != null) return result;
            }
            return null;
        }

        private System.Windows.Window? FindParentWindow() => System.Windows.Window.GetWindow(this);

    private async Task<(bool ok, int exitCode)> RunProcessWithProgressAsync(string exePath, string arguments, CancellationToken ct, string phase)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arguments,
                            // Don't reset here; leave the final reported percentage visible (typically 100%)
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding = System.Text.Encoding.UTF8,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(exePath) ?? Environment.CurrentDirectory
            };
            // Hint for ImagingUtility to avoid Console.WindowWidth when output is redirected
            try { psi.EnvironmentVariables["IMAGINGUTILITY_PLAIN"] = "1"; } catch { }

            using var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _currentProcess = proc;
            var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            proc.Exited += (s, e) =>
            {
                try { tcs.TrySetResult(proc.ExitCode); } catch { }
            };

            try
            {
                if (!proc.Start())
                {
                    AppendFriendlyLog("Failed to start process.");
                    return (false, -1);
                }
                // Small delay to let redirected streams become available, then attach readers with retries
                Task readOut = Task.CompletedTask;
                Task readErr = Task.CompletedTask;
                bool attached = false;
                await Task.Delay(30).ConfigureAwait(true);
                for (int attempt = 0; attempt < 20; attempt++)
                {
                    try
                    {
                        // Accessing StandardOutput/StandardError too early can throw; retry briefly
                        readOut = ReadStreamLinesAsync(proc.StandardOutput, ct, phase);
                        readErr = ReadStreamLinesAsync(proc.StandardError, ct, phase, logAlso: true);
                        attached = true;
                        break;
                    }
                    catch (InvalidOperationException ioe)
                    {
                        // Diagnostic only
                        AppendLog($"I/O redirection not ready (attempt {attempt + 1}): {ioe.Message}");
                        if (proc.HasExited)
                        {
                            AppendFriendlyLog("Process exited before streams were ready.");
                            break;
                        }
                        await Task.Delay(75).ConfigureAwait(true);
                    }
                }
                if (!attached)
                {
                    AppendFriendlyLog("Proceeding without live output capture; progress will be limited to phase start/end.");
                }

                // Do not force-kill on token cancellation here; TryCancelRun handles grace + kill
                using (ct.Register(() => { /* cancellation observed by readers */ }))
                {
                    // Wait for process exit and then drain readers if we attached
                    int code = await tcs.Task.ConfigureAwait(true);
                    try
                    {
                        if (readOut != null && readOut != Task.CompletedTask) await readOut.ConfigureAwait(true);
                        if (readErr != null && readErr != Task.CompletedTask) await readErr.ConfigureAwait(true);
                    }
                    catch { }
                    // Do not reset the progress bar here; keep the last reported value visible.
                    _currentProcess = null; // clear after exit
                    return (code == 0, code);
                }
            }
            finally
            {
                // best-effort clear; already cleared above after exit
                _currentProcess = null;
            }
        }

    private async Task ReadStreamLinesAsync(StreamReader reader, CancellationToken ct, string phase, bool logAlso = false)
        {
            var sb = new System.Text.StringBuilder();
            char[] buf = new char[1024];
            while (!ct.IsCancellationRequested)
            {
                int n;
                try { n = await reader.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false); }
                catch { break; }
                if (n == 0) break; // EOF
                for (int i = 0; i < n; i++)
                {
                    char ch = buf[i];
                    if (ch == '\r' || ch == '\n')
                    {
                        if (sb.Length > 0)
                        {
                            var line = sb.ToString();
                            sb.Clear();
                            if (logAlso) AppendLog(line);
                            ParseAndReportProgress(line, phase);
                        }
                    }
                    else
                    {
                        sb.Append(ch);
                    }
                }
            }
            if (sb.Length > 0)
            {
                var line = sb.ToString();
                if (logAlso) AppendLog(line);
                ParseAndReportProgress(line, phase);
            }
        }

        private Task<(bool ok, int exitCode)> RunInExternalConsoleAsync(string exePath, string arguments, CancellationToken ct)
        {
            return Task.Run<(bool ok, int exitCode)>(() =>
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = exePath,
                        Arguments = arguments,
                        UseShellExecute = true,
                        CreateNoWindow = false,
                        WorkingDirectory = Path.GetDirectoryName(exePath) ?? Environment.CurrentDirectory,
                        WindowStyle = ProcessWindowStyle.Normal
                    };
                    var p = Process.Start(psi);
                    _currentProcess = p; // track for cancel
                    if (p == null) { _currentProcess = null; return (false, -1); }
                    // Best-effort cancel: we cannot kill external console easily here; user can close it.
                    p.WaitForExit();
                    var code = p.ExitCode;
                    _currentProcess = null; // clear after exit
                    return (code == 0, code);
                }
                catch (Exception ex)
                {
                    AppendLog($"External console launch failed: {ex.Message}");
                    return (false, -1);
                }
            }, ct);
        }

    private void ParseAndReportProgress(string line, string phase)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            // Do not append stdout lines to on-screen log anymore; only stderr flows to AppendLog via logAlso.

            // Detect common console handle errors produced when no console is attached
            if (line.Contains("The handle is invalid.", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("ConsolePal", StringComparison.OrdinalIgnoreCase))
            {
                _sawConsoleHandleIssue = true;
            }

            // Try to extract a percentage like "27.9%" or "42%" (with optional spaces before %)
            var m = Regex.Match(line, @"(?<!\d)(\d{1,3}(?:\.\d+)?)\s*%", RegexOptions.CultureInvariant);
            if (m.Success)
            {
                if (double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out double dpct))
                {
                    if (dpct >= 0 && dpct <= 100)
                    {
                        OnUI(() =>
                        {
                            Progress.IsIndeterminate = false;
                            Progress.Maximum = 100;
                            Progress.Value = dpct;
                            UpdateWindowTitlePercent(dpct);
                        });
                    }
                }
            }

            // Extract speed and ETA if present in the plain progress line
            var speedMatch = Regex.Match(line, @"(?<speed>\d+(?:\.\d+)?\s*(?:B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)/s)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (speedMatch.Success)
            {
                var speed = speedMatch.Groups["speed"].Value.Trim();
                OnUI(() => SpeedText = speed);
            }
            var etaMatch = Regex.Match(line, @"ETA\s*(?<eta>(?:~?\s*)?(?:\d\d?:)?\d\d?:\d\d(?:\.\d{1,3})?|~?\s*\d+\s*[smh])", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (etaMatch.Success)
            {
                var eta = etaMatch.Groups["eta"].Value.Trim().Replace("~ ", "~");
                OnUI(() => EtaText = $"ETA {eta}");
            }

            // Lightweight status hints based on known phases
            if (phase == "backup")
            {
                if (line.IndexOf("snapshot", StringComparison.OrdinalIgnoreCase) >= 0 && line.IndexOf("creating", StringComparison.OrdinalIgnoreCase) >= 0)
                    OnUI(() => StatusText = "Creating VSS snapshot...");
                else if (line.IndexOf("scanning", StringComparison.OrdinalIgnoreCase) >= 0)
                    OnUI(() => StatusText = "Scanning used sectors...");
                else if (line.IndexOf("writing", StringComparison.OrdinalIgnoreCase) >= 0 || line.IndexOf("compress", StringComparison.OrdinalIgnoreCase) >= 0)
                    OnUI(() => StatusText = "Writing image...");
            }
            else if (phase == "verify")
            {
                if (line.IndexOf("verify", StringComparison.OrdinalIgnoreCase) >= 0)
                    OnUI(() => StatusText = "Verifying images...");
            }
        }

        private void AppendLog(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            // Diagnostic log only (stderr or internal events); do not update on-screen friendly log here
            // Also append to a file for crash-proof diagnostics
            if (!string.IsNullOrEmpty(_runLogPath))
            {
                try { File.AppendAllText(_runLogPath, text + Environment.NewLine); } catch { }
            }
        }

        private void AppendFriendlyLog(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            OnUI(() =>
            {
                if (string.IsNullOrEmpty(LogText))
                    LogText = text;
                else
                    LogText += "\r\n" + text;
            });
            // Mirror to file as well for completeness
            if (!string.IsNullOrEmpty(_runLogPath))
            {
                try { File.AppendAllText(_runLogPath, text + Environment.NewLine); } catch { }
            }
        }

        private void OnUI(Action action)
        {
            var disp = Dispatcher;
            if (disp == null) { try { action(); } catch { } return; }
            if (disp.CheckAccess())
            {
                action();
            }
            else
            {
                try { disp.BeginInvoke(action); } catch { }
            }
        }

        private static (string exePath, string arch, string note) ResolveImagingUtilityPath()
        {
            string baseDir = AppContext.BaseDirectory;
            string armExe = System.IO.Path.Combine(baseDir, "ThirdParty", "ImagingUtility", "win-arm64", "ImagingUtility.exe");
            string x64Exe = System.IO.Path.Combine(baseDir, "ThirdParty", "ImagingUtility", "win-x64", "ImagingUtility.exe");

            string arch = string.Empty;
            string note = string.Empty;
            try
            {
                var osArch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture;
                if (osArch == System.Runtime.InteropServices.Architecture.Arm64 && File.Exists(armExe))
                {
                    arch = "ARM64";
                    return (armExe, arch, note);
                }
            }
            catch { }

            if (File.Exists(x64Exe))
            {
                arch = "x64";
                return (x64Exe, arch, note);
            }
            if (File.Exists(armExe))
            {
                arch = "ARM64";
                note = "x64 executable not found; using ARM64.";
                return (armExe, arch, note);
            }

            // Fallback to x64 path even if missing, so the log shows the intended path
            arch = "x64";
            note = "Executable not found in output folder; ensure Release build copies ThirdParty binaries.";
            return (x64Exe, arch, note);
        }

        private static string QuotePwsh(string path)
        {
            if (path == null) return "''";
            // PowerShell single-quote with '' escaping inside
            return "'" + path.Replace("'", "''") + "'";
        }

        private void UpdateWindowTitlePercent(double? percent, string? prefix = null)
        {
            try
            {
                var wnd = FindParentWindow();
                if (wnd == null) return;
                if (percent == null)
                {
                    // Reset to base title with optional prefix
                    if (!string.IsNullOrEmpty(_originalWindowTitle))
                        wnd.Title = string.IsNullOrEmpty(prefix) ? _originalWindowTitle : $"{_originalWindowTitle} — {prefix}";
                    return;
                }
                double p = Math.Max(0, Math.Min(100, percent.Value));
                string ptext = p % 1 == 0 ? ((int)p).ToString(CultureInfo.InvariantCulture) : p.ToString("0.0", CultureInfo.InvariantCulture);
                string baseTitle = !string.IsNullOrEmpty(_originalWindowTitle) ? _originalWindowTitle : wnd.Title;
                string left = string.IsNullOrEmpty(prefix) ? baseTitle : $"{baseTitle} — {prefix}";
                wnd.Title = $"{left} ({ptext}%)";
            }
            catch { }
        }
    }

    public class PhysicalDiskItem : INotifyPropertyChanged
    {
        private bool _isSelected;
        public int DiskNumber { get; set; }
        public string Model { get; set; } = string.Empty;
        public long SizeBytes { get; set; }
        public List<string> DriveLetters { get; set; } = new();
        public bool IsSelected
        {
            get => _isSelected; set { _isSelected = value; OnPropertyChanged(); }
        }
        public string Display => $"Disk {DiskNumber}: {Model}";
        public string DisplaySize => SizeBytes > 0 ? FormatBytes(SizeBytes) : string.Empty;
        public string LettersDisplay => DriveLetters.Count > 0 ? string.Join(", ", DriveLetters) : string.Empty;

        private static string FormatBytes(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB", "PB" };
            double value = bytes;
            int unit = 0;
            while (value >= 1024 && unit < units.Length - 1)
            {
                value /= 1024;
                unit++;
            }
            return string.Format(System.Globalization.CultureInfo.CurrentCulture, "{0:0.##} {1}", value, units[unit]);
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
