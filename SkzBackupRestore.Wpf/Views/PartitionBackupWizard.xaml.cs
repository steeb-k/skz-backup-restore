using System;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Forms;
using System.Management;
using System.Globalization;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Windows.Media;

namespace SkzBackupRestore.Wpf.Views
{
    public partial class PartitionBackupWizard : System.Windows.Controls.UserControl
    {
        private CancellationTokenSource? _runCts;
        private Process? _currentProcess;
        private string? _runLogPath;
        private volatile bool _sawConsoleHandleIssue;
        private volatile bool _cancelRequested;
        private string? _originalWindowTitle;

        public ObservableCollection<PartitionItem> Partitions { get; } = new();

        // UI-bound properties for run-time status/logs
        public static readonly DependencyProperty LogTextProperty =
            DependencyProperty.Register(nameof(LogText), typeof(string), typeof(PartitionBackupWizard), new PropertyMetadata(string.Empty));
        public string LogText { get => (string)GetValue(LogTextProperty); private set => SetValue(LogTextProperty, value); }

        public static readonly DependencyProperty StatusTextProperty =
            DependencyProperty.Register(nameof(StatusText), typeof(string), typeof(PartitionBackupWizard), new PropertyMetadata(string.Empty));
        public string StatusText { get => (string)GetValue(StatusTextProperty); private set => SetValue(StatusTextProperty, value); }

        public static readonly DependencyProperty SpeedTextProperty =
            DependencyProperty.Register(nameof(SpeedText), typeof(string), typeof(PartitionBackupWizard), new PropertyMetadata(string.Empty));
        public string SpeedText { get => (string)GetValue(SpeedTextProperty); private set => SetValue(SpeedTextProperty, value); }

        public static readonly DependencyProperty EtaTextProperty =
            DependencyProperty.Register(nameof(EtaText), typeof(string), typeof(PartitionBackupWizard), new PropertyMetadata(string.Empty));
        public string EtaText { get => (string)GetValue(EtaTextProperty); private set => SetValue(EtaTextProperty, value); }
        public PartitionBackupWizard()
        {
            InitializeComponent();
            DataContext = this;
            Loaded += PartitionBackupWizard_Loaded;
        }

        private void PartitionBackupWizard_Loaded(object sender, RoutedEventArgs e)
        {
            LoadPartitions();
            // Bind grouped view
            var view = System.Windows.Data.CollectionViewSource.GetDefaultView(Partitions);
            view.GroupDescriptions.Clear();
            view.GroupDescriptions.Add(new System.Windows.Data.PropertyGroupDescription(nameof(PartitionItem.DiskGroup)));
            PartitionsList.ItemsSource = view;
            // Default validation checkbox from user settings (same behavior as DiskBackupWizard)
            try
            {
                ValidateAfterCheckbox.IsChecked = Services.SettingsService.Settings.AutoVerifyImages;
            }
            catch { }
        }

        private void LoadPartitions()
        {
            Partitions.Clear();
            try
            {
                // Use MSFT_Disk + MSFT_Partition to get all partitions with disk grouping.
                var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Storage", new ConnectionOptions { EnablePrivileges = true });
                scope.Connect();

                // Load disks first for group names
                var diskNames = new Dictionary<uint, string>();
                using (var diskSearcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Number, FriendlyName FROM MSFT_Disk")))
                {
                    foreach (ManagementObject d in diskSearcher.Get())
                    {
                        try
                        {
                            uint num = Convert.ToUInt32(d["Number"], CultureInfo.InvariantCulture);
                            string name = (d["FriendlyName"] as string) ?? $"Disk {num}";
                            diskNames[num] = name;
                        }
                        catch { }
                    }
                }

                using var partSearcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT DiskNumber, PartitionNumber, DriveLetter, Size, GptType, MbrType FROM MSFT_Partition"));
                foreach (ManagementObject p in partSearcher.Get())
                {
                    try
                    {
                        int diskNum = Convert.ToInt32(p["DiskNumber"], CultureInfo.InvariantCulture);
                        int partNum = Convert.ToInt32(p["PartitionNumber"], CultureInfo.InvariantCulture);
                        string? gptType = null; try { gptType = p["GptType"]?.ToString(); } catch { }
                        uint? mbrType = null; try { var mt = p["MbrType"]; if (mt != null) mbrType = Convert.ToUInt32(mt, CultureInfo.InvariantCulture); } catch { }
                        string? driveLetter = null;
                        try
                        {
                            var dl = p["DriveLetter"]; // can be null or char
                            if (dl is char c && char.IsLetter(c)) driveLetter = c + ":";
                            else if (dl != null)
                            {
                                var s = dl.ToString();
                                if (!string.IsNullOrEmpty(s) && char.IsLetter(s[0])) driveLetter = s[0] + ":";
                            }
                        }
                        catch { }
                        long size = 0; try { size = Convert.ToInt64(p["Size"], CultureInfo.InvariantCulture); } catch { }
                        string group = diskNames.TryGetValue((uint)diskNum, out var gname) ? $"Disk {diskNum}: {gname}" : $"Disk {diskNum}";

                        // Hide GPT MSR partitions from the UI list
                        if (!string.IsNullOrEmpty(gptType) && gptType.IndexOf("E3C9E316-0B5C-4DB8-817D-F92DF00215AE", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            // Skip MSR (Microsoft Reserved) — it has no filesystem/volume and is handled by full disk backups
                            continue;
                        }

                        Partitions.Add(new PartitionItem
                        {
                            DiskNumber = diskNum,
                            PartitionNumber = partNum,
                            DriveLetter = driveLetter,
                            SizeBytes = size,
                            DiskGroup = group,
                            GptType = gptType,
                            MbrType = mbrType,
                        });
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine("Partition enumeration failed: " + ex.Message);
            }
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

        private async void Start_Click(object sender, RoutedEventArgs e)
        {
            var dest = BackupLocationTextBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(dest) || !Directory.Exists(dest))
            {
                await new ModernWpf.Controls.ContentDialog { Title = "Validation", Content = "Please choose a valid backup location.", CloseButtonText = "OK" }.ShowAsync();
                return;
            }
            var selected = Partitions.Where(p => p.IsSelected).ToList();
            if (selected.Count == 0)
            {
                await new ModernWpf.Controls.ContentDialog { Title = "Validation", Content = "Select at least one partition to back up.", CloseButtonText = "OK" }.ShowAsync();
                return;
            }

            bool doVerify = ValidateAfterCheckbox.IsChecked == true;
            bool quick = false;
            try { quick = string.Equals(Services.SettingsService.Settings.VerificationMode, "Quick", StringComparison.OrdinalIgnoreCase); } catch { }

            EnterRunMode();

            try
            {
                var (exePath, _, _) = ResolveImagingUtilityPath();
                if (!File.Exists(exePath))
                {
                    await new ModernWpf.Controls.ContentDialog { Title = "ImagingUtility not found", Content = $"Expected at: {exePath}\nEnsure ThirdParty binaries are copied.", CloseButtonText = "OK" }.ShowAsync();
                    return;
                }

                string outDir = System.IO.Path.Combine(dest, BackupNameTextBox.Text?.Trim() ?? "partition-backup");
                try { Directory.CreateDirectory(outDir); }
                catch (Exception dex) { AppendLog($"Failed to create output directory '{outDir}': {dex.Message}"); await new ModernWpf.Controls.ContentDialog { Title = "Output folder error", Content = dex.Message, CloseButtonText = "OK" }.ShowAsync(); return; }

                _runCts = new CancellationTokenSource();
                var ct = _runCts.Token;

                // Initialize per-run log
                try { _runLogPath = System.IO.Path.Combine(outDir, $"partition_backup_{DateTime.Now:yyyyMMdd_HHmmss}.log"); File.AppendAllText(_runLogPath, $"=== Partition Backup Session {DateTime.Now:O} ===\r\n"); } catch { _runLogPath = null; }
                AppendLog($"ImagingUtility: {exePath}");

                bool allOk = true;
                foreach (var part in selected)
                {
                    if (ct.IsCancellationRequested) { allOk = false; break; }

                    var info = await ResolvePartitionInfoAsync(part);
                    if (string.IsNullOrEmpty(info.devicePath))
                    {
                        // Likely a raw/system partition without a mounted volume (e.g., MSR on GPT, MSR/EFI/Recovery without letter)
                        string hint = string.Empty;
                        if (part.IsLikelyMsr)
                            hint = " (Microsoft Reserved partition has no filesystem and cannot be imaged via volume API)";
                        else if (part.IsLikelyEfi)
                            hint = " (EFI System Partition typically FAT32; only raw disk/offset imaging is supported via full disk backup)";
                        else if (part.IsLikelyRecovery)
                            hint = " (Windows Recovery/hidden partition; may not have a volume path)";

                        AppendFriendlyLog($"Could not resolve device path for partition {part.PartitionNumber} on disk {part.DiskNumber}{hint}. Skipping this partition.");
                        continue;
                    }

                    // Choose VSS for NTFS volumes per requirement
                    bool useVss = info.isNtfs;
                    string deviceArg = info.devicePath;
                    if (useVss)
                    {
                        // VSS expects a volume path (C:\ or \\?\Volume{...}\\)
                        if (!deviceArg.EndsWith("\\")) deviceArg += "\\";
                    }
                    else
                    {
                        // Raw device open expects no trailing backslash for Volume GUID, or \\.: for drive letters
                        if (!string.IsNullOrEmpty(deviceArg) && deviceArg.StartsWith("\\\\?\\Volume", StringComparison.OrdinalIgnoreCase))
                        {
                            deviceArg = deviceArg.TrimEnd('\\');
                        }
                        else if (!string.IsNullOrEmpty(part.DriveLetter))
                        {
                            // Map to \\.\D:
                            var dl = part.DriveLetter.EndsWith(":") ? part.DriveLetter : (part.DriveLetter + ":");
                            deviceArg = "\\\\.\\" + dl;
                        }
                    }

                    string imageName = !string.IsNullOrEmpty(info.volumeGuid) ? info.volumeGuid : SanitizeForFilename(info.devicePath);
                    string outFile = Path.Combine(outDir, $"{imageName}.skzimg");

                    OnUI(() => { StatusText = $"Backing up partition {part.PartitionNumber}..."; SpeedText = string.Empty; EtaText = string.Empty; });
                    AppendFriendlyLog($"Starting backup of partition {part.PartitionNumber} (device {info.devicePath}) -> {outFile}");

                    string imgArgs = $"image --device {QuoteArg(deviceArg)} --out {QuoteArg(outFile)}" + (useVss ? " --use-vss" : string.Empty);
                    AppendFriendlyLog($"> {exePath} {imgArgs}");
                    _sawConsoleHandleIssue = false;
                    (bool ok, int exitCode) res;
                    if (ExternalConsoleCheckbox.IsChecked == true)
                    {
                        AppendFriendlyLog("External console requested by user.");
                        res = await RunInExternalConsoleAsync(exePath, imgArgs, ct);
                    }
                    else
                    {
                        res = await RunProcessWithProgressAsync(exePath, imgArgs, ct, phase: "backup");
                    }
                    var (ok, exit) = res;
                    if (!ok && _sawConsoleHandleIssue)
                    {
                        AppendFriendlyLog("Detected console handle issue; retrying in an external console window (progress will not be captured in-app)...");
                        var (ok2, exit2) = await RunInExternalConsoleAsync(exePath, imgArgs, ct);
                        ok = ok2; exit = exit2;
                    }
                    if (!ok)
                    {
                        AppendFriendlyLog($"Backup failed for partition {part.PartitionNumber} (exit code {exit}).");
                        allOk = false; break;
                    }
                    AppendFriendlyLog($"Backup completed for partition {part.PartitionNumber}.");

                    if (doVerify)
                    {
                        if (ct.IsCancellationRequested) { allOk = false; break; }
                        OnUI(() => { StatusText = $"Verifying image {Path.GetFileName(outFile)}..."; SpeedText = string.Empty; EtaText = string.Empty; });
                        AppendFriendlyLog($"Starting verification for '{outFile}'{(quick ? " (quick)" : string.Empty)}...");
                        string verifyArgs = $"verify --in {QuoteArg(outFile)}" + (quick ? " --quick" : string.Empty);
                        AppendFriendlyLog($"> {exePath} {verifyArgs}");
                        _sawConsoleHandleIssue = false;
                        (bool vok, int vexit) vres;
                        if (ExternalConsoleCheckbox.IsChecked == true)
                        {
                            AppendFriendlyLog("External console requested by user (verify).");
                            vres = await RunInExternalConsoleAsync(exePath, verifyArgs, ct);
                        }
                        else
                        {
                            vres = await RunProcessWithProgressAsync(exePath, verifyArgs, ct, phase: "verify");
                        }
                        var (vok, vcode) = vres;
                        if (!vok && _sawConsoleHandleIssue)
                        {
                            AppendFriendlyLog("Detected console handle issue; retrying verification in an external console window...");
                            var (ok2, exit2) = await RunInExternalConsoleAsync(exePath, verifyArgs, ct);
                            vok = ok2; vcode = exit2;
                        }
                        if (!vok)
                        {
                            AppendFriendlyLog($"Verification failed (exit code {vcode}).");
                            allOk = false; break;
                        }
                        AppendFriendlyLog("Verification completed.");
                    }
                }

                if (allOk && !ct.IsCancellationRequested) { OnUI(() => StatusText = "All operations completed successfully."); AppendFriendlyLog("All operations completed successfully."); }
                else if (ct.IsCancellationRequested) { OnUI(() => StatusText = "Operation cancelled."); AppendFriendlyLog("Operation cancelled."); }
            }
            catch (Exception ex)
            {
                AppendFriendlyLog($"Exception: {ex.Message}");
                await new ModernWpf.Controls.ContentDialog { Title = "Unexpected error", Content = ex.Message, CloseButtonText = "OK" }.ShowAsync();
            }
            finally
            {
                _cancelRequested = false;
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
            if (FindParentWindow() is System.Windows.Window wnd)
            {
                _originalWindowTitle = wnd.Title;
                wnd.MinWidth = wnd.ActualWidth; wnd.MaxWidth = wnd.ActualWidth;
            }
            NamePanel.Visibility = Visibility.Collapsed;
            PartitionsPanel.Visibility = Visibility.Collapsed;
            LocationPanel.Visibility = Visibility.Collapsed;
            RunPanel.Visibility = Visibility.Visible;
            ValidateAfterCheckbox.IsEnabled = false;
            if (ExternalConsoleCheckbox != null) ExternalConsoleCheckbox.IsEnabled = false;
            if (StartButton != null) StartButton.Visibility = Visibility.Collapsed;
        }

        private void Cancel_Click(object sender, RoutedEventArgs e)
        {
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
                Task.Run(async () =>
                {
                    const int timeoutMs = 7000; const int pollMs = 150; int waited = 0;
                    try
                    {
                        while (waited < timeoutMs)
                        {
                            var p = _currentProcess; if (p != null) { try { if (p.HasExited) return; } catch { return; } }
                            await Task.Delay(pollMs).ConfigureAwait(false); waited += pollMs;
                        }
                    }
                    catch { return; }
                    var toKill = _currentProcess; if (toKill != null)
                    {
                        AppendFriendlyLog("Cancellation timeout elapsed. Forcing termination...");
                        try { if (!toKill.HasExited) toKill.Kill(entireProcessTree: true); } catch (Exception ex) { AppendFriendlyLog($"Failed to force terminate: {ex.Message}"); }
                    }
                });
            }
            catch { }
        }

        // Helpers and process plumbing (adapted from DiskBackupWizard)
        private static (string exePath, string arch, string note) ResolveImagingUtilityPath()
        {
            string baseDir = AppContext.BaseDirectory;
            string armExe = System.IO.Path.Combine(baseDir, "ThirdParty", "ImagingUtility", "win-arm64", "ImagingUtility.exe");
            string x64Exe = System.IO.Path.Combine(baseDir, "ThirdParty", "ImagingUtility", "win-x64", "ImagingUtility.exe");
            string arch = string.Empty; string note = string.Empty;
            try { var osArch = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture; if (osArch == System.Runtime.InteropServices.Architecture.Arm64 && File.Exists(armExe)) { arch = "ARM64"; return (armExe, arch, note); } }
            catch { }
            if (File.Exists(x64Exe)) { arch = "x64"; return (x64Exe, arch, note); }
            if (File.Exists(armExe)) { arch = "ARM64"; note = "x64 executable not found; using ARM64."; return (armExe, arch, note); }
            arch = "x64"; note = "Executable not found in output folder; ensure ThirdParty binaries are copied."; return (x64Exe, arch, note);
        }

        private static string QuoteArg(string path)
        {
            if (string.IsNullOrEmpty(path)) return "";
            if (path.Contains(' ')) return "\"" + path + "\"";
            return path;
        }

        private string SanitizeForFilename(string s)
        {
            if (string.IsNullOrEmpty(s)) return "part";
            var cleaned = new string(s.Where(ch => char.IsLetterOrDigit(ch) || ch == '_' || ch == '-').ToArray());
            if (string.IsNullOrEmpty(cleaned)) cleaned = "part";
            return cleaned;
        }

        private void AppendLog(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            if (!string.IsNullOrEmpty(_runLogPath)) { try { File.AppendAllText(_runLogPath, text + Environment.NewLine); } catch { } }
        }

        private void AppendFriendlyLog(string text)
        {
            if (string.IsNullOrEmpty(text)) return;
            OnUI(() => { if (string.IsNullOrEmpty(LogText)) LogText = text; else LogText += "\r\n" + text; });
            if (!string.IsNullOrEmpty(_runLogPath)) { try { File.AppendAllText(_runLogPath, text + Environment.NewLine); } catch { } }
        }

        private void OnUI(Action action)
        {
            var disp = Dispatcher;
            if (disp == null) { try { action(); } catch { } return; }
            if (disp.CheckAccess()) action(); else try { disp.BeginInvoke(action); } catch { }
        }

        private System.Windows.Window? FindParentWindow() => System.Windows.Window.GetWindow(this);

        private static T? TryFindChild<T>(DependencyObject parent, string? name) where T : FrameworkElement
        {
            int count = VisualTreeHelper.GetChildrenCount(parent);
            for (int i = 0; i < count; i++)
            {
                var child = VisualTreeHelper.GetChild(parent, i);
                if (child is T fe && (name == null || fe.Name == name)) return fe;
                var result = TryFindChild<T>(child, name);
                if (result != null) return result;
            }
            return null;
        }

        private async Task<(bool ok, int exitCode)> RunProcessWithProgressAsync(string exePath, string arguments, CancellationToken ct, string phase)
        {
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = System.Text.Encoding.UTF8,
                StandardErrorEncoding = System.Text.Encoding.UTF8,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(exePath) ?? Environment.CurrentDirectory
            };
            try { psi.EnvironmentVariables["IMAGINGUTILITY_PLAIN"] = "1"; } catch { }

            using var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
            _currentProcess = proc;
            var tcs = new TaskCompletionSource<int>(TaskCreationOptions.RunContinuationsAsynchronously);
            proc.Exited += (s, e) => { try { tcs.TrySetResult(proc.ExitCode); } catch { } };
            try
            {
                if (!proc.Start()) { AppendFriendlyLog("Failed to start process."); return (false, -1); }
                Task readOut = Task.CompletedTask; Task readErr = Task.CompletedTask; bool attached = false;
                await Task.Delay(30).ConfigureAwait(true);
                for (int attempt = 0; attempt < 20; attempt++)
                {
                    try
                    {
                        readOut = ReadStreamLinesAsync(proc.StandardOutput, ct, phase);
                        readErr = ReadStreamLinesAsync(proc.StandardError, ct, phase, logAlso: true);
                        attached = true; break;
                    }
                    catch (InvalidOperationException ioe)
                    {
                        AppendLog($"I/O redirection not ready (attempt {attempt + 1}): {ioe.Message}");
                        if (proc.HasExited) { AppendFriendlyLog("Process exited before streams were ready."); break; }
                        await Task.Delay(75).ConfigureAwait(true);
                    }
                }
                if (!attached) AppendFriendlyLog("Proceeding without live output capture; progress will be limited to phase start/end.");

                using (ct.Register(() => { }))
                {
                    int code = await tcs.Task.ConfigureAwait(true);
                    try { if (readOut != null && readOut != Task.CompletedTask) await readOut.ConfigureAwait(true); if (readErr != null && readErr != Task.CompletedTask) await readErr.ConfigureAwait(true); } catch { }
                    _currentProcess = null; return (code == 0, code);
                }
            }
            finally { _currentProcess = null; }
        }

        private async Task ReadStreamLinesAsync(StreamReader reader, CancellationToken ct, string phase, bool logAlso = false)
        {
            var sb = new System.Text.StringBuilder(); char[] buf = new char[1024];
            while (!ct.IsCancellationRequested)
            {
                int n; try { n = await reader.ReadAsync(buf, 0, buf.Length).ConfigureAwait(false); } catch { break; }
                if (n == 0) break;
                for (int i = 0; i < n; i++)
                {
                    char ch = buf[i]; if (ch == '\r' || ch == '\n') { if (sb.Length > 0) { var line = sb.ToString(); sb.Clear(); if (logAlso) AppendLog(line); ParseAndReportProgress(line, phase); } }
                    else sb.Append(ch);
                }
            }
            if (sb.Length > 0) { var line = sb.ToString(); if (logAlso) AppendLog(line); ParseAndReportProgress(line, phase); }
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
                    _currentProcess = p;
                    if (p == null) { _currentProcess = null; return (false, -1); }
                    p.WaitForExit(); var code = p.ExitCode; _currentProcess = null; return (code == 0, code);
                }
                catch (Exception ex) { AppendLog($"External console launch failed: {ex.Message}"); return (false, -1); }
            }, ct);
        }

        private void ParseAndReportProgress(string line, string phase)
        {
            if (string.IsNullOrWhiteSpace(line)) return;
            if (line.Contains("The handle is invalid.", StringComparison.OrdinalIgnoreCase) || line.Contains("ConsolePal", StringComparison.OrdinalIgnoreCase)) _sawConsoleHandleIssue = true;
            var m = Regex.Match(line, @"(?<!\d)(\d{1,3}(?:\.\d+)?)\s*%", RegexOptions.CultureInvariant);
            if (m.Success) { if (double.TryParse(m.Groups[1].Value, System.Globalization.NumberStyles.Float, CultureInfo.InvariantCulture, out double dpct)) { if (dpct >= 0 && dpct <= 100) { OnUI(() => { try { var pb = TryFindChild<System.Windows.Controls.ProgressBar>(this, "Progress"); if (pb != null) { pb.IsIndeterminate = false; pb.Maximum = 100; pb.Value = dpct; } UpdateWindowTitlePercent(dpct); } catch { } }); } } }
            var speedMatch = Regex.Match(line, @"(?<speed>\d+(?:\.\d+)?\s*(?:B|KB|MB|GB|TB|KiB|MiB|GiB|TiB)/s)", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (speedMatch.Success) { var speed = speedMatch.Groups["speed"].Value.Trim(); OnUI(() => SpeedText = speed); }
            var etaMatch = Regex.Match(line, @"ETA\s*(?<eta>(?:~?\s*)?(?:\d\d?:)?\d\d?:\d\d(?:\.\d{1,3})?|~?\s*\d+\s*[smh])", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
            if (etaMatch.Success) { var eta = etaMatch.Groups["eta"].Value.Trim().Replace("~ ", "~"); OnUI(() => EtaText = $"ETA {eta}"); }
            if (phase == "backup")
            {
                if (line.IndexOf("snapshot", StringComparison.OrdinalIgnoreCase) >= 0 && line.IndexOf("creating", StringComparison.OrdinalIgnoreCase) >= 0) OnUI(() => StatusText = "Creating VSS snapshot...");
                else if (line.IndexOf("scanning", StringComparison.OrdinalIgnoreCase) >= 0) OnUI(() => StatusText = "Scanning used sectors...");
                else if (line.IndexOf("writing", StringComparison.OrdinalIgnoreCase) >= 0 || line.IndexOf("compress", StringComparison.OrdinalIgnoreCase) >= 0) OnUI(() => StatusText = "Writing image...");
            }
            else if (phase == "verify") { if (line.IndexOf("verify", StringComparison.OrdinalIgnoreCase) >= 0) OnUI(() => StatusText = "Verifying images..."); }
        }

        private void UpdateWindowTitlePercent(double? percent, string? prefix = null)
        {
            try
            {
                var wnd = FindParentWindow(); if (wnd == null) return;
                if (percent == null) { if (!string.IsNullOrEmpty(_originalWindowTitle)) wnd.Title = string.IsNullOrEmpty(prefix) ? _originalWindowTitle : $"{_originalWindowTitle} — {prefix}"; return; }
                double p = Math.Max(0, Math.Min(100, percent.Value)); string ptext = p % 1 == 0 ? ((int)p).ToString(CultureInfo.InvariantCulture) : p.ToString("0.0", CultureInfo.InvariantCulture);
                string baseTitle = !string.IsNullOrEmpty(_originalWindowTitle) ? _originalWindowTitle : wnd.Title; string left = string.IsNullOrEmpty(prefix) ? baseTitle : $"{baseTitle} — {prefix}"; wnd.Title = $"{left} ({ptext}%)";
            }
            catch { }
        }

        private Task<(string devicePath, bool isNtfs, string volumeGuid)> ResolvePartitionInfoAsync(PartitionItem part)
        {
            // Wrap synchronous WMI queries in Task.Run to avoid blocking the UI thread.
            return Task.Run(() =>
            {
                // Returns: devicePath (prefer Volume GUID path), whether FS is NTFS, and the GUID (without braces) for naming
                string devicePath = string.Empty;
                string volumeGuid = string.Empty;
                bool isNtfs = false;
                try
                {
                    var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Storage", new ConnectionOptions { EnablePrivileges = true });
                    scope.Connect();
                    string q = $"SELECT AccessPaths FROM MSFT_Partition WHERE DiskNumber = {part.DiskNumber} AND PartitionNumber = {part.PartitionNumber}";
                    using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(q));
                    foreach (ManagementObject mo in searcher.Get())
                    {
                        var aps = mo["AccessPaths"] as string[];
                        if (aps != null && aps.Length > 0)
                        {
                            var vol = aps.FirstOrDefault(a => a != null && a.StartsWith("\\\\?\\Volume", StringComparison.OrdinalIgnoreCase));
                            devicePath = !string.IsNullOrEmpty(vol) ? vol! : aps[0];
                            if (!string.IsNullOrEmpty(vol))
                            {
                                // Extract GUID within braces
                                var m = Regex.Match(vol, @"Volume\{(?<g>[^}]+)\}", RegexOptions.IgnoreCase);
                                if (m.Success) volumeGuid = m.Groups["g"].Value;
                            }
                            break;
                        }
                    }

                    // Determine filesystem via MSFT_Volume if we have a volume path
                    if (!string.IsNullOrEmpty(devicePath) && devicePath.StartsWith("\\\\?\\Volume", StringComparison.OrdinalIgnoreCase))
                    {
                        string volQuery = $"SELECT FileSystem FROM MSFT_Volume WHERE Path = '{devicePath.Replace("'", "''")}'";
                        using var vsearch = new ManagementObjectSearcher(scope, new ObjectQuery(volQuery));
                        foreach (ManagementObject vo in vsearch.Get())
                        {
                            var fs = vo["FileSystem"] as string;
                            if (!string.IsNullOrEmpty(fs) && fs.Equals("NTFS", StringComparison.OrdinalIgnoreCase)) { isNtfs = true; }
                            break;
                        }
                    }
                }
                catch { }

                if (string.IsNullOrEmpty(devicePath) && !string.IsNullOrEmpty(part.DriveLetter))
                {
                    // Fallback: use drive letter; try to resolve GUID via Win32_Volume for naming
                    devicePath = part.DriveLetter + "\\";
                    try
                    {
                        var wmi = new ManagementScope(@"\\.\root\cimv2"); wmi.Connect();
                        string dq = $"SELECT DeviceID, FileSystem FROM Win32_Volume WHERE DriveLetter = '{part.DriveLetter.Replace("'", "''")}:'";
                        using var dsearch = new ManagementObjectSearcher(wmi, new ObjectQuery(dq));
                        foreach (ManagementObject dvo in dsearch.Get())
                        {
                            var devId = dvo["DeviceID"] as string; var fs = dvo["FileSystem"] as string;
                            if (!string.IsNullOrEmpty(devId))
                            {
                                var m = Regex.Match(devId, @"Volume\{(?<g>[^}]+)\}", RegexOptions.IgnoreCase);
                                if (m.Success) volumeGuid = m.Groups["g"].Value;
                            }
                            if (!string.IsNullOrEmpty(fs) && fs.Equals("NTFS", StringComparison.OrdinalIgnoreCase)) isNtfs = true;
                            break;
                        }
                    }
                    catch { }
                }

                return (devicePath, isNtfs, volumeGuid);
            });
        }
    }

    public class PartitionItem : INotifyPropertyChanged
    {
        public int DiskNumber { get; set; }
        public int PartitionNumber { get; set; }
        public string? DriveLetter { get; set; }
        public long SizeBytes { get; set; }
        public string DiskGroup { get; set; } = string.Empty;
        public string? GptType { get; set; }
        public uint? MbrType { get; set; }

        private bool _isSelected;
        public bool IsSelected
        {
            get => _isSelected;
            set { if (_isSelected != value) { _isSelected = value; OnPropertyChanged(); OnPropertyChanged(nameof(Display)); } }
        }

        public string Display
        {
            get
            {
                string size = FormatBytes(SizeBytes);
                string label = DriveLetter != null ? $"Partition {PartitionNumber} ({DriveLetter})" : $"Partition {PartitionNumber}";
                string tag = SpecialTag;
                if (!string.IsNullOrEmpty(tag)) label += $" [{tag}]";
                return $"{label} — {size}";
            }
        }

        // Heuristics for common special partitions
        public bool IsLikelyMsr
        {
            get
            {
                // GPT MSR: E3C9E316-0B5C-4DB8-817D-F92DF00215AE
                if (!string.IsNullOrEmpty(GptType) && GptType.IndexOf("E3C9E316-0B5C-4DB8-817D-F92DF00215AE", StringComparison.OrdinalIgnoreCase) >= 0) return true;
                // MBR type 0x0 (unused) or 0x0C? MSR doesn't exist in MBR; fall back to size heuristic ~16MB without drive letter
                if (DriveLetter == null && SizeBytes > 8L * 1024 * 1024 && SizeBytes <= 64L * 1024 * 1024) return true;
                return false;
            }
        }
        public bool IsLikelyEfi
        {
            get
            {
                // GPT ESP: C12A7328-F81F-11D2-BA4B-00A0C93EC93B
                if (!string.IsNullOrEmpty(GptType) && GptType.IndexOf("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", StringComparison.OrdinalIgnoreCase) >= 0) return true;
                return false;
            }
        }
        public bool IsLikelyRecovery
        {
            get
            {
                // Windows Recovery: DE94BBA4-06D1-4D40-A16A-BFD50179D6AC
                if (!string.IsNullOrEmpty(GptType) && GptType.IndexOf("DE94BBA4-06D1-4D40-A16A-BFD50179D6AC", StringComparison.OrdinalIgnoreCase) >= 0) return true;
                return false;
            }
        }
        public string SpecialTag
        {
            get
            {
                if (IsLikelyMsr) return "MSR";
                if (IsLikelyEfi) return "EFI";
                if (IsLikelyRecovery) return "Recovery";
                return string.Empty;
            }
        }

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
            return string.Format(CultureInfo.CurrentCulture, "{0:0.##} {1}", value, units[unit]);
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
