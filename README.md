# SKZ Backup & Restore (WIP)

A Windows desktop app (WPF, .NET 8) for making full-disk image backups with a simple, modern UI. It drives the separate ImagingUtility CLI under the hood and shows live progress, speed, and ETA. After backup, it can verify the entire set for integrity.

⚠️ Work-in-progress: Expect sharp edges. Use on test machines/disks first. Running as Administrator is required for disk access and VSS. Data loss is possible if misused.

## What it does today

- Full physical disk backup via the ImagingUtility CLI
  - Uses VSS snapshots when possible to capture a consistent view of NTFS volumes
  - Used-only NTFS imaging to reduce size/time (implemented in the CLI)
  - Zstandard compression with chunk-level SHA-256 and a manifest for set verification (implemented in the CLI)
- Friendly progress in the UI
  - Percent complete, current speed, and ETA parsed from ImagingUtility "plain" output
  - High-level, noise-free on-screen log for the main steps
  - Progress bar reaches 100% at the end (success or failure)
- Optional verification
  - Runs a set-level verification (verify-set) after the backup completes
  - Supports a quick vs. full verification mode
- Cancel behavior that respects the tool
  - Requests a graceful cancel first
  - If the process doesn’t exit, force-terminates after a short timeout to avoid hanging

## Not done yet (roadmap, subject to change)

- Restore workflows and UI
- Partition-by-partition progress display
- Settings surface for tuning behaviors (e.g., cancel timeout)
- Packaging/installer and signed releases
- Broader filesystem support beyond NTFS (depends on the CLI)

## Requirements

- Windows 10/11 on x64 or ARM64
- .NET 8 SDK to build
- Administrator rights to run backups from the app (needed for disk access and VSS)
- ImagingUtility source available locally to build and bundle, or prebuilt binaries

## Building

This repo expects a sibling folder layout by default:

```
<root>
├─ skz-backup-restore/   # this repo
└─ imaging-utility/      # sibling repo (the CLI)
```

1) Build and copy the ImagingUtility binaries into the WPF app:

- From this repo root (PowerShell):

```
./build-imaging-utility.ps1
```

- If your imaging-utility folder is elsewhere:

```
./build-imaging-utility.ps1 -ImagingUtilityPath "C:\\src\\imaging-utility"
```

This publishes ImagingUtility for win-x64 and win-arm64 as single-file executables and copies them to `SkzBackupRestore.Wpf/ThirdParty/ImagingUtility/<rid>/`.

2) Build the WPF application:

- Debug build (fast inner loop):

```
dotnet build .\skz-backup-restore.sln -c Debug
```

- Release build (includes bundled CLI in output/publish):

```
dotnet build .\skz-backup-restore.sln -c Release
# or
dotnet publish .\SkzBackupRestore.Wpf\SkzBackupRestore.Wpf.csproj -c Release -r win-x64
```

Note: The WPF project is configured to include any EXEs under `SkzBackupRestore.Wpf/ThirdParty/ImagingUtility/**` into the Release output/publish. See `README-build.md` for more details.

## Running

- Run the app as Administrator (right-click the EXE → Run as administrator) so the wizard can enumerate and read physical disks.
- Open the Disk Backup wizard, select a disk, pick a destination, and choose whether to verify on completion (Quick or Full).
- Start the backup. The UI shows status, speed, and ETA. A friendly, high-level log appears under the progress.
- Cancel: Press Cancel to request cancellation. The app waits briefly for a graceful exit; if the tool won’t stop, it force-terminates after a short timeout. A partial backup set may remain—delete it before retrying.

## Troubleshooting

- CLI missing: If starting a backup fails because ImagingUtility isn’t found, (re)run `build-imaging-utility.ps1` to bundle the CLI, or place the appropriate ImagingUtility EXE(s) under `SkzBackupRestore.Wpf/ThirdParty/ImagingUtility/<rid>/`.
- Progress not updating: The app runs the CLI in "plain" mode and parses stdout. If a custom ImagingUtility build changes its output format, update the parser in the UI accordingly.
- Access denied: Ensure you’re running the GUI elevated and that any antivirus or endpoint protection allows raw disk reads.
- Hung cancel: If cancel appears stuck, the app will force-terminate after its timeout. You may need to clean up any incomplete backup set and retry.

## Project structure (high level)

- `SkzBackupRestore.Wpf/` — WPF app, ModernWpf-based shell and disk backup wizard
  - `Views/DiskBackupWizard.xaml(.cs)` — main wizard UI and process orchestration
  - `ThirdParty/ImagingUtility/` — holds ImagingUtility binaries per RID (win-x64, win-arm64)
- `build-imaging-utility.ps1` — builds and copies ImagingUtility into the WPF project
- `README-build.md` — additional notes about building/bundling the CLI

## Credits

- ImagingUtility CLI (separate project) provides the core imaging, compression, hashing, and verification
- ModernWpf for the app’s look and theme integration

## Disclaimer

This is early software provided without any warranty. Use at your own risk. Always test on non-critical systems and keep independent backups. Contributions and feedback are welcome while this is still taking shape.
