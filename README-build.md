# Build and bundle ImagingUtility for the WPF app

This repo bundles the `ImagingUtility.exe` CLI into the WPF app outputs for production (Release) builds.

Expected folder layout (siblings):

```
<root>
├─ skz-backup-restore/   # this repo
└─ imaging-utility/      # sibling repo
```

## 1) Build ImagingUtility and copy into WPF project

Run from the repo root (PowerShell):

```
./build-imaging-utility.ps1
```

If your imaging-utility is not a sibling folder, you can pass the path explicitly:

```
./build-imaging-utility.ps1 -ImagingUtilityPath "C:\\src\\imaging-utility"
```

This will:
- Publish `imaging-utility` for `win-x64` and `win-arm64` as single-file executables
- Copy the resulting EXEs into `SkzBackupRestore.Wpf/ThirdParty/ImagingUtility/<rid>/`

## 2) Build or publish the WPF app

- Debug build for development:
```
dotnet build .\skz-backup-restore.sln -c Debug
```

- Release build (bundles the CLI EXEs into output/publish):
```
dotnet build .\skz-backup-restore.sln -c Release
# or
dotnet publish .\SkzBackupRestore.Wpf\SkzBackupRestore.Wpf.csproj -c Release -r win-x64
```

The WPF project is configured to include any EXEs under `SkzBackupRestore.Wpf/ThirdParty/ImagingUtility/**` into both the build output and publish folder (Release config only).

## Notes
- Ensure the `imaging-utility` project exists under the repo folder `imaging-utility/` and builds on your machine.
- If the CLI output EXE has a different name, update the copy script paths accordingly.
- You can tweak the publish options in the script (single-file, trimming) as desired.
