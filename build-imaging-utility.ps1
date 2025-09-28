<#
 Builds the imaging-utility project for win-x64 and win-arm64 and copies EXEs
 into the WPF project's ThirdParty folder.

 Assumes folder layout:
   <root>
     ├─ skz-backup-restore/   (this repo)
     └─ imaging-utility/      (sibling repo)

 You can override the imaging-utility path via -ImagingUtilityPath.
#>
param(
    [string] $RepoRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path),
    [string] $ImagingUtilityPath
)

$ErrorActionPreference = 'Stop'

# Paths
if ([string]::IsNullOrWhiteSpace($ImagingUtilityPath)) {
    # Try sibling folder: <repoRoot>\..\imaging-utility
    $parent = Split-Path -Parent $RepoRoot
    $candidate = Join-Path $parent 'imaging-utility'
    if (Test-Path $candidate) {
        $ImagingUtilityPath = (Resolve-Path $candidate).Path
    }
}

if ([string]::IsNullOrWhiteSpace($ImagingUtilityPath) -or -not (Test-Path $ImagingUtilityPath)) {
    throw "Could not locate imaging-utility. Pass -ImagingUtilityPath 'C:\\path\\to\\imaging-utility'."
}

$imagingRoot = (Resolve-Path $ImagingUtilityPath).Path
$wpfThirdParty = Join-Path $RepoRoot 'SkzBackupRestore.Wpf\ThirdParty\ImagingUtility'

# Build/publish single-file trimmed exe for two RIDs
$targets = @(
    @{ rid = 'win-x64'; out = (Join-Path $wpfThirdParty 'win-x64') },
    @{ rid = 'win-arm64'; out = (Join-Path $wpfThirdParty 'win-arm64') }
)

foreach ($t in $targets) {
    $rid = $t.rid
    $outDir = $t.out
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    Push-Location $imagingRoot
    try {
        dotnet publish . -c Release -r $rid --self-contained true /p:PublishSingleFile=true /p:PublishTrimmed=true /p:IncludeNativeLibrariesForSelfExtract=true /p:DebugType=None /p:DebugSymbols=false
    } finally {
        Pop-Location
    }

    # Find the published exe (assumes a single EXE output)
    $publishRoot = Get-ChildItem -Recurse -Directory (Join-Path $imagingRoot 'bin/Release') | Where-Object { $_.FullName -like "*\$rid\publish" } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $publishRoot) { throw "Publish output not found for $rid" }

    $exe = Get-ChildItem -Path $publishRoot.FullName -Filter *.exe | Select-Object -First 1
    if (-not $exe) { throw "No exe found in publish output for $rid at $($publishRoot.FullName)" }

    Copy-Item $exe.FullName -Destination $outDir -Force
}

Write-Host "ImagingUtility exes copied to: $wpfThirdParty" -ForegroundColor Green
