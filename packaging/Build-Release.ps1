[CmdletBinding()]
param(
    [switch]$AllowDirty,
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$Version = '1.0.10'
$AssemblyVersion = '1.0.10.0'
$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path $RepoRoot 'dist' }

function Write-Utf8NoBom([string]$Path, [string]$Value) {
    $parent = Split-Path -Parent $Path
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Resolve-RepoPath([string]$RelativePath) {
    return Join-Path $RepoRoot ($RelativePath -replace '/', '\')
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-NeutralIcon([string]$Path) {
    Add-Type -AssemblyName System.Drawing
    $bitmap = New-Object Drawing.Bitmap(64, 64, ([Drawing.Imaging.PixelFormat]::Format32bppArgb))
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([Drawing.Color]::FromArgb(255, 35, 42, 47))
    $shield = [Drawing.Point[]]@(
        [Drawing.Point]::new(32, 7),
        [Drawing.Point]::new(52, 14),
        [Drawing.Point]::new(49, 37),
        [Drawing.Point]::new(32, 54),
        [Drawing.Point]::new(15, 37),
        [Drawing.Point]::new(12, 14)
    )
    $graphics.FillPolygon((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(255, 100, 222, 157))), $shield)
    $inner = [Drawing.Point[]]@(
        [Drawing.Point]::new(32, 16),
        [Drawing.Point]::new(42, 20),
        [Drawing.Point]::new(40, 34),
        [Drawing.Point]::new(32, 43),
        [Drawing.Point]::new(24, 34),
        [Drawing.Point]::new(22, 20)
    )
    $graphics.FillPolygon((New-Object Drawing.SolidBrush ([Drawing.Color]::FromArgb(255, 35, 42, 47))), $inner)
    $graphics.Dispose()
    $handle = $bitmap.GetHicon()
    $icon = [Drawing.Icon]::FromHandle($handle)
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $icon.Save($stream) } finally { $stream.Dispose() }
    }
    finally {
        $icon.Dispose()
        $bitmap.Dispose()
    }
}

$statusLines = @(git -C $RepoRoot status --porcelain --untracked-files=all)
$sourceDirty = $statusLines.Count -gt 0
if ($sourceDirty -and -not $AllowDirty) {
    throw 'Tracked or untracked changes are present. Commit them or rerun with -AllowDirty for a candidate build.'
}
$sourceSha = (git -C $RepoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceSha -notmatch '^[0-9a-f]{40}$') { throw 'Unable to resolve the source commit SHA.' }

$outputBase = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Path $outputBase -Force | Out-Null
$shortSha = $sourceSha.Substring(0, 12).ToLowerInvariant()
$outputDirectory = Join-Path $outputBase ('v' + $Version + '-' + $shortSha)
if (Test-Path -LiteralPath $outputDirectory) { throw ('Release output already exists; choose a new source SHA or output root: ' + $outputDirectory) }
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$workBase = Join-Path $PSScriptRoot '.build'
New-Item -ItemType Directory -Path $workBase -Force | Out-Null
$workRoot = Join-Path $workBase ([Guid]::NewGuid().ToString('N'))
$stage = Join-Path $workRoot 'payload'
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$tracked = @(git -C $RepoRoot ls-files --full-name)
if ($LASTEXITCODE -ne 0) { throw 'Unable to enumerate tracked source files.' }
$trackedSet = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
foreach ($trackedPath in $tracked) { [void]$trackedSet.Add(($trackedPath -replace '\\', '/')) }
$payload = @(
    'BrowserDiagnostics.mjs'
    'BrowserUDPGuard.ps1'
    'Check-Network.cmd'
    'ClaudeGuard.ps1'
    'ClaudeGuard.xaml'
    'ClaudeGuardBackdrop.cs'
    'ClaudeGuardJob.cs'
    'ClaudeGuardUI.ps1'
    'Get-PanelSnapshot.ps1'
    'guard-config.example.json'
    'GuardBrowserUDP.ps1'
    'GuardCore.ps1'
    'GuardDiscovery.ps1'
    'GuardIconConverter.cs'
    'GuardIcons.ps1'
    'GuardInventory.ps1'
    'GuardPanel.ps1'
    'GuardPresentation.ps1'
    'GuardRouteAudit.py'
    'GuardRouting.ps1'
    'GuardRuntime.ps1'
    'GuardSetup.ps1'
    'GuardSetup.xaml'
    'GuardSetupCore.ps1'
    'GuardSetupUI.ps1'
    'GuardTheme.ps1'
    'GuardWindowLayout.ps1'
    'icons/LICENSE.txt'
    'icons/lucide.json'
    'Install-Browser-UDP.cmd'
    'Install-Protection.cmd'
    'Open-ClaudeGuard.cmd'
    'PanelDiagnostics.ps1'
    'README.md'
    'Remove-Browser-UDP.cmd'
    'Remove-Protection.cmd'
    'requirements.txt'
    'runtime-lock.json'
    'setup-zh.json'
    'Start-Claude-Code.cmd'
    'Start-Claude-Desktop.cmd'
    'ui-palette.json'
    'ui-zh.json'
)
$seenPaths = New-Object Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
foreach ($relative in $payload) {
    if (-not $seenPaths.Add($relative)) { throw ('Duplicate payload path: ' + $relative) }
    if (-not $trackedSet.Contains($relative)) { throw ('Allowlisted payload file is not tracked: ' + $relative) }
    $source = Resolve-RepoPath $relative
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw ('Allowlisted source file is missing: ' + $relative) }
    $target = Join-Path $stage ($relative -replace '/', '\\')
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $target -Force
}
$iconRelative = 'assets/ClaudeGuard.ico'
$iconPath = Join-Path $stage ($iconRelative -replace '/', '\\')
New-Item -ItemType Directory -Path (Split-Path -Parent $iconPath) -Force | Out-Null
New-NeutralIcon $iconPath
if (-not $seenPaths.Add($iconRelative)) { throw 'Generated icon path collides with the payload allowlist.' }
$payload += $iconRelative
$payload = @($payload | Sort-Object)

$fileEntries = New-Object Collections.Generic.List[object]
foreach ($relative in $payload) {
    $path = Join-Path $stage ($relative -replace '/', '\')
    $info = Get-Item -LiteralPath $path
    $fileEntries.Add([ordered]@{ path = $relative; length = [int64]$info.Length; sha256 = (Get-Sha256 $path) })
}
Add-Type -AssemblyName System.IO.Compression,System.IO.Compression.FileSystem
$zipPath = Join-Path $workRoot 'payload.zip'
$zipStream = [IO.File]::Open($zipPath, [IO.FileMode]::CreateNew)
$archive = [IO.Compression.ZipArchive]::new($zipStream, [IO.Compression.ZipArchiveMode]::Create, $false)
try {
    foreach ($relative in $payload) {
        $entry = $archive.CreateEntry($relative, [IO.Compression.CompressionLevel]::Optimal)
        $input = [IO.File]::OpenRead((Join-Path $stage ($relative -replace '/', '\')))
        $output = $entry.Open()
        try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
    }
}
finally { $archive.Dispose(); $zipStream.Dispose() }
$payloadSha = Get-Sha256 $zipPath
$manifest = [ordered]@{
    version = $Version
    assemblyVersion = $AssemblyVersion
    payloadSha256 = $payloadSha
    files = $fileEntries.ToArray()
}
$manifestPath = Join-Path $workRoot 'payload.manifest.json'
Write-Utf8NoBom $manifestPath (($manifest | ConvertTo-Json -Depth 10 -Compress) + "`n")

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw ('Framework64 csc.exe not found: ' + $csc) }
$exeName = 'ClaudeGuard-' + $Version + '-win-x64.exe'
$exePath = Join-Path $outputDirectory $exeName
$cscArguments = @(
    '/nologo', '/target:winexe', '/platform:x64', '/optimize+',
    ('/out:' + $exePath), ('/win32icon:' + $iconPath),
    '/reference:System.dll', '/reference:System.Core.dll', '/reference:System.IO.Compression.dll',
    '/reference:System.IO.Compression.FileSystem.dll', '/reference:System.Web.Extensions.dll',
    '/reference:System.Windows.Forms.dll',
    ('/resource:' + $zipPath + ',ClaudeGuard.Payload.zip'),
    ('/resource:' + $manifestPath + ',ClaudeGuard.Payload.manifest.json'),
    (Join-Path $PSScriptRoot 'Launcher.cs')
)
$previousLib = $env:LIB
try { $env:LIB = $null; & $csc @cscArguments }
finally { $env:LIB = $previousLib }
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exePath)) { throw 'Launcher compilation failed.' }

$exeSha = Get-Sha256 $exePath
$sourceShaPath = Join-Path $outputDirectory 'sourceSHA.txt'
$sourceText = "sourceSHA=$sourceSha`nsourceDirty=$($sourceDirty.ToString().ToLowerInvariant())`nversion=$Version`n"
Write-Utf8NoBom $sourceShaPath $sourceText
$sourceShaFileHash = Get-Sha256 $sourceShaPath
Write-Utf8NoBom (Join-Path $outputDirectory 'sourceSHA.sha256') ($sourceShaFileHash + '  sourceSHA.txt' + "`n")
$receipt = [ordered]@{
    schema = 1
    version = $Version
    assemblyVersion = $AssemblyVersion
    architecture = 'win-x64'
    unsigned = $true
    sourceSHA = $sourceSha
    sourceCommit = $sourceSha
    sourceDirty = $sourceDirty
    payloadFileCount = $payload.Count
    payloadSHA256 = $payloadSha
    payloadHashPrefix = $payloadSha.Substring(0, 12).ToLowerInvariant()
    executable = $exeName
    executableSHA256 = $exeSha
    outputDirectory = $outputDirectory
    payloadFiles = $fileEntries.ToArray()
    builtUtc = [DateTime]::UtcNow.ToString('o')
}
$receiptPath = Join-Path $outputDirectory 'release-receipt.json'
Write-Utf8NoBom $receiptPath (($receipt | ConvertTo-Json -Depth 12) + "`n")
$receiptSha = Get-Sha256 $receiptPath
$sumLines = @(
    ($exeSha + '  ' + $exeName),
    ($receiptSha + '  release-receipt.json'),
    ($sourceShaFileHash + '  sourceSHA.txt')
)
Write-Utf8NoBom (Join-Path $outputDirectory 'SHA256SUMS') (($sumLines -join "`n") + "`n")
Write-Utf8NoBom (Join-Path $outputDirectory 'build-summary.txt') ("status=success`nsourceSHA=$sourceSha`nsourceDirty=$($sourceDirty.ToString().ToLowerInvariant())`npayloadFileCount=$($payload.Count)`npayloadSHA256=$payloadSha`nexecutableSHA256=$exeSha`nunsigned=true`noutput=$outputDirectory`n")
Write-Output ('Release output: ' + $outputDirectory)
Write-Output ('Executable: ' + $exePath)
Write-Output ('Source SHA: ' + $sourceSha)
Write-Output ('Payload files: ' + $payload.Count)
Write-Output ('Payload SHA256: ' + $payloadSha)
Write-Output ('Executable SHA256: ' + $exeSha)
