[CmdletBinding()]
param(
    [string]$BuildDirectory
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$passed = 0

function Assert-Release([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw ('FAIL: ' + $Message) }
    $script:passed++
    Write-Output ('PASS: ' + $Message)
}

function Write-Utf8NoBom([string]$Path, [string]$Value) {
    [IO.File]::WriteAllText($Path, $Value, [Text.UTF8Encoding]::new($false))
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Quote-ProcessArgument([string]$Value) {
    if ($Value.IndexOf('"') -ge 0) { throw 'Test path contains an unsupported quote character.' }
    return '"' + $Value + '"'
}

function Invoke-OwnedProcess([string]$FileName, [string[]]$Arguments, [int]$TimeoutMs = 60000) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $FileName
    $quoted = New-Object Collections.Generic.List[string]
    foreach ($argument in $Arguments) { $quoted.Add((Quote-ProcessArgument $argument)) }
    $psi.Arguments = $quoted -join ' '
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $psi
    try {
        [void]$process.Start()
        if (-not $process.WaitForExit($TimeoutMs)) {
            try { $process.Kill() } catch { }
            throw ('Owned process timed out: ' + $FileName)
        }
        return $process.ExitCode
    }
    finally { $process.Dispose() }
}

function Find-OwnedWindowProcess([int]$RootPid) {
    try { $all = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'") } catch { return $null }
    $owned = New-Object Collections.Generic.HashSet[int]
    [void]$owned.Add($RootPid)
    for ($pass = 0; $pass -lt 8; $pass++) {
        foreach ($entry in $all) {
            if ($owned.Contains([int]$entry.ParentProcessId)) { [void]$owned.Add([int]$entry.ProcessId) }
        }
    }
    foreach ($entry in $all) {
        if (-not $owned.Contains([int]$entry.ProcessId)) { continue }
        try {
            $process = Get-Process -Id ([int]$entry.ProcessId) -ErrorAction Stop
            if ($process.MainWindowHandle -ne 0 -and $process.MainWindowTitle -like 'ClaudeGuard*') { return $process }
            $process.Dispose()
        } catch { }
    }
    return $null
}

function Invoke-FreshLauncherSmoke([string]$Executable, [string]$Destination) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $Executable
    $psi.Arguments = (Quote-ProcessArgument '--destination') + ' ' + (Quote-ProcessArgument $Destination)
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $psi.WorkingDirectory = Split-Path -Parent $Executable
    $foreignModules = $Destination + '.foreign-modules'
    $foreignUtility = Join-Path $foreignModules 'Microsoft.PowerShell.Utility'
    New-Item -ItemType Directory -Path $foreignUtility -Force | Out-Null
    Write-Utf8NoBom (Join-Path $foreignUtility 'Microsoft.PowerShell.Utility.psd1') "@{RootModule='foreign.psm1';ModuleVersion='7.0';PowerShellVersion='7.0';FunctionsToExport=@('Get-FileHash')}"
    Write-Utf8NoBom (Join-Path $foreignUtility 'foreign.psm1') "function Get-FileHash { throw 'Foreign PowerShell module loaded' }"
    $psi.EnvironmentVariables['PSModulePath'] = $foreignModules
    $launcher = New-Object Diagnostics.Process
    $launcher.StartInfo = $psi
    $window = $null
    try {
        [void]$launcher.Start()
        for ($attempt = 0; $attempt -lt 60 -and -not $window; $attempt++) {
            Start-Sleep -Milliseconds 500
            $window = Find-OwnedWindowProcess $launcher.Id
        }
        if (-not $window) { throw 'Fresh EXE did not expose an owned setup window within 30 seconds.' }
        Write-Output ('Fresh owned window PID=' + $window.Id + ' title=[' + $window.MainWindowTitle + '] handle=' + $window.MainWindowHandle)
        $discoveryResult = Join-Path (Join-Path $Destination '.state') 'setup-result-*.json'
        $discoveryReady = $false
        for ($attempt = 0; $attempt -lt 120; $attempt++) {
            if (@(Get-ChildItem -Path $discoveryResult -File -ErrorAction SilentlyContinue).Count -gt 0) { $discoveryReady = $true; break }
            Start-Sleep -Milliseconds 500
        }
        if (-not $discoveryReady) { throw 'Fresh EXE setup discovery did not finish within 60 seconds.' }
        $discoveryFile = Get-ChildItem -Path $discoveryResult -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $discovery = Get-Content -LiteralPath $discoveryFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-Release ([bool]$discovery.Ok) 'fresh EXE discovery completes successfully rather than merely writing an error result'
        Assert-Release ($discovery.HostCheck.HashAvailable -and $discovery.HostCheck.NativeModulesFirst) 'fresh EXE isolates foreign PowerShell module paths and resolves Get-FileHash'
        Assert-Release ($discovery.HostCheck.ScriptSHA256 -eq (Get-Sha256 (Join-Path $Destination 'GuardSetup.ps1'))) 'normal EXE child computes the actual script checksum'
        Start-Sleep -Milliseconds 1000
        if (-not $window.CloseMainWindow()) { throw 'Owned setup window rejected CloseMainWindow().' }
        if (-not $window.WaitForExit(30000)) { throw 'Owned setup window did not close within 30 seconds.' }
        if (-not $launcher.WaitForExit(30000)) { throw 'Fresh EXE launcher did not exit after setup close.' }
        if ($launcher.ExitCode -ne 0) { throw ('Fresh EXE exited with code ' + $launcher.ExitCode) }
    }
    finally {
        if ($window -and -not $window.HasExited) { try { [void]$window.CloseMainWindow() } catch { }; try { [void]$window.WaitForExit(5000) } catch { } }
        if (-not $launcher.HasExited) { try { $launcher.Kill() } catch { }; try { [void]$launcher.WaitForExit(5000) } catch { } }
        if ($window) { $window.Dispose() }
        $launcher.Dispose()
    }
}
if ([string]::IsNullOrWhiteSpace($BuildDirectory)) {
    $dist = Join-Path $RepoRoot 'dist'
    $candidate = @(Get-ChildItem -LiteralPath $dist -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'v1.0.10-*' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1)
    if ($candidate.Count -ne 1) { throw 'Pass -BuildDirectory or create one dist/v1.0.10-* output first.' }
    $BuildDirectory = $candidate[0].FullName
}
$BuildDirectory = [IO.Path]::GetFullPath($BuildDirectory)
$receiptPath = Join-Path $BuildDirectory 'release-receipt.json'
$sumPath = Join-Path $BuildDirectory 'SHA256SUMS'
$receipt = Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8 | ConvertFrom-Json
$exePath = Join-Path $BuildDirectory ([string]$receipt.executable)
Assert-Release ($receipt.status -ne 'failed' -and [string]$receipt.version -eq '1.0.10') 'release receipt identifies version 1.0.10'
Assert-Release ([bool]$receipt.unsigned) 'release receipt records unsigned build'
Assert-Release ([string]$receipt.sourceSHA -match '^[0-9a-f]{40}$') 'release receipt records source commit SHA'
Assert-Release ((Test-Path -LiteralPath $exePath -PathType Leaf)) 'single EXE exists'
Assert-Release ([string]$receipt.executableSHA256 -eq (Get-Sha256 $exePath)) 'EXE SHA256 matches release receipt'
Assert-Release ([string]$receipt.payloadFileCount -eq ([array]$receipt.payloadFiles).Count) 'payload file count matches allowlist'
Assert-Release ((Get-Content -LiteralPath $sumPath -Raw -Encoding UTF8) -match [regex]::Escape([string]$receipt.executableSHA256)) 'SHA256SUMS contains EXE hash'

$pe = [IO.File]::ReadAllBytes($exePath)
Assert-Release ($pe.Length -gt 256 -and $pe[0] -eq 0x4d -and $pe[1] -eq 0x5a) 'EXE has a PE header'
$peOffset = [BitConverter]::ToInt32($pe, 0x3c)
$machine = [BitConverter]::ToUInt16($pe, $peOffset + 4)
$optional = $peOffset + 24
$magic = [BitConverter]::ToUInt16($pe, $optional)
$subsystemOffset = if ($magic -eq 0x20b) { $optional + 68 } else { $optional + 68 }
$subsystem = [BitConverter]::ToUInt16($pe, $subsystemOffset)
Assert-Release ($machine -eq 0x8664) 'EXE is Windows x64'
Assert-Release ($subsystem -eq 2) 'EXE is GUI subsystem'
Assert-Release (([Diagnostics.FileVersionInfo]::GetVersionInfo($exePath).FileVersion) -like '1.0.10.0*') 'EXE file version is 1.0.10.0'

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeGuard release test ' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    $verifyReceipt = Join-Path $testRoot 'verify receipt.json'
    $verifyExit = Invoke-OwnedProcess $exePath @('--verify-only', '--receipt', $verifyReceipt)
    Assert-Release ($verifyExit -eq 0) '--verify-only exits successfully'
    $verify = Get-Content -LiteralPath $verifyReceipt -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Release ([string]$verify.status -eq 'success' -and [string]$verify.version -eq '1.0.10') '--verify-only receipt is successful'
    Assert-Release ([string]$verify.payloadSha256 -eq [string]$receipt.payloadSHA256) '--verify-only payload hash matches build receipt'

    $destination = Join-Path $testRoot 'payload destination with spaces'
    $extractReceipt = Join-Path $testRoot 'extract receipt.json'
    $extractExit = Invoke-OwnedProcess $exePath @('--extract-only', '--destination', $destination, '--receipt', $extractReceipt)
    Assert-Release ($extractExit -eq 0) '--extract-only handles a path with spaces'
    $extract = Get-Content -LiteralPath $extractReceipt -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Release ([string]$extract.status -eq 'success' -and [string]$extract.destination -eq [IO.Path]::GetFullPath($destination)) 'extraction receipt records destination'
    Assert-Release ((Get-ChildItem -LiteralPath $destination -Recurse -File | Where-Object { $_.Name -like '*.staging-*' }).Count -eq 0) 'atomic extraction leaves no staging files'
    foreach ($item in @($extract.files)) {
        $relative = [string]$item.path
        Assert-Release ($relative -notmatch '(^|/)(\.\.?)(/|$)' -and $relative -notmatch '\\' -and $relative -notmatch '^[A-Za-z]:') ('manifest path is relative: ' + $relative)
        $filePath = Join-Path $destination ($relative -replace '/', '\')
        Assert-Release (Test-Path -LiteralPath $filePath -PathType Leaf) ('extracted file exists: ' + $relative)
        Assert-Release ([string]$item.sha256 -eq (Get-Sha256 $filePath)) ('extracted file hash matches: ' + $relative)
    }

    $configPath = Join-Path $destination 'guard-config.json'
    $statePath = Join-Path $destination '.state\user-marker.json'
    New-Item -ItemType Directory -Path (Split-Path -Parent $statePath) -Force | Out-Null
    Write-Utf8NoBom $configPath '{"userMarker":"preserve-me"}'
    Write-Utf8NoBom $statePath '{"stateMarker":"preserve-me"}'
    $secondReceipt = Join-Path $testRoot 'second receipt.json'
    $secondExit = Invoke-OwnedProcess $exePath @('--extract-only', '--destination', $destination, '--receipt', $secondReceipt)
    Assert-Release ($secondExit -eq 0) 'relaunch verifies an existing payload'
    Assert-Release ((Get-Content -LiteralPath $configPath -Raw -Encoding UTF8) -eq '{"userMarker":"preserve-me"}') 'guard-config.json is preserved on relaunch'
    Assert-Release ((Get-Content -LiteralPath $statePath -Raw -Encoding UTF8) -eq '{"stateMarker":"preserve-me"}') '.state user data is preserved on relaunch'

    $corruptRelative = @($extract.files | Where-Object { [string]$_.path -like '*.ps1' } | Select-Object -First 1)[0].path
    $corruptPath = Join-Path $destination ($corruptRelative -replace '/', '\')
    Add-Content -LiteralPath $corruptPath -Value '# deliberate corruption' -Encoding UTF8
    $corruptReceipt = Join-Path $testRoot 'corrupt receipt.json'
    $corruptExit = Invoke-OwnedProcess $exePath @('--extract-only', '--destination', $destination, '--receipt', $corruptReceipt)
    Assert-Release ($corruptExit -ne 0) 'corrupted installed code is refused'
    $corrupt = Get-Content -LiteralPath $corruptReceipt -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Release ([string]$corrupt.status -eq 'failed') 'corruption refusal writes a failed receipt'

    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $setupScript = Join-Path $destination 'GuardSetupUI.ps1'
    $setupExit = Invoke-OwnedProcess $powershell @('-NoProfile', '-STA', '-File', $setupScript, '-UiSmokeTest')
    Assert-Release ($setupExit -eq 0) 'factory wizard UI smoke exits normally in its owned child'
    $mainScript = Join-Path $destination 'ClaudeGuardUI.ps1'
    $example = Join-Path $destination 'guard-config.example.json'
    $mainExit = Invoke-OwnedProcess $powershell @('-NoProfile', '-STA', '-File', $mainScript, '-UiSmokeTest', '-TestConfigPath', $example)
    Assert-Release ($mainExit -eq 0) 'main UI smoke exits normally in its owned child'
    $selectedFixture = Get-Content -LiteralPath $example -Raw -Encoding UTF8 | ConvertFrom-Json
    $selectedFixture.SchemaVersion=3
    $selectedFixture | Add-Member NoteProperty Clients @(@{Id='claude-code';Name='Claude Code';Kind='Code'},@{Id='claude-desktop';Name='Claude Desktop';Kind='Desktop'},@{Id='codex-code';Name='Codex CLI';Kind='CodexCode'},@{Id='codex-desktop';Name='Codex Desktop';Kind='CodexDesktop'}) -Force
    $selectedFixturePath=Join-Path $testRoot 'four selected clients.json'
    Write-Utf8NoBom $selectedFixturePath ($selectedFixture | ConvertTo-Json -Depth 8)
    $selectedExit=Invoke-OwnedProcess $powershell @('-NoProfile','-STA','-File',$mainScript,'-UiSmokeTest','-TestConfigPath',$selectedFixturePath)
    Assert-Release ($selectedExit -eq 0) 'configured four-client tabs preserve launch selection and fit panel/widget themes'
    $freshDestination = Join-Path $testRoot 'fresh normal destination with spaces'
    Invoke-FreshLauncherSmoke $exePath $freshDestination
    Assert-Release $true 'fresh EXE setup window closes through its owned child'
}
finally {
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $resolvedRoot.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase) -or $resolvedRoot -notmatch 'ClaudeGuard release test [0-9a-f]{32}$') { throw ('Refusing to clean unexpected test path: ' + $resolvedRoot) }
    if (Test-Path -LiteralPath $resolvedRoot) {
        $rootItem = Get-Item -LiteralPath $resolvedRoot -Force
        if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing to clean a reparse-point test root.' }
        $reparse = @(Get-ChildItem -LiteralPath $resolvedRoot -Force -Recurse -ErrorAction Stop | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
        if ($reparse.Count -gt 0) { throw 'Refusing to clean a test tree containing a reparse point.' }
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
Write-Output ('Release tests passed: ' + $passed)
