[CmdletBinding()]
param(
    [ValidateSet('Check','Launch','Install','Remove')][string]$Mode='Check',
    [ValidateSet('Code','Desktop')][string]$Client='Code',
    [string]$StatusFile,
    [string]$StopFile,
    [Parameter(ValueFromRemainingArguments=$true)][string[]]$ClaudeArguments=@()
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GuardCore.ps1')
. (Join-Path $PSScriptRoot 'GuardInventory.ps1')
. (Join-Path $PSScriptRoot 'GuardRouting.ps1')
$state=Join-Path $PSScriptRoot '.state'
New-Item -ItemType Directory -Path $state -Force | Out-Null
$config=Get-GuardConfig
$script:GuardStatusPath=Get-GuardStatePath $StatusFile
$script:GuardStopPath=Get-GuardStatePath $StopFile
$probe=Get-GuardProbePath
$programs=@($config.ProtectedPrograms)+@($probe)
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin=([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$job=$null; $mutex=$null; $ownsMutex=$false
try {
    if($Mode -eq 'Install' -or $Mode -eq 'Remove') {
        if(!$isAdmin) {
            $powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
            $arguments='-NoProfile -File "'+$PSCommandPath+'" -Mode '+$Mode
            $child=Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -PassThru -Wait
            if($child.ExitCode -ne 0){throw ('Administrator operation failed, exit '+$child.ExitCode+'. Check .state/install-result.json.')}
            if($Mode -eq 'Install'){$config=Get-GuardConfig; $programs=@($config.ProtectedPrograms)+@($probe); Assert-GuardInventory $config (Get-GuardInventory $config); Assert-GuardFirewall $programs; Write-Host 'Firewall protection installed and verified.' -ForegroundColor Green}
            else {Write-Host 'Only ClaudeGuard firewall rules were removed.'}
            exit 0
        }
        if($Mode -eq 'Remove') {
            Get-NetFirewallRule -Group $script:GuardGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
            Write-GuardLog 'rules-removed' 'User invoked Remove; existing proxy and IPv6 settings were not changed.'
            exit 0
        }
        $inventory=Get-GuardInventory $config
        $programs=@($inventory.Programs)+@($probe)
        $source=Join-Path $env:SystemRoot 'System32\curl.exe'
        if(!(Test-Path -LiteralPath $probe)){Copy-Item -LiteralPath $source -Destination $probe}
        if((Get-FileHash -LiteralPath $probe).Hash -ne (Get-FileHash -LiteralPath $source).Hash){throw 'Network probe differs from the Windows curl executable; refusing installation.'}
        foreach($path in $programs) {
            if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw ('Protected program not found: '+$path)}
            $name=Get-GuardRuleName $path
            $existing=Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
            if(!$existing){New-NetFirewallRule -Name $name -DisplayName ('ClaudeGuard: block direct - '+[IO.Path]::GetFileName($path)) -Group $script:GuardGroup -Description 'Block non-loopback IPv4/IPv6 for this executable. The approved HTTP proxy remains on 127.0.0.1:7890.' -Direction Outbound -Action Block -Enabled True -Profile Any -Program $path -Protocol Any -RemoteAddress $script:GuardRemote -PolicyStore PersistentStore | Out-Null}
        }
        if($config.RequireBrowserUDP){
            & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -File (Join-Path $PSScriptRoot 'BrowserUDPGuard.ps1') -Mode Install
            if($LASTEXITCODE -ne 0){throw 'Browser UDP rule installation failed.'}
        }
        Assert-GuardFirewall $programs
        Save-GuardInventory $config $inventory
        $receipt=[pscustomobject]@{Success=$true;Time=(Get-Date).ToString('o');Rules=@($programs | ForEach-Object {Get-GuardRuleName $_});Programs=$programs}
        [IO.File]::WriteAllText((Join-Path $state 'install-result.json'),($receipt|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
        Write-GuardLog 'installed' 'Per-program direct-connection blocks verified in ActiveStore.'
        exit 0
    }
    Write-GuardStatus 'checking-components' 'Checking installed Claude components and update coverage.'
    Assert-GuardInventory $config (Get-GuardInventory $config)
    Write-GuardStatus 'checking-firewall' 'Checking active per-program outbound blocks.'
    Assert-GuardFirewall $programs
    Assert-GuardIPv6
    Write-GuardStatus 'checking-routing' 'Checking saved routing, selected node and proxy graph.'
    Assert-GuardRouting $config
    Assert-GuardProxyPort $config
    Write-GuardStatus 'checking-egress' 'Checking both AI-domain egress addresses through the proxy.'
    Assert-GuardEgress $config
    Assert-GuardRoutingUnchanged $config
    Write-GuardStatus 'ready' 'All startup checks passed; no claim about account risk or untested clients.'
    Write-Host ('PASS: proxy '+$config.Proxy+'; egress '+$config.ExpectedIPv4+' / '+$config.ExpectedCountry+'; firewall and IPv6 checked.') -ForegroundColor Green
    Write-GuardLog 'preflight-pass' ($Client+'; expected egress '+$config.ExpectedIPv4+'/'+$config.ExpectedCountry)
    if($Mode -eq 'Check'){exit 0}
    if($isAdmin){throw 'Run Launch in a normal, non-administrator terminal. Only installation needs elevation.'}
    if(@(Get-Process -Name claude -ErrorAction SilentlyContinue).Count){throw 'Claude is already running outside this launch. Close it yourself, then launch through this guard.'}
    $mutex=New-Object Threading.Mutex($false,'Local\ClaudeGuard-01a1169a')
    $ownsMutex=$mutex.WaitOne(0)
    if(!$ownsMutex){throw 'Another guarded Claude session is already running.'}
    $app=if($Client -eq 'Code'){$config.CodePath}else{$config.DesktopPath}
    if($app -notin $config.ProtectedPrograms){throw 'Launcher executable is not included in the protected program list.'}
    if($Client -eq 'Desktop') {
        $package=Get-AppxPackage -Name Claude
        if(!$package -or (Join-Path $package.InstallLocation 'app\claude.exe') -ine $app){throw 'Claude Desktop was updated or moved. Refresh protected paths and run Install before launching.'}
    }
    Set-GuardEnvironment $config
    Import-GuardJob
    if($Client -eq 'Code') {
        if(@($ClaudeArguments | Where-Object {$_ -match '^--(settings|setting-sources)(=|$)'}).Count){throw 'Network settings are managed by the guard; --settings overrides are not accepted.'}
        $settingsPath=Join-Path $state 'session-settings.json'
        $settings=@{env=@{HTTP_PROXY=$config.Proxy;HTTPS_PROXY=$config.Proxy;ALL_PROXY=$config.Proxy;NO_PROXY='localhost,127.0.0.1,::1'}}
        [IO.File]::WriteAllText($settingsPath,($settings|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
        $launchArguments=@($ClaudeArguments)+@('--settings',$settingsPath)
    } else {$launchArguments=@(('--proxy-server='+$config.Proxy),'--disable-quic')+@($ClaudeArguments)}
    Write-Host 'Starting Claude in a supervised window. Closing this guard also closes its Claude process tree.' -ForegroundColor Yellow
    $job=[ClaudeGuardJob]::new([string]$app,[string[]]$launchArguments,(Get-Location).Path,($Client -eq 'Code'))
    Write-GuardStatus 'running' 'Claude started in the supervised process job.'
    Write-GuardLog 'launched' ($Client+'; PID '+$job.ProcessId)
    $fast={if($script:GuardStopPath -and (Test-Path -LiteralPath $script:GuardStopPath)){throw 'Stop requested by the local guard UI.'}; Assert-GuardProxyPort $config; Assert-GuardRoutingUnchanged $config}
    $full={Assert-GuardInventory $config (Get-GuardInventory $config); Assert-GuardFirewall $programs; Assert-GuardIPv6; Assert-GuardRouting $config; Assert-GuardEgress $config; Write-GuardStatus 'running' 'Latest full network and protection check passed.'}
    $childExit = Invoke-GuardWatch $job $fast $full $config.CheckIntervalSeconds
    $job=$null
    if($childExit -ne 0){throw ('Claude exited with code '+$childExit)}
    Write-GuardLog 'session-ended' 'Supervised root exited; remaining job members were closed.'
    Write-GuardStatus 'stopped' 'Claude session ended.'
    Write-Host 'Claude session ended.'
} catch {
    if($job){$job.Dispose();$job=$null}
    $message=$_.Exception.Message
    if($message -eq 'Stop requested by the local guard UI.'){Write-GuardStatus 'stopped' $message}else{Write-GuardStatus 'blocked' $message}
    Write-GuardLog 'blocked-or-stopped' $message
    if($Mode -eq 'Install') {[IO.File]::WriteAllText((Join-Path $state 'install-result.json'),([pscustomobject]@{Success=$false;Error=$message;Time=(Get-Date).ToString('o')}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))}
    Write-Host ('BLOCKED / STOPPED: '+$message) -ForegroundColor Red
    Write-Host 'No direct retry, automatic restart, or new IP enrollment was attempted.'
    exit 1
} finally {
    if($job){$job.Dispose()}
    if($ownsMutex){$mutex.ReleaseMutex()}
    if($mutex){$mutex.Dispose()}
}