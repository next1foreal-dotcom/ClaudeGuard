$script:GuardRoot = $PSScriptRoot
. (Join-Path $PSScriptRoot 'GuardBrowserUDP.ps1')
$script:GuardGroup = 'ClaudeGuard-01a1169a'
$script:GuardRemote = @('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
function Get-GuardConfig {
    $config = Get-Content -LiteralPath (Join-Path $script:GuardRoot 'guard-config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $uri = [uri]$config.Proxy
    if($uri.Scheme -ne 'http' -or $uri.Host -ne '127.0.0.1' -or $uri.Port -ne 7890 -or $uri.UserInfo) { throw 'Only the approved loopback HTTP proxy 127.0.0.1:7890 is accepted.' }
    $ip=[ipaddress]$config.ExpectedIPv4
    if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or [ipaddress]::IsLoopback($ip)) { throw 'ExpectedIPv4 must be an explicitly approved external IPv4 address.' }
    if($config.ExpectedCountry -notmatch '^[A-Z]{2}$') { throw 'ExpectedCountry must contain two uppercase letters.' }
    if($config.PSObject.Properties.Name -contains 'RequireBrowserUDP' -and $config.RequireBrowserUDP -isnot [bool]) { throw 'RequireBrowserUDP must be a boolean.' }
    if($config.ProbeTimeoutSeconds -lt 1 -or $config.ProbeTimeoutSeconds -gt 10 -or $config.CheckIntervalSeconds -lt 2 -or $config.CheckIntervalSeconds -gt 30) { throw 'Invalid timeout or check interval.' }
    $approved=@('https://api.anthropic.com/cdn-cgi/trace','https://claude.ai/cdn-cgi/trace')
    if(@($config.ProbeUrls).Count -ne 2 -or @($config.ProbeUrls | Where-Object {$_ -notin $approved}).Count) { throw 'Unexpected trace URL.' }
    return $config
}
function Write-GuardLog([string]$event, [string]$detail) {
    $state=Join-Path $script:GuardRoot '.state'
    if(!(Test-Path -LiteralPath $state)){New-Item -ItemType Directory -Path $state -Force | Out-Null}
    $entry=[pscustomobject]@{Time=(Get-Date).ToString('o');Event=$event;Detail=$detail}
    [IO.File]::AppendAllText((Join-Path $state 'events.jsonl'),(($entry|ConvertTo-Json -Compress)+[Environment]::NewLine),[Text.UTF8Encoding]::new($false))
}
function Get-GuardRuleName([string]$path) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try {$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($path.ToLowerInvariant())); return $script:GuardGroup+'-'+([BitConverter]::ToString($digest).Replace('-','').Substring(0,16))} finally {$sha.Dispose()}
}
function Get-GuardProbePath { return Join-Path $script:GuardRoot '.state\network-probe.exe' }
function Assert-GuardFirewall([string[]]$programs) {
    if((Get-GuardConfig).RequireBrowserUDP){Assert-BrowserUDPProtection}
    if((Get-Service MpsSvc -ErrorAction Stop).Status -ne 'Running') {throw 'Windows Firewall service is not running.'}
    if(@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.Enabled -ne 'True'}).Count) {throw 'A Windows Firewall profile is disabled.'}
    foreach($path in $programs) {
        if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw ('Protected executable is missing: '+$path)}
        $rule=Get-NetFirewallRule -PolicyStore ActiveStore -Name (Get-GuardRuleName $path) -ErrorAction Stop
        if($rule.Group -ne $script:GuardGroup -or $rule.Enabled -ne 'True' -or $rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Block' -or $rule.Profile -ne 'Any'){throw 'Firewall rule properties do not match the required policy.'}
        $app=$rule | Get-NetFirewallApplicationFilter
        if($app.Program -ine $path){throw 'Firewall executable path does not match.'}
        $address=$rule | Get-NetFirewallAddressFilter
        if(@(Compare-Object @($script:GuardRemote | Sort-Object) @($address.RemoteAddress | Sort-Object)).Count){throw 'Firewall remote ranges have changed.'}
        $port=$rule | Get-NetFirewallPortFilter
        if($port.Protocol -ne 'Any' -or $port.LocalPort -ne 'Any' -or $port.RemotePort -ne 'Any'){throw 'Firewall protocol/port filter is incomplete.'}
    }
}
function Assert-GuardIPv6 {
    if(@(Get-NetAdapter -Physical | ForEach-Object {Get-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction Stop} | Where-Object Enabled).Count){throw 'IPv6 is enabled on a physical adapter.'}
    if(@(Get-NetRoute -AddressFamily IPv6 -ErrorAction Stop | Where-Object DestinationPrefix -eq '::/0').Count){throw 'An IPv6 default route is present.'}
}
function Assert-GuardTrace([string]$text, $config) {
    $fields=@{}
    foreach($line in ($text -split '\r?\n')) {if($line -match '^([a-z_]+)=(.*)$') {$fields[$matches[1]]=$matches[2].Trim()}}
    if(!$fields.ContainsKey('ip') -or !$fields.ContainsKey('loc')) {throw 'Proxy probe did not return a valid trace.'}
    if($fields.ip -ne $config.ExpectedIPv4 -or $fields.loc -ne $config.ExpectedCountry){throw ('Proxy egress mismatch. Expected '+$config.ExpectedIPv4+'/'+$config.ExpectedCountry+', received '+$fields.ip+'/'+$fields.loc)}
}
function Assert-GuardProxyPort($config) {
    $uri=[uri]$config.Proxy
    $client=New-Object Net.Sockets.TcpClient
    try {
        $pending=$client.BeginConnect($uri.Host,$uri.Port,$null,$null)
        if(!$pending.AsyncWaitHandle.WaitOne(700)){throw 'Local proxy listener is unavailable.'}
        $client.EndConnect($pending)
    } finally {$client.Close()}
}
function Assert-GuardEgress($config) {
    $probe=Get-GuardProbePath
    foreach($url in $config.ProbeUrls) {
        $args=@('--silent','--show-error','--fail','--ipv4','--noproxy','localhost,127.0.0.1,::1','--proxy',[string]$config.Proxy,'--connect-timeout','2','--max-time',[string]$config.ProbeTimeoutSeconds,[string]$url)
        $previous=$ErrorActionPreference
        try {$ErrorActionPreference='Continue'; $raw=& $probe @args 2>&1; $code=$LASTEXITCODE} finally {$ErrorActionPreference=$previous}
        if($code -ne 0){throw ('Proxy trace failed for '+([uri]$url).Host+' (curl exit '+$code+'). No direct fallback is allowed.')}
        Assert-GuardTrace ($raw -join "`n") $config
    }
}
function Set-GuardEnvironment($config) {
    $env:HTTP_PROXY=$config.Proxy; $env:HTTPS_PROXY=$config.Proxy; $env:ALL_PROXY=$config.Proxy
    $env:NO_PROXY='localhost,127.0.0.1,::1'
}
function Import-GuardJob {if(!('ClaudeGuardJob' -as [type])) {$savedLib=$env:LIB; try {$env:LIB=$null; Add-Type -Path (Join-Path $script:GuardRoot 'ClaudeGuardJob.cs') -ErrorAction Stop} finally {$env:LIB=$savedLib}}}
function Invoke-GuardWatch($job,[scriptblock]$fastCheck,[scriptblock]$fullCheck,[int]$interval) {
    $next=[DateTime]::UtcNow.AddSeconds($interval)
    try {
        while($job.IsRunning) {
            & $fastCheck
            if([DateTime]::UtcNow -ge $next){& $fullCheck; $next=[DateTime]::UtcNow.AddSeconds($interval)}
            Start-Sleep -Milliseconds 800
        }
        return [int]$job.ExitCode
    } finally {$job.Dispose()}
}