param([string]$SnapshotPath,[string]$StopPath,[string]$RefreshPath,[switch]$Once)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GuardCore.ps1')
. (Join-Path $PSScriptRoot 'GuardInventory.ps1')
. (Join-Path $PSScriptRoot 'PanelDiagnostics.ps1')
$config=Get-GuardConfig
$state=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '.state'))+[IO.Path]::DirectorySeparatorChar
foreach($path in @($SnapshotPath,$StopPath,$RefreshPath)){if($path -and ![IO.Path]::GetFullPath($path).StartsWith($state,[StringComparison]::OrdinalIgnoreCase)){throw 'Panel paths must remain within .state.'}}
if(!$SnapshotPath){$SnapshotPath=Join-Path $PSScriptRoot '.state\panel-snapshot.json'}
function Invoke-PanelCurl([string]$url,[bool]$direct){
 $exe=if($direct){Join-Path $env:SystemRoot 'System32\curl.exe'}else{Get-GuardProbePath}
 $arguments=@('--silent','--show-error','--fail','--ipv4','--connect-timeout','2','--max-time','5')
 if($direct){$arguments+=@('--noproxy','*')}else{$arguments+=@('--proxy',[string]$config.Proxy,'--noproxy','localhost,127.0.0.1,::1')}
 $arguments+=@($url)
 $watch=[Diagnostics.Stopwatch]::StartNew();$previous=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$raw=& $exe @arguments 2>&1;$exitCode=$LASTEXITCODE}finally{$ErrorActionPreference=$previous;$watch.Stop()}
 if($exitCode -ne 0){$failure=[Exception]::new(('Probe failed (curl '+$exitCode+').'));$failure.Data['CurlExitCode']=$exitCode;throw $failure}
 return [pscustomobject]@{Text=($raw -join "`n");Milliseconds=[int]$watch.ElapsedMilliseconds}
}
function Read-Trace([string]$text){
 $fields=@{};foreach($line in $text -split '\r?\n'){if($line -match '^([a-z_]+)=(.*)$'){$fields[$matches[1]]=$matches[2].Trim()}}
 if(!$fields.ip -or !$fields.loc){throw 'Trace does not contain IP and country.'}
 $address=[ipaddress]$fields.ip;if($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){throw 'Trace did not return IPv4.'}
 return [pscustomobject]@{ip=$fields.ip;country=$fields.loc}
}
function Write-PanelSnapshot($snapshot) {
 $snapshot.Time=(Get-Date).ToString('o')
 $temp=$SnapshotPath+'.tmp'
 [IO.File]::WriteAllText($temp,($snapshot|ConvertTo-Json -Depth 9),[Text.UTF8Encoding]::new($false))
 if(Test-Path -LiteralPath $SnapshotPath){[IO.File]::Replace($temp,$SnapshotPath,[NullString]::Value)}else{[IO.File]::Move($temp,$SnapshotPath)}
}
$diagnostics=$null;$diagnosticIP='';$diagnosticContext='';$nextDiagnostics=[datetime]::MinValue
while($true){
 $components=[pscustomobject]@{ok=$true;error=$null;Time=(Get-Date).ToString('o')}
 try{$config=Get-GuardConfig;if($config.SchemaVersion -ge 3){Assert-GuardInventory $config (Get-GuardInventory $config)}}catch{$components.ok=$false;$components.error=$_.Exception.Message}
 if($StopPath -and (Test-Path -LiteralPath $StopPath)){break}
 if($RefreshPath -and (Test-Path -LiteralPath $RefreshPath)){Remove-Item -LiteralPath $RefreshPath;$nextDiagnostics=[datetime]::MinValue}
 $direct=[pscustomobject]@{ok=$false;ip=$null;country=$null;city=$null;region=$null;org=$null;error=$null;source='ipinfo.io direct'}
 try{
  $response=Invoke-PanelCurl 'https://ipinfo.io/json' $true
  $data=$response.Text|ConvertFrom-Json
  if(!$data.ip -or !$data.country){throw 'Direct IP metadata was incomplete.'}
  [void][ipaddress]::Parse($data.ip)
  $direct.ok=$true;$direct.ip=$data.ip;$direct.country=$data.country;$direct.city=$data.city;$direct.region=$data.region;$direct.org=$data.org
 }catch{
  $direct.error=$_.Exception.Message
  try{$trace=Read-Trace (Invoke-PanelCurl 'https://www.cloudflare.com/cdn-cgi/trace' $true).Text;$direct.ok=$true;$direct.ip=$trace.ip;$direct.country=$trace.country;$direct.source='Cloudflare trace direct';$direct.error=$null}catch{}
 }
 $proxy=[pscustomobject]@{ok=$false;ip=$null;country=$null;milliseconds=$null;matchesPin=$false;error=$null;domains=@();Time=$null}
 $observations=@()
 foreach($url in $config.ProbeUrls){
  try{$response=Invoke-PanelCurl $url $false;$trace=Read-Trace $response.Text;$observations+=@([pscustomobject]@{host=([uri]$url).Host;ok=$true;ip=$trace.ip;country=$trace.country;milliseconds=$response.Milliseconds})}
  catch{$observations+=@([pscustomobject]@{host=([uri]$url).Host;ok=$false;error=$_.Exception.Message})}
 }
 $proxy.domains=$observations
 $good=@($observations|Where-Object ok)
 if($good.Count){$proxy.ip=$good[0].ip;$proxy.country=$good[0].country;$proxy.milliseconds=$good[0].milliseconds}
 $proxy.ok=Test-GuardTraceObservations $observations @($config.ProbeUrls).Count
 $proxy.matchesPin=($proxy.ok -and $proxy.ip -eq $config.ExpectedIPv4 -and $proxy.country -eq $config.ExpectedCountry)
 if(!$proxy.ok){$proxy.error='Selected-client traces failed or disagreed.'}
 $proxy.Time=(Get-Date).ToString('o')
 $environment=[pscustomobject]@{timezone=$null;timezoneId=$null;timezoneIana=(Get-PanelSystemZone);language=$null;regionalFormat=(Get-Culture).Name;location=$null;locationService=$null}
 try{$zone=Get-TimeZone;$environment.timezone=$zone.DisplayName;$environment.timezoneId=$zone.Id}catch{}
 try{$language=Get-WinUILanguageOverride;if($language){$environment.language=$language.Name+' (override)'}else{$environment.language=(Get-WinUserLanguageList|Select-Object -First 1).LanguageTag+' (preference)'}}catch{$environment.language=[Globalization.CultureInfo]::CurrentUICulture.Name+' (process)'}
 try{$environment.location=(Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name Value -ErrorAction Stop).Value}catch{}
 try{$environment.locationService=(Get-Service lfsvc -ErrorAction Stop).Status.ToString()}catch{}
 $context=[string]$config.Proxy+'|'+[string]$environment.timezoneId
 if(!$diagnostics -or $diagnosticIP -ne $proxy.ip -or $diagnosticContext -ne $context -or (Get-Date) -ge $nextDiagnostics){
  $diagnostics=[pscustomobject]@{DNS=[pscustomobject]@{System=(New-PanelDiagnostic 'Windows system DNS');Proxy=(New-PanelDiagnostic 'HTTP proxy probe-domain DNS');Browser=(New-PanelDiagnostic 'Browser policy');Paths=(New-PanelDiagnostic 'Owned probe paths')};WebRTC=(New-PanelDiagnostic 'isolated Edge');IPReputation=(New-PanelDiagnostic 'NetCoffee third-party network cache');ExitMetadata=(New-PanelDiagnostic 'Protected exit metadata')}
  $refreshDiagnostics=$true
 }else{$refreshDiagnostics=$false}
 $snapshot=[pscustomobject]@{Time=(Get-Date).ToString('o');WorkerPid=$PID;Components=$components;Direct=$direct;Proxy=$proxy;Environment=$environment;DNS=$diagnostics.DNS;WebRTC=$diagnostics.WebRTC;IPReputation=$diagnostics.IPReputation;ExitMetadata=$diagnostics.ExitMetadata;RefreshSeconds=30;DiagnosticRefreshSeconds=600;UDPProtection=(Get-BrowserUDPStatus)}
 Write-PanelSnapshot $snapshot
 if($refreshDiagnostics){
  $diagnostics.ExitMetadata=Invoke-PanelExitMetadata $proxy.ip;$snapshot.ExitMetadata=$diagnostics.ExitMetadata;Write-PanelSnapshot $snapshot
  $diagnostics.DNS.System=Invoke-PanelDNS $true;Write-PanelSnapshot $snapshot
  $diagnostics.DNS.Proxy=Invoke-PanelDNS $false;Write-PanelSnapshot $snapshot
  $diagnostics.DNS.Browser=Get-PanelBrowserDNS;Write-PanelSnapshot $snapshot
  $diagnostics.DNS.Paths=Invoke-PanelNetworkPaths;Write-PanelSnapshot $snapshot
  $diagnostics.IPReputation=Invoke-PanelReputation $proxy.ip;$snapshot.IPReputation=$diagnostics.IPReputation;Write-PanelSnapshot $snapshot
  $diagnostics.WebRTC=Invoke-PanelWebRTC $proxy.ip;$snapshot.WebRTC=$diagnostics.WebRTC;Write-PanelSnapshot $snapshot
  $diagnosticIP=$proxy.ip;$diagnosticContext=$context;$nextDiagnostics=(Get-Date).AddSeconds(600)
 }
 if($Once){$snapshot|Select-Object Time,WorkerPid,@{n='DirectAvailable';e={$_.Direct.ok}},@{n='ProxyAvailable';e={$_.Proxy.ok}},@{n='ProxyMatchesPin';e={$_.Proxy.matchesPin}}|ConvertTo-Json -Compress;break}
 $next=(Get-Date).AddSeconds(30)
 while((Get-Date) -lt $next){if(($StopPath -and (Test-Path -LiteralPath $StopPath)) -or ($RefreshPath -and (Test-Path -LiteralPath $RefreshPath))){break};Start-Sleep -Milliseconds 500}
}