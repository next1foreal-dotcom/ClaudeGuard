function New-PanelDiagnostic([string]$scope) {return [pscustomobject]@{state='pending';scope=$scope;Time=(Get-Date).ToString('o');error=$null}}
function Invoke-PanelDNS([bool]$direct) {
 $scope=if($direct){'Windows system DNS'}else{'HTTP proxy probe-domain DNS'}
 $result=New-PanelDiagnostic $scope
 $token=[guid]::NewGuid().ToString('N')
 try {
  if($direct){
   $null=Resolve-DnsName -Name ($token+'-1.d.ip.net.coffee') -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
  }else{
   # Request only the public test name through the pinned HTTP proxy. A failed image load can still resolve DNS.
   try{$null=Invoke-PanelCurl ('https://'+$token+'-1.d.ip.net.coffee/pixel.gif') $false}catch{}
  }
  $data=(Invoke-PanelCurl ('https://ip.net.coffee/api/dns/result/'+$token) $false).Text|ConvertFrom-Json
  $servers=@($data.dns_servers | Where-Object {$_ -and [ipaddress]::TryParse([string]$_,[ref]([ipaddress]::None))})
  $result|Add-Member NoteProperty resolvers $servers
  $result.state=if($servers.Count){'observed'}else{'inconclusive'}
 }catch{$result.state='failed';$result.error=$_.Exception.Message}
 $result.Time=(Get-Date).ToString('o');return $result
}
function Invoke-PanelReputation([string]$ip) {
 $result=New-PanelDiagnostic 'NetCoffee third-party CIDR cache; not a Claude score'
 try {
  if(!$ip){throw 'No Claude egress address is available.'}
  $data=(Invoke-PanelCurl ('https://ip.net.coffee/api/iprisk/'+$ip) $false).Text|ConvertFrom-Json
  if($null -eq $data.trust_score -or !$data.cidr -or !$data.ip){throw 'Reputation response is incomplete.'}
  # Never display a cached score belonging to an unrelated network.
  $parts=$data.cidr -split '/';$network=[ipaddress]$parts[0];$address=[ipaddress]$ip;$prefix=[int]$parts[1]
  if($network.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.AddressFamily -ne $network.AddressFamily -or $prefix -lt 0 -or $prefix -gt 32){throw 'Unsupported reputation network.'}
  $a=$address.GetAddressBytes();$n=$network.GetAddressBytes()
  for($bit=0;$bit -lt $prefix;$bit++){ $index=[int][Math]::Floor($bit/8);$mask=1 -shl (7-($bit%8));if(($a[$index] -band $mask) -ne ($n[$index] -band $mask)){throw 'Reputation cache does not cover this egress.'}}
  $score=[int]$data.trust_score;if($score -lt 0 -or $score -gt 100){throw 'Invalid third-party score.'}
  $result|Add-Member NoteProperty score $score
  $result|Add-Member NoteProperty cidr ([string]$data.cidr)
  $result|Add-Member NoteProperty requestedIP $ip
  $result|Add-Member NoteProperty responseIP ([string]$data.ip)
  $result|Add-Member NoteProperty category ([string]$data.asn_kind)
  $result.state='observed'
 }catch{$result.state='failed';$result.error=$_.Exception.Message}
 $result.Time=(Get-Date).ToString('o');return $result
}
function Invoke-PanelWebRTC([string]$ip,[string]$BrowserPath) {
 $scope='Isolated Edge with explicit HTTP proxy; not the daily browser'
 $result=New-PanelDiagnostic $scope
 $job=$null;$mutex=$null;$ownsMutex=$false
 try {
  $edge=if($BrowserPath){$BrowserPath}else{Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'}
  if($edge -notin (Get-BrowserUDPPrograms) -or [IO.Path]::GetFileName($edge) -notin @('msedge.exe','chrome.exe')){throw 'Unexpected diagnostic browser executable.'}
  $mutex=[Threading.Mutex]::new($false,'Local\ClaudeGuard-BrowserDiagnostic-01a1169a')
  $ownsMutex=$mutex.WaitOne(10000)
  if(!$ownsMutex){throw 'Another owned diagnostic is still running.'}
  $node=Join-Path $env:ProgramFiles 'nodejs\node.exe'
  if(!(Test-Path -LiteralPath $edge) -or !(Test-Path -LiteralPath $node)){throw 'Edge or Node.js is unavailable.'}
  $profile=Join-Path $PSScriptRoot ('.state\browser-diagnostic-'+[IO.Path]::GetFileNameWithoutExtension($edge)+'-profile')
  if(!(Test-Path -LiteralPath $profile)){New-Item -ItemType Directory -Path $profile|Out-Null}
  # An old port record is owned diagnostic state, never a user's browser profile.
  $portFile=Join-Path $profile 'DevToolsActivePort';if(Test-Path -LiteralPath $portFile){Remove-Item -LiteralPath $portFile}
  Import-GuardJob
  $arguments=@('--headless=new','--remote-debugging-port=0','--remote-debugging-address=127.0.0.1',('--user-data-dir='+$profile),('--proxy-server='+[string]$config.Proxy),'--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-extensions','--disable-sync','--disable-gpu','--disable-quic','about:blank')
  $job=[ClaudeGuardJob]::new($edge,[string[]]$arguments,$PSScriptRoot,$false)
  $raw=& $node (Join-Path $PSScriptRoot 'BrowserDiagnostics.mjs') $profile $ip
  $result=($raw -join "`n")|ConvertFrom-Json
  $result|Add-Member NoteProperty Time (Get-Date).ToString('o')
  $result|Add-Member NoteProperty Browser ([IO.Path]::GetFileName($edge))
 }catch{$result=New-PanelDiagnostic $scope;$result.state='failed';$result.error=$_.Exception.Message}
 finally{if($job){$job.Dispose()};if($ownsMutex){$mutex.ReleaseMutex()};if($mutex){$mutex.Dispose()}}
 return $result
}
# These observations apply only to the owned curl probe and test endpoint.
# They never authorize an exit or stand in for the launch firewall audit.
function Invoke-PanelPathRequest([string]$Executable,[int]$Family,[string]$Proxy) {
 $arguments=@('--silent','--show-error','--fail',('--ipv'+$Family),'--connect-timeout','2','--max-time','4')
 if($Proxy){$arguments+=@('--proxy',$Proxy,'--noproxy','localhost,127.0.0.1,::1')}else{$arguments+=@('--noproxy','*')}
 $arguments+='https://www.cloudflare.com/cdn-cgi/trace'
 $previous=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$raw=& $Executable @arguments 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$previous}
 $valid=$false
 if($code -eq 0){
  $text=$raw -join "`n"
  if($text -match '(?m)^ip=([^\r\n]+)'){
   $address=$null
   if([ipaddress]::TryParse($matches[1],[ref]$address)){
    $expected=if($Family -eq 4){[Net.Sockets.AddressFamily]::InterNetwork}else{[Net.Sockets.AddressFamily]::InterNetworkV6}
    $valid=$address.AddressFamily -eq $expected
   }
  }
 }
 [pscustomobject]@{exitCode=$code;reachable=$valid}
}
function Get-PanelPathVerdict($Before,$Protected,$After) {
 if($Protected.reachable -or $Protected.exitCode -eq 0){return 'warning'}
 if($Before.reachable -and $After.reachable -and $Protected.exitCode -in @(7,28)){return 'denial-observed'}
 return 'inconclusive'
}
function Invoke-PanelNetworkPaths {
 $result=New-PanelDiagnostic 'Owned curl only; Cloudflare test endpoint; no proxy client is stopped'
 try {
  $system=Join-Path $env:SystemRoot 'System32\curl.exe';$probe=Get-GuardProbePath
  if((Get-FileHash -LiteralPath $system).Hash -ne (Get-FileHash -LiteralPath $probe).Hash){throw 'Diagnostic probe differs from Windows curl.'}
  foreach($family in @(4,6)){
   $before=Invoke-PanelPathRequest $system $family ''
   $protected=Invoke-PanelPathRequest $probe $family ''
   $after=Invoke-PanelPathRequest $system $family ''
   $result|Add-Member NoteProperty ('IPv'+$family) ([pscustomobject]@{state=(Get-PanelPathVerdict $before $protected $after);controlBefore=$before;protected=$protected;controlAfter=$after})
  }
  # Bind an unused loopback port without listening, preventing another service from taking it.
  $socket=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Stream,[Net.Sockets.ProtocolType]::Tcp)
  try {
   $socket.ExclusiveAddressUse=$true;$socket.Bind([Net.IPEndPoint]::new([ipaddress]::Loopback,0))
   $dead=Invoke-PanelPathRequest $probe 4 ('http://127.0.0.1:'+$socket.LocalEndPoint.Port)
   $deadState=if($dead.reachable -or $dead.exitCode -eq 0){'warning'}elseif($dead.exitCode -in @(7,28)){'rejected'}else{'inconclusive'}
   $result|Add-Member NoteProperty DeadProxy ([pscustomobject]@{state=$deadState;exitCode=$dead.exitCode})
  }finally{$socket.Dispose()}
  $result.state=if('warning' -in @($result.IPv4.state,$result.IPv6.state,$result.DeadProxy.state)){'warning'}else{'observed'}
 }catch{$result.state='failed';$result.error=$_.Exception.Message}
 $result.Time=(Get-Date).ToString('o');return $result
}
function Get-PanelBrowserDNS {
 $result=New-PanelDiagnostic 'Local Chrome/Edge policy registry only; effective policy and live browser DNS remain unverified'
 $entries=@()
 foreach($browser in @(@('Edge','Microsoft\Edge'),@('Chrome','Google\Chrome'))){
  foreach($hive in @('HKLM','HKCU')){
   $key=$hive+':\SOFTWARE\Policies\'+$browser[1]
   $entry=[pscustomobject]@{browser=$browser[0];source=$hive;state='not-configured';mode=$null;templateConfigured=$false}
   try {
    if(Test-Path -LiteralPath $key -ErrorAction Stop){
     $policy=Get-ItemProperty -LiteralPath $key -ErrorAction Stop
     $entry.mode=[string]$policy.DnsOverHttpsMode
     $entry.templateConfigured=![string]::IsNullOrWhiteSpace([string]$policy.DnsOverHttpsTemplates)
     if($entry.mode -or $entry.templateConfigured){$entry.state='configured'}
    }
   }catch{$entry.state='unreadable'}
   $entries+=@($entry)
  }
 }
 $result|Add-Member NoteProperty policies $entries
 $result.state='unverified';return $result
}