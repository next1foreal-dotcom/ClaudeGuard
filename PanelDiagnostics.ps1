function Invoke-PanelCurlAttempt([string]$exe,[string[]]$arguments) {
 $watch=[Diagnostics.Stopwatch]::StartNew();$previous=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$raw=& $exe @arguments 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$previous;$watch.Stop()}
 return [pscustomobject]@{ExitCode=$code;Text=($raw -join "`n");Milliseconds=[int]$watch.ElapsedMilliseconds}
}
function Test-PanelPublicIPv4([string]$value) {
 $address=$null
 if($value -notmatch '^\d{1,3}(\.\d{1,3}){3}$' -or ![ipaddress]::TryParse($value,[ref]$address) -or $address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){return $false}
 $b=$address.GetAddressBytes()
 return !($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and ($b[1] -eq 168 -or ($b[1] -eq 0 -and $b[2] -in @(0,2)))) -or ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or ($b[0] -eq 198 -and ($b[1] -in @(18,19) -or ($b[1] -eq 51 -and $b[2] -eq 100))) -or ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113))
}
function Invoke-PanelHttp([string]$url,[bool]$direct) {
 $exe=if($direct){Join-Path $env:SystemRoot 'System32\curl.exe'}else{Get-GuardProbePath}
 $base=@('--silent','--show-error','--fail','--ipv4','--connect-timeout','2','--max-time','5','--max-filesize','1048576')
 if($direct){$base+=@('--noproxy','*')}else{$base+=@('--proxy',[string]$config.Proxy,'--noproxy','localhost,127.0.0.1,::1')}
 if($url -match '^https://dnsleak\.dev/api/'){$base+=@('-H','Accept: application/json')}
 $attempt=Invoke-PanelCurlAttempt $exe ($base+@($url));$elapsed=$attempt.Milliseconds
 if($attempt.ExitCode -eq 0){return [pscustomobject]@{Text=$attempt.Text;Milliseconds=$elapsed;Resolution='configured-route'}}
 $originalCode=$attempt.ExitCode;$uri=[uri]$url
 # Only optional diagnostic API hosts. Never change DNS measurement names or startup trace routing.
 $hosts=@('ipinfo.io','ipwho.is','ipapi.co','ip.net.coffee')
 if(!$direct -and $originalCode -in @(6,7,28,35) -and $uri.Scheme -eq 'https' -and $uri.Port -eq 443 -and !$uri.UserInfo -and $uri.Host -in $hosts){
  try {
   $dnsUrl='https://cloudflare-dns.com/dns-query?name='+[uri]::EscapeDataString($uri.Host)+'&type=A'
   $dns=Invoke-PanelCurlAttempt $exe ($base+@('-H','accept: application/dns-json',$dnsUrl));$elapsed+=$dns.Milliseconds
   if($dns.ExitCode -eq 0){
    $answer=$dns.Text|ConvertFrom-Json
    if($answer.Status -eq 0){
     $addresses=@($answer.Answer|Where-Object {$_.type -eq 1 -and (Test-PanelPublicIPv4 ([string]$_.data))}|Select-Object -ExpandProperty data -Unique|Select-Object -First 2)
     foreach($address in $addresses){
      # --connect-to retains the original HTTPS host, SNI and certificate verification.
      $mapping=$uri.Host+':443:'+ $address+':443'
      $retry=Invoke-PanelCurlAttempt $exe ($base+@('--connect-to',$mapping,$url));$elapsed+=$retry.Milliseconds
      if($retry.ExitCode -eq 0){return [pscustomobject]@{Text=$retry.Text;Milliseconds=$elapsed;Resolution='proxy-doh-ipv4'}}
     }
    }
   }
  }catch{ } # The original request remains a failure if the bounded fallback cannot complete.
 }
 $failure=[Exception]::new(('Probe failed (curl '+$originalCode+').'));$failure.Data['CurlExitCode']=$originalCode;throw $failure
}
function Set-PanelDiagnosticFailure($result,$exception) {
 # Transport/HTTP failures describe test-service availability, never a leak verdict.
 $result.state=if($exception.Data.Contains('CurlExitCode')){'unavailable'}else{'failed'}
 $result.error=$exception.Message
}
function New-PanelDiagnostic([string]$scope) {return [pscustomobject]@{state='pending';scope=$scope;Time=(Get-Date).ToString('o');error=$null}}
function Invoke-PanelProxyDNSFallback {
 $result=New-PanelDiagnostic 'HTTP proxy fresh-name DNS; dnsleak.dev authoritative observations, not a global leak verdict'
 $result|Add-Member NoteProperty source 'dnsleak.dev'
 try {
  $session=(Invoke-PanelCurl 'https://dnsleak.dev/api/new' $false).Text|ConvertFrom-Json
  $id=[string]$session.testId;$names=@($session.hostnames)
  if($id -cnotmatch '^[a-z0-9]{6,64}$' -or !$config.ExpectedIPv4 -or $session.client.ip -ne $config.ExpectedIPv4){throw 'DNS session does not match the approved proxy exit.'}
  $pattern='^'+[regex]::Escape($id)+'-(a|q)[0-9]{2}\.t\.dnsleak\.dev$'
  if($names.Count -lt 2 -or $names.Count -gt 16 -or @($names|Select-Object -Unique).Count -ne $names.Count -or @($names|Where-Object {$_ -cnotmatch $pattern}).Count -or !@($names|Where-Object {$_ -match '-a[0-9]{2}\.'}).Count -or !@($names|Where-Object {$_ -match '-q[0-9]{2}\.'}).Count){throw 'DNS service returned an unexpected measurement hostname set.'}
  $base=@('--silent','--show-error','--fail','--proxy',[string]$config.Proxy,'--noproxy','localhost,127.0.0.1,::1','--connect-timeout','2','--max-time','3','--max-filesize','65536')
  $triggers=@();$exe=Get-GuardProbePath
  foreach($name in $names){
   # Only the proxy resolves these single-use names. TLS failure after lookup is expected.
   $attempt=Invoke-PanelCurlAttempt $exe ($base+@(('https://'+$name+'/')))
   $triggers+=@([pscustomobject]@{host=$name;exitCode=$attempt.ExitCode})
  }
  $servers=@();$observedA=$false;$observedAAAA=$false;$lookups=0
  for($poll=0;$poll -lt 3;$poll++){
   Start-Sleep -Milliseconds 1000
   $data=(Invoke-PanelCurl ('https://dnsleak.dev/api/result/'+$id) $false).Text|ConvertFrom-Json
   if($data.testId -cne $id -or $data.client.ip -ne $config.ExpectedIPv4){throw 'DNS result does not match the requested session and approved exit.'}
   # Ignore the service's heuristic verdict and any secondary/observer resolver echoes.
   $entries=@($data.resolvers|Where-Object {$_.role -eq 'resolver' -and $_.original -gt 0 -and (Test-PanelPublicIPv4 ([string]$_.ip))})
   $servers=@($entries|Select-Object -ExpandProperty ip -Unique)
   $observedA=@($entries|Where-Object sawA).Count -gt 0;$observedAAAA=@($entries|Where-Object sawQ).Count -gt 0;$lookups=[int]$data.lookups
   if($servers.Count -and $observedA -and $observedAAAA -and $lookups -ge $names.Count){break}
  }
  $result|Add-Member NoteProperty resolvers $servers
  $result|Add-Member NoteProperty resolverCountries @($entries|Select-Object -ExpandProperty countryCode -Unique)
  $result|Add-Member NoteProperty observedA $observedA
  $result|Add-Member NoteProperty observedAAAA $observedAAAA
  $result|Add-Member NoteProperty lookups $lookups
  $result|Add-Member NoteProperty requestedLookups $names.Count
  $result|Add-Member NoteProperty triggers $triggers
  $result.state=if($servers.Count -and $observedA -and $observedAAAA -and $lookups -ge $names.Count){'observed'}else{'inconclusive'}
  if($result.state -eq 'inconclusive'){$result.error='Authoritative DNS observations are incomplete.'}
 }catch{Set-PanelDiagnosticFailure $result $_.Exception}
 $result.Time=(Get-Date).ToString('o');return $result
}
function Invoke-PanelDNS([bool]$direct) {
 $scope=if($direct){'Windows system DNS'}else{'HTTP proxy probe-domain DNS'}
 $result=New-PanelDiagnostic $scope
 $token=[guid]::NewGuid().ToString('N');$triggerError=$null
 try {
  if($direct){
   $null=Resolve-DnsName -Name ($token+'-1.d.ip.net.coffee') -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue
  }else{
   # Request only the public test name through the pinned HTTP proxy. A failed image load can still resolve DNS.
   try{$null=Invoke-PanelCurl ('https://'+$token+'-1.d.ip.net.coffee/pixel.gif') $false}catch{$triggerError=$_.Exception.Message}
  }
  $data=(Invoke-PanelCurl ('https://ip.net.coffee/api/dns/result/'+$token) $false).Text|ConvertFrom-Json
  $servers=@($data.dns_servers | Where-Object {$_ -and [ipaddress]::TryParse([string]$_,[ref]([ipaddress]::None))})
  $result|Add-Member NoteProperty resolvers $servers
  $result.state=if($servers.Count){'observed'}else{'inconclusive'}
  if(!$servers.Count -and $triggerError){$result.error='DNS test-name request failed: '+$triggerError}
 }catch{Set-PanelDiagnosticFailure $result $_.Exception}
 if(!$direct -and $result.state -ne 'observed'){
  $fallback=Invoke-PanelProxyDNSFallback
  $fallback|Add-Member NoteProperty previousSource 'ip.net.coffee'
  $fallback|Add-Member NoteProperty previousState $result.state
  $fallback|Add-Member NoteProperty previousError $result.error
  $result=$fallback
 }
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
 }catch{Set-PanelDiagnosticFailure $result $_.Exception}
 $result.Time=(Get-Date).ToString('o');return $result
}
function Invoke-PanelWebRTC([string]$ip,[string]$BrowserPath,[switch]$EnvironmentOnly) {
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
  $zoneBefore=(Get-TimeZone).Id
  $probeArgs=@((Join-Path $PSScriptRoot 'BrowserDiagnostics.mjs'),$profile,$ip)
  if($EnvironmentOnly){$probeArgs+='--environment-only'}
  $raw=& $node @probeArgs
  $result=($raw -join "`n")|ConvertFrom-Json
  $result|Add-Member NoteProperty Time (Get-Date).ToString('o')
  $result|Add-Member NoteProperty Browser ([IO.Path]::GetFileName($edge))
  $result|Add-Member NoteProperty BrowserPath $edge
  if($result.environment -and $zoneBefore -eq (Get-TimeZone).Id){$result.environment|Add-Member NoteProperty systemTimezoneId $zoneBefore}
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
function Invoke-PanelExitMetadata([string]$ip) {
 $result=New-PanelDiagnostic 'IP geolocation estimate through the configured HTTP proxy'
 foreach($entry in @{ip=$ip;timezone=$null;city=$null;country=$null;source=$null;attempts=@()}.GetEnumerator()){$result|Add-Member NoteProperty $entry.Key $entry.Value}
 if(!$ip){$result.state='unverified';return $result}
 $invalid=$false
 foreach($service in @('https://ipinfo.io/json','https://ipwho.is/','https://ipapi.co/json/')){
  $source=([uri]$service).Host;$received=$false
  try {
   $response=Invoke-PanelCurl $service $false;$received=$true
   if($response.Text.Length -gt 32768){throw 'Metadata response is too large.'}
   $data=$response.Text|ConvertFrom-Json
   if($data.success -eq $false -or $data.error){throw 'Metadata service returned an error.'}
   if(!$data.ip -or ([ipaddress]$data.ip).ToString() -ne ([ipaddress]$ip).ToString()){throw 'Metadata IP differs from the protected exit.'}
   $zone=if($data.timezone -is [string]){$data.timezone}else{$data.timezone.id}
   if(!$zone -or $zone.Length -gt 100 -or $zone -notmatch '^(?:[A-Za-z_+-]+/){1,2}[A-Za-z0-9_+-]+$'){throw 'Metadata timezone is missing or invalid.'}
   $country=if($data.country_code){$data.country_code}else{$data.country}
   if($country -notmatch '^[A-Z]{2}$'){throw 'Metadata country is invalid.'}
   $result.timezone=[string]$zone;$result.city=[string]$data.city;$result.country=[string]$country;$result.source=$source;$result.state='observed'
   $result.attempts+=@([pscustomobject]@{source=$source;state='observed'})
   $result.Time=(Get-Date).ToString('o');return $result
  }catch{
   if($received){$invalid=$true}
   $result.attempts+=@([pscustomobject]@{source=$source;state=$(if($received){'invalid'}else{'unavailable'});error=$_.Exception.Message})
  }
 }
 $result.state=if($invalid){'failed'}else{'unavailable'}
 $result.error='No matching exit metadata could be verified.';$result.Time=(Get-Date).ToString('o');return $result
}
function Get-PanelSystemZone {
 [TimeZoneInfo]::ClearCachedData()
 try {
  $node=Join-Path $env:ProgramFiles 'nodejs\node.exe'
  if(!(Test-Path -LiteralPath $node)){return $null}
  $raw=& $node (Join-Path $PSScriptRoot 'BrowserDiagnostics.mjs') --system-environment
  if($LASTEXITCODE -ne 0){return $null}
  $value=($raw -join "`n")|ConvertFrom-Json
  # Offset is a consistency check only, never sufficient for timezone equality.
  $zone=Get-TimeZone
  if($value.utcOffsetMinutes -ne $zone.GetUtcOffset([datetime]::Now).TotalMinutes){return $null}
  return [string]$value.timezone
 }catch{return $null}
}