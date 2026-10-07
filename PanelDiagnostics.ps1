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