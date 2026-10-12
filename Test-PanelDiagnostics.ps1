$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'PanelDiagnostics.ps1')
. (Join-Path $PSScriptRoot 'GuardPanel.ps1')
$labels=Get-Content (Join-Path $PSScriptRoot 'ui-zh.json') -Raw -Encoding UTF8|ConvertFrom-Json
$count=0
function Assert-Case([bool]$ok,[string]$name){if(!$ok){throw ('FAIL '+$name)};$script:count++;Write-Output ('PASS '+$name)}
$up=[pscustomobject]@{reachable=$true;exitCode=0};$denied=[pscustomobject]@{reachable=$false;exitCode=7};$dnsFailure=[pscustomobject]@{reachable=$false;exitCode=6}
Assert-Case ((Get-PanelPathVerdict $up $denied $up) -eq 'denial-observed') 'Denial requires successful controls before and after'
Assert-Case ((Get-PanelPathVerdict $denied $denied $denied) -eq 'inconclusive') 'Unavailable IPv6 cannot be marked blocked'
Assert-Case ((Get-PanelPathVerdict $up $denied $denied) -eq 'inconclusive') 'A network failure during the probe is inconclusive'
Assert-Case ((Get-PanelPathVerdict $up $dnsFailure $up) -eq 'inconclusive') 'DNS failure is not a transport denial'
Assert-Case ((Get-PanelPathVerdict $denied $up $denied) -eq 'warning') 'Protected direct success is a warning even if controls fail'
Assert-Case ((Get-PanelPathVerdict $up ([pscustomobject]@{reachable=$false;exitCode=0}) $up) -eq 'warning') 'Successful transport with an invalid trace cannot pass'
$controls=@{HideIP=[pscustomobject]@{IsChecked=$true}}
foreach($name in @('DNS','WebRTC','Reputation')){
 $controls[$name+'State']=[pscustomobject]@{Text='';ToolTip=''}
 $controls[$name+'Mark']=[pscustomobject]@{Text=''}
}
$tones=@{}
function Set-PanelTone($name,$tone){$script:tones[$name]=$tone}
$observed=[pscustomobject]@{state='observed';resolvers=@('192.0.2.1')}
$snapshot=[pscustomobject]@{DNS=[pscustomobject]@{System=$observed;Proxy=$observed};WebRTC=[pscustomobject]@{state='inconclusive'};IPReputation=[pscustomobject]@{state='observed';score=100};UDPProtection=[pscustomobject]@{ok=$true}}
Update-PanelDiagnostics $snapshot
Assert-Case ($tones.DNS -eq 'neutral') 'DNS resolver counts never imply leak prevention'
Assert-Case ($tones.Reputation -eq 'neutral') 'A third-party 100 score is not a safety pass'
Assert-Case ($tones.WebRTC -eq 'neutral') 'Empty STUN candidates do not get a green pass'
Assert-Case ($controls.DNSState.ToolTip -notmatch '192\.0\.2\.1') 'Hide IP also masks resolver details'
$snapshot.WebRTC.state='warning';Update-PanelDiagnostics $snapshot
Assert-Case ($tones.WebRTC -eq 'fail') 'Observed WebRTC bypass remains red'
$snapshot.DNS.System=[pscustomobject]@{state='failed'};Update-PanelDiagnostics $snapshot
Assert-Case ($tones.DNS -eq 'fail') 'Failed DNS probe remains visible'
$snapshot.DNS.System=[pscustomobject]@{state='pending'};Update-PanelDiagnostics $snapshot
Assert-Case ($tones.DNS -eq 'pending') 'Pending DNS is not shown as completed'
$detail=Get-PanelNetworkDetail ([pscustomobject]@{Browser=[pscustomobject]@{policies=@([pscustomobject]@{browser='Edge';source='HKLM';mode='secure'})};Paths=[pscustomobject]@{IPv4=[pscustomobject]@{state='denial-observed'};IPv6=[pscustomobject]@{state='inconclusive'};DeadProxy=[pscustomobject]@{state='rejected'}}})
Assert-Case ($detail.Contains($labels.browserDNSUnverified) -and $detail.Contains($labels.inconclusive)) 'Static secure DoH and unavailable IPv6 retain their limits'
function Invoke-PanelCurl { $e=[Exception]::new('Probe failed (curl 35).');$e.Data['CurlExitCode']=35;throw $e }
$unavailable=Invoke-PanelReputation '192.0.2.1'
Assert-Case ($unavailable.state -eq 'unavailable') 'TLS handshake failure describes service availability'
$dnsUnavailable=Invoke-PanelDNS $false
Assert-Case ($dnsUnavailable.state -eq 'unavailable') 'DNS result endpoint failure is not a DNS leak verdict'
$snapshot.DNS.System=$dnsUnavailable;$snapshot.DNS.Proxy=$dnsUnavailable;$snapshot.IPReputation=$unavailable;Update-PanelDiagnostics $snapshot
Assert-Case ($tones.DNS -eq 'neutral' -and $tones.Reputation -eq 'neutral' -and $controls.DNSState.Text -eq $labels.serviceUnavailable) 'Unavailable optional services stay distinct from broken protection'
Assert-Case ($controls.DNSState.ToolTip.Contains('curl 35')) 'DNS detail preserves the actual connection error'
function Invoke-PanelCurl { [pscustomobject]@{Text='{}'} }
$malformed=Invoke-PanelReputation '192.0.2.1'
Assert-Case ($malformed.state -eq 'failed') 'Invalid service data remains a failed diagnostic'
$script:metaCalls=@()
function Invoke-PanelCurl([string]$url,[bool]$direct){
 $script:metaCalls+=@([pscustomobject]@{url=$url;direct=$direct})
 if($url -like '*ipinfo*'){ $e=[Exception]::new('Probe failed (curl 35).');$e.Data['CurlExitCode']=35;throw $e }
 [pscustomobject]@{Text='{"success":true,"ip":"192.0.2.1","country_code":"US","timezone":{"id":"America/Los_Angeles"},"city":"Los Angeles"}'}
}
$meta=Invoke-PanelExitMetadata '192.0.2.1'
Assert-Case ($meta.state -eq 'observed' -and $meta.timezone -eq 'America/Los_Angeles' -and $meta.source -eq 'ipwho.is') 'Exit metadata falls back after a TLS failure'
Assert-Case ($metaCalls.Count -eq 2 -and @($metaCalls|Where-Object direct).Count -eq 0) 'Every metadata service uses the proxy route'
function Invoke-PanelCurl { [pscustomobject]@{Text='{"ip":"192.0.2.99","country":"US","country_code":"US","timezone":"America/Los_Angeles"}'} }
$meta=Invoke-PanelExitMetadata '192.0.2.1'
Assert-Case ($meta.state -ne 'observed' -and !$meta.timezone) 'Metadata from another exit cannot be reused'
function Invoke-PanelCurl { throw 'Unavailable' }
$meta=Invoke-PanelExitMetadata '192.0.2.1'
Assert-Case ($meta.state -eq 'unavailable' -and $meta.attempts.Count -eq 3) 'All unavailable services remain unverified'
$now=(Get-Date).ToString('o')
$fixture=[pscustomobject]@{Proxy=[pscustomobject]@{ip='192.0.2.1';matchesPin=$true};Environment=[pscustomobject]@{timezoneIana='America/Los_Angeles';timezoneId='Pacific Standard Time'};ExitMetadata=[pscustomobject]@{state='observed';ip='192.0.2.1';timezone='America/Los_Angeles';Time=$now};WebRTC=[pscustomobject]@{Time=$now;environment=[pscustomobject]@{timezone='America/Los_Angeles';systemTimezoneId='Pacific Standard Time'}}}
Assert-Case ((Get-PanelTimezoneVerdict $fixture) -eq 'match') 'All three measured timezone identities match'
$fixture.Environment.timezoneIana='America/Phoenix'
Assert-Case ((Get-PanelTimezoneVerdict $fixture) -eq 'mismatch') 'Arizona is not Los Angeles even at the same UTC offset'
$fixture.Environment.timezoneIana='America/Los_Angeles';$fixture.WebRTC.environment.timezone=$null
Assert-Case ((Get-PanelTimezoneVerdict $fixture) -eq 'unverified') 'Missing browser measurement never passes'
$fixture.WebRTC.environment.timezone='America/Los_Angeles';$fixture.WebRTC.Time=(Get-Date).AddMinutes(-12).ToString('o')
Assert-Case ((Get-PanelTimezoneVerdict $fixture) -eq 'unverified') 'Expired browser readings never pass'
$fixture.WebRTC.Time=$now;$fixture.ExitMetadata.ip='192.0.2.99'
Assert-Case ((Get-PanelTimezoneVerdict $fixture) -eq 'unverified') 'Old exit metadata never passes for a new exit'
$fixture.ExitMetadata.ip='192.0.2.1';$fixture.WebRTC.environment.systemTimezoneId='US Mountain Standard Time'
Assert-Case ((Get-PanelTimezoneVerdict $fixture) -eq 'unverified') 'Browser reading from before a system timezone change cannot pass'
# Reproduce domain-connect TLS EOF with a successful same-proxy IPv4 destination.
$config=[pscustomobject]@{Proxy='http://127.0.0.1:10808'}
function Get-GuardProbePath { 'owned-probe.exe' }
$script:transportCalls=@()
function Invoke-PanelCurlAttempt([string]$exe,[string[]]$arguments){
 $script:transportCalls+=@([pscustomobject]@{exe=$exe;arguments=$arguments})
 if($arguments -contains '--connect-to'){return [pscustomobject]@{ExitCode=0;Text='{"ip":"192.0.2.1"}';Milliseconds=1}}
 if($arguments[-1] -like 'https://cloudflare-dns.com/*'){return [pscustomobject]@{ExitCode=0;Text='{"Status":0,"Answer":[{"type":1,"data":"104.21.53.138"}]}';Milliseconds=1}}
 return [pscustomobject]@{ExitCode=35;Text='TLS EOF';Milliseconds=1}
}
$recovered=Invoke-PanelHttp 'https://ip.net.coffee/api/example' $false
Assert-Case ($recovered.Resolution -eq 'proxy-doh-ipv4' -and $transportCalls.Count -eq 3) 'Domain TLS failure recovers through encrypted DNS and the same proxy'
Assert-Case (@($transportCalls|Where-Object {$_.exe -ne 'owned-probe.exe' -or $_.arguments -notcontains $config.Proxy -or $_.arguments -contains '--insecure' -or $_.arguments -contains '*'}).Count -eq 0) 'Fallback never bypasses protected curl proxy or TLS validation'
Assert-Case ($transportCalls[-1].arguments -contains 'ip.net.coffee:443:104.21.53.138:443' -and $transportCalls[-1].arguments[-1] -eq 'https://ip.net.coffee/api/example') 'Retry preserves HTTPS URL and hostname while changing CONNECT destination'
$script:transportCalls=@();try{$null=Invoke-PanelHttp 'https://unique.d.ip.net.coffee/pixel.gif' $false}catch{}
Assert-Case ($transportCalls.Count -eq 1) 'DNS resolver measurement names never use the substitute resolver'
$script:transportCalls=@();try{$null=Invoke-PanelHttp 'https://claude.ai/cdn-cgi/trace' $false}catch{}
Assert-Case ($transportCalls.Count -eq 1) 'Startup trace hosts cannot use diagnostic fallback'
$script:transportCalls=@();try{$null=Invoke-PanelHttp 'https://ipinfo.io/json' $true}catch{}
Assert-Case ($transportCalls.Count -eq 1) 'Direct comparison route is never substituted'
function Invoke-PanelCurlAttempt([string]$exe,[string[]]$arguments){
 $script:transportCalls+=@([pscustomobject]@{exe=$exe;arguments=$arguments})
 if($arguments[-1] -like 'https://cloudflare-dns.com/*'){return [pscustomobject]@{ExitCode=0;Text='{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1"},{"type":1,"data":"10.0.0.1"}]}';Milliseconds=1}}
 return [pscustomobject]@{ExitCode=35;Text='TLS EOF';Milliseconds=1}
}
$script:transportCalls=@();try{$null=Invoke-PanelHttp 'https://ipinfo.io/json' $false}catch{}
Assert-Case ($transportCalls.Count -eq 2) 'Encrypted DNS cannot redirect diagnostic retries to loopback or private addresses'
$scoped=[pscustomobject]@{WebRTC=[pscustomobject]@{state='inconclusive';BrowserPath='C:\Edge\msedge.exe'};UDPProtection=[pscustomobject]@{ok=$false;programs=@([pscustomobject]@{program='C:\Edge\msedge.exe';ok=$true},[pscustomobject]@{program='C:\Codex\app.exe';ok=$false})}}
Assert-Case (Test-PanelRTCProtection $scoped) 'Isolated Edge UDP audit is independent of unrelated Codex path'
$scoped.UDPProtection.programs[0].ok=$false
Assert-Case (!(Test-PanelRTCProtection $scoped)) 'Missing rule for the actual probe browser never passes'
$scoped.UDPProtection.programs[0].ok=$true
Update-PanelDiagnostics $scoped
Assert-Case ($controls.WebRTCState.Text -eq $labels.rtcBlocked -and $tones.WebRTC -eq 'neutral') 'Actual browser block explains empty candidates without claiming leak-free pass'
$scoped|Add-Member NoteProperty DNS ([pscustomobject]@{System=[pscustomobject]@{state='observed';resolvers=@('192.0.2.1')};Proxy=[pscustomobject]@{state='inconclusive';error='DNS test-name request failed'}})
Update-PanelDiagnostics $scoped
Assert-Case ($controls.DNSState.Text -eq ($labels.dnsProxyUnobserved -f 1) -and $controls.DNSState.ToolTip.Contains('DNS test-name request failed')) 'Partial DNS measurement retains observed system result and proxy failure detail'
$script:transportCalls=@();try{$null=Invoke-PanelHttp 'https://dnsleak.dev/api/new' $false}catch{}
Assert-Case ($transportCalls[0].arguments -contains 'Accept: application/json') 'DNS API session explicitly requests JSON instead of the default plain-text test ID'
# A second authoritative service must observe the proxy's own fresh-name lookups.
$config=[pscustomobject]@{Proxy='http://127.0.0.1:10808';ExpectedIPv4='8.8.8.8'}
function Invoke-PanelCurl([string]$url,[bool]$direct){Invoke-PanelHttp $url $direct}
$script:dnsMode='ok';$script:dnsCalls=@();$script:triggerCalls=@();$script:polls=0
function Start-Sleep { param($Milliseconds,$Seconds) }
function Invoke-PanelHttp([string]$url,[bool]$direct){
 $script:dnsCalls+=@{url=$url;direct=$direct}
 if($url -eq 'https://dnsleak.dev/api/new'){
  $ip=if($script:dnsMode -eq 'wrong-exit'){'9.9.9.9'}else{'8.8.8.8'}
  $names=if($script:dnsMode -eq 'bad-host'){@('abc123-a01.evil.example','abc123-q01.t.dnsleak.dev')}else{@('abc123-a01.t.dnsleak.dev','abc123-q01.t.dnsleak.dev')}
  return [pscustomobject]@{Text=(@{testId='abc123';client=@{ip=$ip};hostnames=$names}|ConvertTo-Json -Depth 4)}
 }
 $script:polls++
 $id=if($script:dnsMode -eq 'wrong-session'){'other123'}else{'abc123'}
 $servers=if($script:dnsMode -eq 'empty' -or ($script:dnsMode -eq 'delayed' -and $script:polls -eq 1)){@()}else{@(@{ip='1.1.1.1';role='resolver';original=2;sawA=$true;sawQ=$true;countryCode='US'})}
 return [pscustomobject]@{Text=(@{testId=$id;client=@{ip='8.8.8.8'};lookups=2;resolvers=$servers}|ConvertTo-Json -Depth 5)}
}
function Invoke-PanelCurlAttempt([string]$exe,[string[]]$arguments){$script:triggerCalls+=@{exe=$exe;arguments=$arguments};[pscustomobject]@{ExitCode=60;Text='Certificate error after name lookup';Milliseconds=1}}
$measured=Invoke-PanelProxyDNSFallback
Assert-Case ($measured.state -eq 'observed' -and $measured.resolvers.Count -eq 1 -and $measured.source -eq 'dnsleak.dev') 'Independent authoritative result recovers proxy DNS despite expected probe TLS errors'
Assert-Case ($triggerCalls.Count -eq 2 -and @($triggerCalls|Where-Object {$_.exe -ne 'owned-probe.exe' -or $_.arguments -notcontains $config.Proxy -or $_.arguments -contains '--insecure' -or $_.arguments -contains '--connect-to'}).Count -eq 0) 'Fresh DNS names use exact proxy hostname requests without TLS bypass or external resolution'
Assert-Case (@($dnsCalls|Where-Object direct).Count -eq 0 -and $measured.observedA -and $measured.observedAAAA) 'Session and results use same proxy and include both query families'
$script:dnsMode='delayed';$script:polls=0
Assert-Case ((Invoke-PanelProxyDNSFallback).state -eq 'observed' -and $script:polls -eq 2) 'Delayed authoritative observations receive a bounded second poll'
$script:dnsMode='empty';$script:polls=0
Assert-Case ((Invoke-PanelProxyDNSFallback).state -eq 'inconclusive' -and $script:polls -eq 3) 'Empty authoritative results stay inconclusive after bounded polling'
foreach($mode in @('wrong-exit','bad-host','wrong-session')){
 $script:dnsMode=$mode;$script:triggerCalls=@()
 $rejected=Invoke-PanelProxyDNSFallback
 Assert-Case ($rejected.state -eq 'failed') ('Reject unrelated DNS response: '+$mode)
 if($mode -ne 'wrong-session'){Assert-Case ($triggerCalls.Count -eq 0) ('Do not trigger names before validation: '+$mode)}
}
$script:dnsMode='ok'
function Invoke-PanelCurl([string]$url,[bool]$direct){if($url -like 'https://dnsleak.dev/*'){return Invoke-PanelHttp $url $direct};[pscustomobject]@{Text='{"dns_servers":[]}'}}
$integrated=Invoke-PanelDNS $false
Assert-Case ($integrated.state -eq 'observed' -and $integrated.source -eq 'dnsleak.dev' -and $integrated.previousSource -eq 'ip.net.coffee') 'Actual panel DNS caller uses the authoritative fallback when primary observes nothing'
Write-Output ('Diagnostic tests passed: '+$count)