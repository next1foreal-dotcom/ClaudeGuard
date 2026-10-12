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
Write-Output ('Diagnostic tests passed: '+$count)