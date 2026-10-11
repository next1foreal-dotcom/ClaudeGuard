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
Write-Output ('Diagnostic tests passed: '+$count)