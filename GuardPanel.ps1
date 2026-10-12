function Invalidate-PanelLaunch {
 $script:ready=$false
 if(Get-Command Update-MainAction -ErrorAction SilentlyContinue){Update-MainAction}else{$controls.StartButton.IsEnabled=$false}
}
$script:PanelRefreshPath=$null;$script:PanelProcess=$null;$script:PanelSnapshot=$null;$script:PanelSeen='';$script:PanelStopPath=$null;$script:PanelSnapshotPath=$null
function Get-MaskedPanelIP([string]$ip){
 if(!$ip){return [string][char]0x2014}
 if($controls.HideIP.IsChecked -and $ip -match '^(\d+\.\d+)\.\d+\.\d+$'){return $matches[1]+'.*.*'}
 return $ip
}
function Update-PanelIPs {
 $controls.DirectIpText.Text=Get-MaskedPanelIP $script:PanelSnapshot.Direct.ip
 $controls.IpText.Text=Get-MaskedPanelIP $script:PanelSnapshot.Proxy.ip
}
function Get-PanelCountry([string]$code){
 switch($code){'CN'{return $labels.countryCN};'TW'{return $labels.countryTW};'US'{return $labels.countryUS};'JP'{return $labels.countryJP};default{if($code){return $code}else{return $labels.notTested}}}
}
function Start-PanelWorker {
 if($script:PanelProcess -and !$script:PanelProcess.HasExited){return}
 $id=[guid]::NewGuid().ToString('N')
 $script:PanelSnapshotPath=Join-Path $root ('.state\panel-'+$id+'.json')
 $script:PanelStopPath=Join-Path $root ('.state\panel-'+$id+'.stop')
 $script:PanelRefreshPath=Join-Path $root ('.state\panel-'+$id+'.refresh')
 $args='-NoProfile -File "'+(Join-Path $root 'Get-PanelSnapshot.ps1')+'" -SnapshotPath "'+$script:PanelSnapshotPath+'" -StopPath "'+$script:PanelStopPath+'" -RefreshPath "'+$script:PanelRefreshPath+'"'
 $script:PanelProcess=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $args -WindowStyle Hidden -RedirectStandardOutput (Join-Path $root ('.state\panel-'+$id+'.log')) -RedirectStandardError (Join-Path $root ('.state\panel-'+$id+'.err')) -PassThru
}
function Stop-PanelWorker {
 if($script:PanelStopPath){[IO.File]::WriteAllText($script:PanelStopPath,'stop')}
}
function Request-PanelRefresh {
 if($script:PanelRefreshPath){[IO.File]::WriteAllText($script:PanelRefreshPath,'refresh',[Text.UTF8Encoding]::new($false))}
}
function Get-PanelDiagnosticDetail($value,[string]$scope) {
 $detail=$scope
 if($value.System){$detail+="`n"+($labels.dnsSystemDetail -f (@($value.System.resolvers) -join ', '))+"`n"+($labels.dnsProxyDetail -f (@($value.Proxy.resolvers) -join ', '))}
 elseif($value.publicIPs){$detail+="`n"+($labels.rtcAddressesDetail -f (@($value.publicIPs) -join ', '))}
 elseif($value.cidr){$detail+="`n"+($labels.reputationNetworkDetail -f $value.cidr)+"`n"+($labels.reputationKindDetail -f $value.category)}
 if($value.Proxy.source){$detail+="`n"+($labels.dnsSourceDetail -f $value.Proxy.source)}
 if($value.Proxy.requestedLookups){$detail+="`n"+($labels.dnsCoverageDetail -f $value.Proxy.lookups,$value.Proxy.requestedLookups)}
 foreach($entry in @($value.System,$value.Proxy)){if($entry.error){$detail+="`n"+$entry.scope+': '+$entry.error}}
 if($value.Time){$detail+="`n"+$labels.updated+([datetimeoffset]$value.Time).ToLocalTime().ToString('HH:mm:ss')}
 if($value.error){$detail+="`n"+$labels.diagnosticErrorDetail+$value.error}
 if($controls.HideIP.IsChecked){$detail=[regex]::Replace($detail,'\b(\d{1,3}\.\d{1,3})\.\d{1,3}\.\d{1,3}\b','$1.*.*')}
 return $detail
}
function Get-PanelNetworkDetail($dns) {
 $detail="`n"+$labels.browserDNSUnverified
 foreach($entry in @($dns.Browser.policies)){
  if(!$entry){continue}
  $mode=if($entry.state -eq 'unreadable'){$labels.probeFailed}elseif($entry.mode){$entry.mode}else{$labels.noPolicy}
  if($entry.templateConfigured){$mode+=' / '+$labels.dohTemplateConfigured}
  $detail+="`n"+$entry.browser+' / '+$entry.source+': '+$mode
 }
 if($dns.Paths){
  $detail+="`n"+$labels.pathScope
  foreach($item in @(@('IPv4',$dns.Paths.IPv4),@('IPv6',$dns.Paths.IPv6),@($labels.deadProxy,$dns.Paths.DeadProxy))){
   $state=switch($item[1].state){'denial-observed'{$labels.directDenied};'rejected'{$labels.proxyRejected};'warning'{$labels.pathBypass};default{$labels.inconclusive}}
   $detail+="`n"+$item[0]+': '+$state
  }
  if($dns.Paths.error){$detail+="`n"+$dns.Paths.error}
 }
 return $detail
}
function Test-PanelRTCProtection($snapshot) {
 $entries=@($snapshot.UDPProtection.programs)
 if($snapshot.WebRTC.BrowserPath){return @($entries|Where-Object {$_.program -ieq $snapshot.WebRTC.BrowserPath -and $_.ok}).Count -eq 1}
 # Compatibility with snapshots predating per-program results.
 return (!$snapshot.UDPProtection.programs -and [bool]$snapshot.UDPProtection.ok)
}
function Update-PanelDiagnostics($snapshot) {
 $rtcProtected=Test-PanelRTCProtection $snapshot
 $dns=$snapshot.DNS
 $controls.DNSState.Text=$labels.notTested
 if($dns.System -and $dns.Proxy){
  if($dns.System.state -eq 'pending' -or $dns.Proxy.state -eq 'pending'){$controls.DNSState.Text=$labels.checkActive}
  elseif($dns.System.state -eq 'observed' -and $dns.Proxy.state -eq 'observed'){$controls.DNSState.Text=($labels.dnsObserved -f @($dns.System.resolvers).Count,@($dns.Proxy.resolvers).Count)}
  elseif($dns.System.state -eq 'observed' -and $dns.Proxy.state -eq 'inconclusive'){$controls.DNSState.Text=($labels.dnsProxyUnobserved -f @($dns.System.resolvers).Count)}
  elseif($dns.System.state -eq 'failed' -or $dns.Proxy.state -eq 'failed'){$controls.DNSState.Text=$labels.probeFailed}
  elseif($dns.System.state -eq 'unavailable' -or $dns.Proxy.state -eq 'unavailable'){$controls.DNSState.Text=$labels.serviceUnavailable}
  else{$controls.DNSState.Text=$labels.inconclusive}
 }
 $rtc=$snapshot.WebRTC
 $controls.WebRTCState.Text=switch($rtc.state){'pending'{$labels.checkActive};'warning'{$labels.rtcBypass};'observed-match'{$labels.rtcMatch};'inconclusive'{$labels.inconclusive};'failed'{$labels.probeFailed};default{$labels.notTested}}
 if($rtcProtected -and $rtc.state -eq 'inconclusive'){$controls.WebRTCState.Text=$labels.rtcBlocked}
 $risk=$snapshot.IPReputation
 $controls.ReputationState.Text=switch($risk.state){'pending'{$labels.checkActive};'observed'{($labels.reputationObserved -f $risk.score)};'unavailable'{$labels.serviceUnavailable};'failed'{$labels.probeFailed};default{$labels.noResult}}
 $dnsTone=if($controls.DNSState.Text -eq $labels.probeFailed){'fail'}elseif($controls.DNSState.Text -eq $labels.checkActive){'pending'}else{'neutral'}
 $rtcTone=if($rtc.state -in @('warning','failed')){'fail'}elseif($rtc.state -eq 'observed-match' -and $rtcProtected){'pass'}elseif($rtc.state -eq 'pending'){'pending'}else{'neutral'}
 $riskTone=if($risk.state -eq 'failed'){'fail'}elseif($risk.state -eq 'pending'){'pending'}else{'neutral'}
 foreach($row in @(@('DNS',$dnsTone),@('WebRTC',$rtcTone),@('Reputation',$riskTone))){
  $name=$row[0];$tone=$row[1];Set-PanelTone $name $tone
  $controls[$name+'Mark'].Text=switch($tone){'fail'{'!'}'pass'{[string][char]0x2713}'pending'{[string][char]0x25CB}default{[string][char]0x00B7}}
 }
 $controls.DNSState.ToolTip=(Get-PanelDiagnosticDetail $dns $labels.dnsScope)+(Get-PanelNetworkDetail $dns)
 $controls.WebRTCState.ToolTip=(Get-PanelDiagnosticDetail $rtc $labels.webRTCScope)+"`n"+$(if($rtcProtected){$labels.udpRuleVerified}else{$labels.udpRuleMissing})
 $controls.ReputationState.ToolTip=Get-PanelDiagnosticDetail $risk $labels.reputationScope
}
function Get-PanelTimezoneVerdict($snapshot) {
 $system=$snapshot.Environment;$browser=$snapshot.WebRTC;$exit=$snapshot.ExitMetadata
 if(!$snapshot.Proxy.matchesPin -or $exit.state -ne 'observed' -or $exit.ip -ne $snapshot.Proxy.ip){return 'unverified'}
 if(!$system.timezoneIana -or !$browser.environment.timezone -or !$exit.timezone -or $browser.environment.systemTimezoneId -ne $system.timezoneId){return 'unverified'}
 foreach($item in @($browser,$exit)){
  try{$age=([datetimeoffset]::Now-[datetimeoffset]$item.Time).TotalSeconds;if(!$item.Time -or $age -lt -30 -or $age -gt 660){return 'unverified'}}catch{return 'unverified'}
 }
 if($system.timezoneIana -ceq $browser.environment.timezone -and $system.timezoneIana -ceq $exit.timezone){return 'match'}
 return 'mismatch'
}
function Update-PanelTimezones($snapshot) {
 $verdict=Get-PanelTimezoneVerdict $snapshot
 $controls.TimezoneState.Text=if($snapshot.Environment.timezoneIana){$snapshot.Environment.timezoneIana}elseif($snapshot.Environment.timezone){$snapshot.Environment.timezone}else{$labels.notTested}
 $browserZone=$snapshot.WebRTC.environment.timezone
 $metadata=$snapshot.ExitMetadata
 $controls.BrowserTimezoneState.Text=if($browserZone){$browserZone}else{$labels.notTested}
 $controls.ExitTimezoneState.Text=if($metadata.state -eq 'observed' -and $metadata.ip -eq $snapshot.Proxy.ip){$metadata.timezone}elseif($metadata.state -eq 'pending'){$labels.checkActive}elseif($metadata.state -eq 'unavailable'){$labels.serviceUnavailable}else{$labels.notTested}
 $tone=switch($verdict){'match'{'pass'}'mismatch'{'fail'}default{'neutral'}}
 $summary=switch($verdict){'match'{$labels.timezoneMatch}'mismatch'{$labels.timezoneMismatch}default{$labels.timezoneUnverified}}
 foreach($name in @('Timezone','BrowserTimezone','ExitTimezone')){Set-PanelTone $name $tone}
 $controls.TimezoneState.ToolTip=$summary+"`n"+$snapshot.Environment.timezone+"`n"+$labels.timezoneScope
 $controls.BrowserTimezoneState.ToolTip=$summary+"`n"+$labels.browserTimezoneScope+$(if($snapshot.WebRTC.Time){"`n"+$labels.updated+([datetimeoffset]$snapshot.WebRTC.Time).ToLocalTime().ToString('HH:mm:ss')})
 $controls.ExitTimezoneState.ToolTip=$summary+"`n"+(Get-PanelDiagnosticDetail $metadata $labels.exitTimezoneScope)+$(if($metadata.source){"`n"+$metadata.source})
}
function Apply-PanelSnapshot($snapshot) {
 $script:PanelSnapshot=$snapshot
 $egressTime=if($snapshot.Proxy.Time){[datetimeoffset]$snapshot.Proxy.Time}else{[datetimeoffset]$snapshot.Time}
 $udpTime=if($snapshot.UDPProtection.Time){[datetimeoffset]$snapshot.UDPProtection.Time}else{[datetimeoffset]$snapshot.Time}
 $olderEgress=($script:LastGuardVerifiedTime -and $egressTime -lt $script:LastGuardVerifiedTime)
 $olderUDP=($script:LastGuardVerifiedTime -and $udpTime -lt $script:LastGuardVerifiedTime)
 $olderThanGuard=($script:LastGuardVerifiedTime -and [datetimeoffset]$snapshot.Time -lt $script:LastGuardVerifiedTime)
 Update-PanelIPs
 $controls.DirectCountryText.Text=if($snapshot.Direct.ok){(Get-PanelCountry $snapshot.Direct.country)+$(if($snapshot.Direct.city){' - '+$snapshot.Direct.city}else{''})}else{$labels.probeFailed}
 $controls.CountryText.Text=if($snapshot.Proxy.ip){Get-PanelCountry $snapshot.Proxy.country}else{$labels.probeFailed}
 $controls.ProxyLatencyText.Text=if($snapshot.Proxy.milliseconds){[string]$snapshot.Proxy.milliseconds+' ms'}else{''}
 $controls.DirectCountryText.ToolTip=$snapshot.Direct.source
 $controls.CountryText.ToolTip=($snapshot.Proxy.domains|ConvertTo-Json -Depth 4)
 $controls.ClaudeReachState.Text=if($snapshot.Proxy.matchesPin){$labels.egressApproved}elseif($snapshot.Proxy.ok){$labels.egressChanged}else{$labels.probeFailed}
 Set-ThemeBrush $controls.ClaudeReachState Foreground $(if($snapshot.Proxy.matchesPin){'#62DB98'}else{'#FF757C'})
 $controls.ClaudeReachMark.Text=if($snapshot.Proxy.matchesPin){[string][char]0x2713}else{'!'}
 $controls.ClaudeReachMark.Foreground=$controls.ClaudeReachState.Foreground
 if($olderEgress -and !$snapshot.Proxy.matchesPin){
  $controls.ClaudeReachState.Text=$labels.olderProbeFailed;$controls.ClaudeReachMark.Text=[string][char]0x25CB
  Set-ThemeBrush $controls.ClaudeReachState Foreground '#A2A9AF';$controls.ClaudeReachMark.Foreground=$controls.ClaudeReachState.Foreground
 }
 Set-PanelTone 'ClaudeReach' $(if($olderEgress -and !$snapshot.Proxy.matchesPin){'neutral'}elseif($snapshot.Proxy.matchesPin){'pass'}else{'fail'})
 Update-PanelDiagnostics $snapshot
 Update-PanelTimezones $snapshot
 $controls.LanguageState.Text=if($snapshot.Environment.language){$snapshot.Environment.language.Replace(' (override)','').Replace(' (preference)','').Replace(' (process)','')}else{$labels.notTested}
 $controls.LanguageState.ToolTip=$snapshot.Environment.language+"`n"+$labels.regionalFormat+": "+$snapshot.Environment.regionalFormat
 $controls.LocationState.Text=switch($snapshot.Environment.location){'Allow'{$labels.locationAllowed};'Deny'{$labels.locationDenied};default{$labels.notTested}}
 Set-PanelTone 'Location' $(switch($snapshot.Environment.location){'Allow'{'fail'}'Deny'{'pass'}default{'neutral'}})
 $controls.LocationState.ToolTip=$labels.locationScope+' / '+$snapshot.Environment.locationService
 $displayTime=if($olderThanGuard){$script:LastGuardVerifiedTime}else{[datetimeoffset]$snapshot.Time}
 $controls.LastChecked.Text=$labels.updated+$displayTime.ToLocalTime().ToString('HH:mm:ss')
 if((!$olderEgress -and !$snapshot.Proxy.matchesPin) -or (!$olderUDP -and $config.RequireBrowserUDP -and !$snapshot.UDPProtection.ok)){
  Invalidate-PanelLaunch
  if(!$script:backend -and $script:lastPhase -notin @('blocked','stopped')){$controls.StatusText.Text=$labels.blocked;$controls.StageText.Text=if(!$snapshot.Proxy.matchesPin){$labels.monitorEgressFailed}else{$labels.udpRuleMissing};Set-UIPresentation 'blocked';$controls.FooterStatus.Text=$labels.footerBlocked}
 }elseif(!$script:backend -and $script:lastPhase -notin @('blocked','stopped')){
  if($script:ready){
   $controls.StatusText.Text=$labels.ready;$controls.StageText.Text=$labels.diagnosticsSeparate;Set-UIPresentation 'ready'
  }else{
   $controls.StatusText.Text=$labels.monitorPartial;$controls.StageText.Text=$labels.monitorPartialHint
   Set-ThemeBrush $controls.StatusText Foreground '#E7E9EA';$controls.StatusGlyph.Text='?';Set-ThemeBrush $controls.StatusGlyph Foreground '#D3AE67';Set-ThemeBrush $controls.StatusIconBackground Background '#272D32'
  }
 }
 if($snapshot.DNS.Paths.state -eq 'warning'){
  Invalidate-PanelLaunch
  $controls.ClaudeReachState.Text=$labels.networkPathWarning;$controls.ClaudeReachMark.Text='!';Set-PanelTone 'ClaudeReach' 'fail'
  $controls.StatusText.Text=$labels.blocked;$controls.StageText.Text=$labels.networkPathWarning;Set-UIPresentation 'blocked';$controls.FooterStatus.Text=$labels.footerBlocked
 }
 if($snapshot.Components -and !$snapshot.Components.ok -and (!$script:LastGuardVerifiedTime -or [datetimeoffset]$snapshot.Components.Time -ge $script:LastGuardVerifiedTime)){
  Invalidate-PanelLaunch
  $controls.StatusText.Text=$labels.blocked;$controls.StageText.Text=$labels.componentsChanged;Set-UIPresentation 'blocked'
  $controls.ComponentState.Text=$labels.componentsChanged;$controls.ComponentMark.Text='!';Set-PanelTone 'Component' 'fail'
  $controls.Details.Text=$snapshot.Components.error;$controls.FooterStatus.Text=$labels.footerBlocked
 }
}
function Poll-PanelWorker {
 if(!$script:PanelProcess){return}
 if($script:PanelSnapshotPath -and (Test-Path -LiteralPath $script:PanelSnapshotPath)){
  try {
   $snapshot=Get-Content -LiteralPath $script:PanelSnapshotPath -Raw -Encoding UTF8|ConvertFrom-Json
   if($snapshot.WorkerPid -eq $script:PanelProcess.Id -and $snapshot.Time -ne $script:PanelSeen){$script:PanelSeen=$snapshot.Time;Apply-PanelSnapshot $snapshot}
  }catch{}
 }
 if($script:PanelProcess.HasExited -or ($script:PanelSnapshot -and ([datetimeoffset]::Now-[datetimeoffset]$script:PanelSnapshot.Time).TotalSeconds -gt 90)){
  $controls.ClaudeReachState.Text=$labels.monitorStale;$controls.ClaudeReachMark.Text='!'
  Set-ThemeBrush $controls.ClaudeReachState Foreground '#FF757C'
  Set-PanelTone 'ClaudeReach' 'fail';$controls.ClaudeReachMark.Foreground=$controls.ClaudeReachState.Foreground
  $controls.IpText.Text=[string][char]0x2014;$controls.ProxyLatencyText.Text='';$controls.CountryText.Text=$labels.monitorStale
  Invalidate-PanelLaunch
  foreach($name in @('Timezone','BrowserTimezone','ExitTimezone')){Set-PanelTone $name 'neutral'}
  $controls.TimezoneState.ToolTip=$labels.monitorStale
 }
}