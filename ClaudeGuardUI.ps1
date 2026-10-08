param([switch]$RenderPreview,[switch]$UiSmokeTest,[switch]$Reconfigure,[int]$PreviewWidth=480,[int]$PreviewHeight=720,[string]$TestConfigPath)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
$root=$PSScriptRoot
$labels=Get-Content -LiteralPath (Join-Path $root 'ui-zh.json') -Raw -Encoding UTF8|ConvertFrom-Json
if(!$UiSmokeTest -and !$RenderPreview){
 . (Join-Path $root 'GuardSetupCore.ps1')
 if($Reconfigure -or (Test-SetupRequired)){
  & (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -STA -File (Join-Path $root 'GuardSetupUI.ps1') -Standalone
  if($LASTEXITCODE -ne 0){exit 0}
 }
}
if($TestConfigPath -and !$UiSmokeTest){throw 'Fixture configuration is only accepted for UI tests.'}
$config=Get-Content -LiteralPath $(if($TestConfigPath){$TestConfigPath}else{Join-Path $root 'guard-config.json'}) -Raw -Encoding UTF8|ConvertFrom-Json
$xml=[xml][IO.File]::ReadAllText((Join-Path $root 'ClaudeGuard.xaml'))
$reader=New-Object Xml.XmlNodeReader $xml
$window=[Windows.Markup.XamlReader]::Load($reader)
$controls=@{}
foreach($name in 'StatusText','StageText','Progress','IpText','CoverageText','ChecksText','LastChecked','Details','HideIP','ClientChoice','InstallButton','CheckButton','StartButton','WindowTopmost','CloseButton','StatusGlyph','StatusIconBackground','FooterStatus','FooterDot','CountryText','ComponentState','ComponentMark','FirewallState','FirewallMark','RoutingState','RoutingMark','EgressState','EgressMark','DirectIpText','DirectCountryText','ProxyLatencyText','ClaudeReachState','ClaudeReachMark','DNSState','DNSMark','WebRTCState','WebRTCMark','ReputationState','ReputationMark','TimezoneState','LanguageState','LocationState'){$controls[$name]=$window.FindName($name)}
$script:LastGuardVerifiedTime=$null;$script:backend=$null;$script:mode='';$script:statePath=$null;$script:stopPath=$null;$script:seenTime='';$script:ready=$false;$script:lastPhase='unknown';$script:UIBusy=$false;$script:StopRequested=$false
. (Join-Path $root 'GuardTheme.ps1')
Restore-PanelTheme
. (Join-Path $root 'GuardPresentation.ps1')
. (Join-Path $root 'GuardPanel.ps1')
. (Join-Path $root 'GuardWindowLayout.ps1')
if($UiSmokeTest){$script:PanelSnapshot=[pscustomobject]@{Direct=[pscustomobject]@{ip='192.0.2.7'};Proxy=[pscustomobject]@{ip=$config.ExpectedIPv4}}}
function Refresh-IP {Update-PanelIPs;if($script:PanelSnapshot){Update-PanelDiagnostics $script:PanelSnapshot}}
function Update-MainAction {
 $stopping=($script:UIBusy -and $script:mode -eq 'Launch')
 $button=$controls.StartButton;$caption=$window.FindName('LaunchLabel')
 if($stopping){
  $caption.Text=if($script:StopRequested){$labels.stoppingSession}else{$labels.stopSession}
  Set-GuardActionIcon $button ($window.FindName('LaunchIcon')) 'square'
  Set-ThemeBrush $button Foreground '#FF757C';Set-ThemeBrush $button Background '#45262B'
  $button.IsEnabled=!$script:StopRequested
 }else{
  $caption.Text=$labels.launchPrefix+$(if($config.SchemaVersion -ge 3){[string]$config.Clients[$controls.ClientChoice.SelectedIndex].Name}else{'Claude'})
  Set-GuardActionIcon $button ($window.FindName('LaunchIcon')) 'play'
  Set-ThemeBrush $button Foreground '#68DA9C';Set-ThemeBrush $button Background '#183127'
  $button.IsEnabled=(!$script:UIBusy -and $script:ready)
 }
 [Windows.Automation.AutomationProperties]::SetName($button,$caption.Text)
 $button.ToolTip=if($stopping){$labels.stopSession}else{$labels.launchProtected}
}
function Request-ManagedStop {
 if(!$script:UIBusy -or $script:mode -ne 'Launch' -or !$script:stopPath -or $script:StopRequested){return}
 [IO.File]::WriteAllText($script:stopPath,'stop',[Text.UTF8Encoding]::new($false))
 $script:StopRequested=$true;$controls.StageText.Text=$labels.stopHint;Update-MainAction
}
function Set-Busy([bool]$busy) {
 $script:UIBusy=$busy
 $controls.CheckButton.IsEnabled=!$busy;$controls.InstallButton.IsEnabled=!$busy;$controls.ClientChoice.IsEnabled=!$busy;$modeCode.IsEnabled=!$busy;$modeDesktop.IsEnabled=!$busy
 Update-MainAction

 $controls.Progress.Visibility=if($busy -and $script:lastPhase -ne 'running'){'Visible'}else{'Collapsed'}
}
function Begin-Backend([string]$mode) {
 if($script:backend -and !$script:backend.HasExited){return}
 $script:mode=$mode;$script:ready=$false;$script:StopRequested=$false;$script:lastPhase='checking';$script:seenTime=''
 $id=[guid]::NewGuid().ToString('N')
 $script:statePath=Join-Path $root ('.state\ui-'+$id+'.json')
 $script:stopPath=Join-Path $root ('.state\stop-'+$id+'.signal')
 $client=if($config.SchemaVersion -ge 3){[string]$config.Clients[$controls.ClientChoice.SelectedIndex].Kind}elseif($controls.ClientChoice.SelectedIndex -eq 0){'Code'}else{'Desktop'}
 $controls.StatusText.Text=if($mode -eq 'Install'){$labels.installing}else{$labels.checking}
 $controls.StageText.Text=$labels.checkingHint;$controls.ChecksText.Text=$labels.checksPending;$controls.CoverageText.Text=$labels.coverageChecking;$controls.Details.Text='';Set-UIPresentation 'checking'
 $arguments='-NoProfile -File "'+(Join-Path $root 'ClaudeGuard.ps1')+'" -Mode '+$mode+' -Client '+$client+' -StatusFile "'+$script:statePath+'" -StopFile "'+$script:stopPath+'"'
 $out=Join-Path $root ('.state\ui-'+$id+'.log');$err=Join-Path $root ('.state\ui-'+$id+'.err')
 try {$script:backend=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -WorkingDirectory (Get-Location).Path -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru;$null=$script:backend.Handle;Set-Busy $true}
 catch {$script:lastPhase='blocked';Set-UIPresentation 'blocked';$controls.StatusText.Text=$labels.blocked;$controls.Details.Text=$_.Exception.Message;Set-Busy $false}
}
$modeCode=$window.FindName('ModeCode');$modeDesktop=$window.FindName('ModeDesktop')
$modeCode.Add_Checked({if($config.SchemaVersion -ge 3){return};$controls.ClientChoice.SelectedIndex=0})
$modeDesktop.Add_Checked({if($config.SchemaVersion -ge 3){return};$controls.ClientChoice.SelectedIndex=1})
$controls.ClientChoice.Add_SelectionChanged({if($config.SchemaVersion -ge 3){Update-ClientCaption;return};if($controls.ClientChoice.SelectedIndex -eq 0){$modeCode.IsChecked=$true}else{$modeDesktop.IsChecked=$true}})
function Update-ClientCaption {
 if($config.SchemaVersion -lt 3){return}
 $index=$controls.ClientChoice.SelectedIndex
 if($index -ge 0 -and $index -lt @($config.Clients).Count){Update-MainAction}
}
if($config.SchemaVersion -ge 3){
 $modeCode.Visibility='Collapsed';$modeDesktop.Visibility='Collapsed';if($window.FindName('ExitTitle')){$window.FindName('ExitTitle').Text=$labels.protectedExit};if($window.FindName('ReachTitle')){$window.FindName('ReachTitle').Text=$labels.protectedReach}
 $choice=$controls.ClientChoice;$parent=$choice.Parent;$parent.Children.Remove($choice)
 $modeCode.Parent.Children.Insert(0,$choice);$choice.Visibility='Visible';[System.Windows.Shell.WindowChrome]::SetIsHitTestVisibleInChrome($choice,$true);$choice.Width=160;$choice.Height=34;$choice.Items.Clear()
 foreach($client in @($config.Clients)){$choice.Items.Add([string]$client.Name)|Out-Null};$choice.SelectedIndex=0;Update-ClientCaption
}
$window.Add_SourceInitialized({
 $result=[ordered]@{Time=(Get-Date).ToString('o');UIProcessId=$PID;Requested='Per-pixel transparent surface';AcrylicEnabled=$false;Enabled=$false;Error=$null}
 try {
  if(!('ClaudeGuardBackdrop' -as [type])){ $previousLib=$env:LIB;try{$env:LIB=$null;Add-Type -Path (Join-Path $root 'ClaudeGuardBackdrop.cs')}finally{$env:LIB=$previousLib} }
  $handle=[Windows.Interop.WindowInteropHelper]::new($window).Handle
  $native=[ClaudeGuardBackdrop]::Apply($handle)
  $result.SetHResult=$native[0];$result.ReadHResult=$native[1];$result.ObservedBackdrop=$native[2];$result.FrameHResult=$native[3];$result.CompositionEnabled=($native[4] -eq 1)
  $transparency=(Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' -Name EnableTransparency -ErrorAction SilentlyContinue).EnableTransparency
  $result.SystemTransparency=($transparency -eq 1)
    $surfaceMode=[ClaudeGuardBackdrop]::InspectSurfaceMode($handle)
  $result.PerPixelTransparency=($surfaceMode[2] -eq 1)
  $result.Enabled=($native[0] -eq 0 -and $native[1] -eq 0 -and $native[2] -eq 1 -and $result.PerPixelTransparency)
  if($result.Enabled){
   $source=[Windows.Interop.HwndSource]::FromHwnd($handle);$source.CompositionTarget.BackgroundColor=[Windows.Media.Colors]::Transparent
   $window.Background=[Windows.Media.Brushes]::Transparent

  }else{$window.Background=[Windows.Media.Brushes]::Transparent}
 }catch{$result.Error=$_.Exception.Message;$window.Background=[Windows.Media.Brushes]::Transparent}
 [IO.File]::WriteAllText((Join-Path $root '.state\popup-backdrop.json'),($result|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
 Sync-WindowCorners
 $source=[Windows.Interop.HwndSource]::FromHwnd([Windows.Interop.WindowInteropHelper]::new($window).Handle)
 $script:CornerDpiHook=[Windows.Interop.HwndSourceHook]{param($hwnd,$message,$wParam,$lParam,[ref]$handled)
  if($message -eq 0x02E0){$null=$window.Dispatcher.BeginInvoke([Action]{Sync-WindowCorners})}
  return [IntPtr]::Zero
 }
 $source.AddHook($script:CornerDpiHook)
})
$window.FindName('ThemeButton').Add_Click({Set-PanelTheme $(if($script:PanelTheme -eq 'Dark'){'Light'}else{'Dark'}) -Persist:( !$UiSmokeTest -and !$RenderPreview)})
$window.FindName('CompactButton').Add_Click({Toggle-PanelWidget})
$window.Add_SizeChanged({param($sender,$e)
 if($window.WindowState -ne 'Minimized'){
  Update-AdaptiveWindowLayout $e.NewSize.Width $e.NewSize.Height
  Sync-WindowCorners
  if(!$UiSmokeTest -and !$RenderPreview){
   $live=[ordered]@{UIProcessId=$PID;Time=(Get-Date).ToString('o');Width=$e.NewSize.Width;Height=$e.NewSize.Height;Mode=$script:AdaptiveMode;EnvironmentExpanded=$window.FindName('EnvironmentDisclosure').IsExpanded}
   [IO.File]::WriteAllText((Join-Path $root '.state\ui-layout-current.json'),($live|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
  }
 }
})
$window.Add_StateChanged({Sync-WindowCorners})


$controls.CloseButton.Add_Click({$window.Close()})
$controls.WindowTopmost.Add_Checked({$window.Topmost=$true;Set-GuardButtonIcon $controls.WindowTopmost 'pin'})
$controls.WindowTopmost.Add_Unchecked({$window.Topmost=$false;Set-GuardButtonIcon $controls.WindowTopmost 'pin-off'})
$controls.HideIP.Add_Checked({Refresh-IP})
$controls.HideIP.Add_Unchecked({Refresh-IP})
$controls.CheckButton.Add_Click({Request-PanelRefresh;Begin-Backend 'Check'})
$settingsMenu=[Windows.Controls.ContextMenu]::new();$settingsMenu.SetResourceReference([Windows.Controls.Control]::BackgroundProperty,'Ink_1D2124');$settingsMenu.SetResourceReference([Windows.Controls.Control]::ForegroundProperty,'Ink_E7E9EA')
$updateItem=[Windows.Controls.MenuItem]::new();$updateItem.Header=$labels.updateProtection;$updateItem.Add_Click({Begin-Backend 'Install'})
$setupItem=[Windows.Controls.MenuItem]::new();$setupItem.Header=$labels.configureProtection
$setupItem.Add_Click({
 if($script:backend -and !$script:backend.HasExited){return}
 $arguments='-NoProfile -STA -File "'+(Join-Path $root 'ClaudeGuardUI.ps1')+'" -Reconfigure'
 Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -WindowStyle Hidden|Out-Null
 $window.Close()
})
$updateItem.Icon=New-GuardIcon 'shield-check' 16 $updateItem;$setupItem.Icon=New-GuardIcon 'sliders-horizontal' 16 $setupItem
$minimizeItem=[Windows.Controls.MenuItem]::new();$minimizeItem.Header=$labels.minimizeWindow;$minimizeItem.Icon=New-GuardIcon 'minus' 16 $minimizeItem;$minimizeItem.Add_Click({$window.WindowState='Minimized'})
$settingsMenu.Items.Add($updateItem)|Out-Null;$settingsMenu.Items.Add($setupItem)|Out-Null
$settingsMenu.Items.Add([Windows.Controls.Separator]::new())|Out-Null;$settingsMenu.Items.Add($minimizeItem)|Out-Null
$controls.InstallButton.ContextMenu=$settingsMenu
$controls.InstallButton.Add_Click({$settingsMenu.PlacementTarget=$controls.InstallButton;$settingsMenu.IsOpen=$true})
$controls.StartButton.Add_Click({if($script:UIBusy -and $script:mode -eq 'Launch'){Request-ManagedStop}elseif(!$script:UIBusy -and $script:ready){Begin-Backend 'Launch'}})

$timer=New-Object Windows.Threading.DispatcherTimer
$timer.Interval=[TimeSpan]::FromMilliseconds(500)
$timer.Add_Tick({
 Poll-PanelWorker
 if(!$script:backend){return}
 if($script:statePath -and (Test-Path -LiteralPath $script:statePath)){
  try {$state=Get-Content -LiteralPath $script:statePath -Raw -Encoding UTF8|ConvertFrom-Json
   if($state.MonitorPid -eq $script:backend.Id -and $state.Time -ne $script:seenTime){
    $script:seenTime=$state.Time;$script:lastPhase=$state.Phase;Set-UIPresentation $state.Phase
    if($state.Phase -in @('ready','running')){$script:LastGuardVerifiedTime=[datetimeoffset]$state.Time}
    $phaseKey=$state.Phase.Replace('-','_')
    $controls.LastChecked.Text=$labels.last+([datetimeoffset]$state.Time).ToLocalTime().ToString('HH:mm:ss')
    $controls.Details.Text=$state.Detail
    switch($state.Phase){
     'ready' {$controls.StatusText.Text=$labels.ready;$controls.StageText.Text=$labels.readyHint;$controls.ChecksText.Text=$labels.checksPass;$controls.CoverageText.Text=[string]$state.ProtectedPrograms+$labels.coverage}
     'running' {$controls.StatusText.Text=$labels.running;$controls.StageText.Text=$labels.runningHint;$controls.ChecksText.Text=$labels.checksPass;$controls.CoverageText.Text=[string]$state.ProtectedPrograms+$labels.coverage;$controls.Progress.Visibility='Collapsed'}
     'blocked' {$controls.StatusText.Text=$labels.blocked;$controls.StageText.Text=$labels.stoppedHint;$script:ready=$false}
     'stopped' {$controls.StatusText.Text=$labels.stopped;$controls.StageText.Text=$labels.stoppedHint;$script:ready=$false}
     default {$controls.StatusText.Text=$labels.checking;if($labels.$phaseKey){$controls.StageText.Text=$labels.$phaseKey}}
    }
   }
  }catch{}
 }
 if($script:backend.HasExited){
  $script:backend.WaitForExit();$script:LastBackendExitCode=$script:backend.ExitCode
  if($script:mode -eq 'Install'){$controls.StatusText.Text=if($script:backend.ExitCode -eq 0){$labels.installDone}else{$labels.blocked};$script:ready=$false}
  elseif($script:mode -eq 'Check' -and $script:backend.ExitCode -eq 0 -and $script:lastPhase -eq 'ready'){$script:ready=$true}
  elseif($script:lastPhase -notin @('blocked','stopped')){$controls.StatusText.Text=$labels.blocked;$controls.StageText.Text=$labels.exitHint;$script:ready=$false;$script:lastPhase='blocked';Set-UIPresentation 'blocked'}
  [IO.File]::WriteAllText((Join-Path $root '.state\ui-last-backend.json'),([pscustomobject]@{Time=(Get-Date).ToString('o');Mode=$script:mode;ExitCode=$script:LastBackendExitCode;Phase=$script:lastPhase;Ready=$script:ready}|ConvertTo-Json),[Text.UTF8Encoding]::new($false));Set-Busy $false;$script:backend=$null; if($script:PanelSnapshot){Apply-PanelSnapshot $script:PanelSnapshot}
 }
})
$window.Add_Closing({param($sender,$e)
 if($script:backend -and !$script:backend.HasExited -and $script:mode -eq 'Launch'){
  $answer=[Windows.MessageBox]::Show($labels.closeQuestion,$labels.closeTitle,'YesNo','Question')
  if($answer -ne 'Yes'){$e.Cancel=$true;return}
  [IO.File]::WriteAllText($script:stopPath,'stop')
 }
 try{Save-PanelWindowSize (Join-Path $root '.state\ui-window-size.json')}catch{}
 Stop-PanelWorker
 $timer.Stop()
})
Refresh-IP
Update-MainAction
Set-UIPresentation 'unknown'
if($UiSmokeTest){
 if($config.SchemaVersion -ge 3){
  if($controls.ClientChoice.Items.Count -ne @($config.Clients).Count -or $modeCode.Visibility -ne 'Collapsed'){throw 'Selected-client picker includes an unselected client.'}
  if(![System.Windows.Shell.WindowChrome]::GetIsHitTestVisibleInChrome($controls.ClientChoice)){throw 'Selected-client picker cannot receive caption input.'}
  foreach($index in 0..(@($config.Clients).Count-1)){$controls.ClientChoice.SelectedIndex=$index;if($window.FindName('LaunchLabel').Text -notmatch [regex]::Escape($config.Clients[$index].Name)){throw 'Launch caption points to another client.'}}
  Set-Busy $true;if($controls.ClientChoice.IsEnabled -or $controls.StartButton.IsEnabled){throw 'Client selection changed during operation.'};Set-Busy $false
  [pscustomobject]@{Passed=4;Failed=0;SelectedClients=$controls.ClientChoice.Items.Count;SchemaVersion=3;NetworkRequests=$false}|ConvertTo-Json;return
 }
 $checks=New-Object Collections.Generic.List[string]
 if($controls.Values -contains $null){throw 'Missing named control.'};$checks.Add('All existing and redesigned controls are connected')
 Set-UIPresentation 'checking-firewall'
 if($controls.ComponentState.Text -ne $labels.checkPass -or $controls.FirewallState.Text -ne $labels.checkActive -or $controls.EgressState.Text -ne $labels.checkPending){throw 'Partial progress display is incorrect.'};$checks.Add('Only completed checks show passed')
 Set-UIPresentation 'blocked'
 if($controls.FirewallState.Text -ne $labels.checkFailed -or $controls.EgressState.Text -ne $labels.checkPending){throw 'Failed check display is incorrect.'};$checks.Add('Failure identifies current check without passing pending checks')
 Set-UIPresentation 'ready';Set-UIPresentation 'blocked'
 if($controls.ComponentState.Text -ne $labels.checkReview -or $controls.EgressState.Text -ne $labels.checkReview){throw 'Runtime failure left a stale passed state.'};$checks.Add('Runtime failure invalidates prior passed state')
 $controls.WindowTopmost.IsChecked=$false;$controls.WindowTopmost.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Primitives.ButtonBase]::ClickEvent))
 if($window.Topmost){throw 'Pin toggle failed.'};$checks.Add('Pin control actually changes window topmost')
 $controls.HideIP.IsChecked=$false;$controls.HideIP.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Primitives.ButtonBase]::ClickEvent))
 if($controls.IpText.Text -ne $config.ExpectedIPv4){throw 'IP display toggle failed.'};$checks.Add('IP display toggle preserves approved address')
 $controls.HideIP.IsChecked=$true;Refresh-IP
 if($controls.IpText.Text -eq $config.ExpectedIPv4){throw 'IP mask failed.'};$checks.Add('IP masking restores hidden display')
 if($window.ResizeMode -ne 'CanResize' -or $window.MinWidth -ne 420 -or $controls.StartButton.IsEnabled){throw 'Window or startup constraints changed.'};$checks.Add('Resizable window and unchecked-start restriction preserved')
 $sample=[pscustomobject]@{Time=(Get-Date).ToString('o');Direct=[pscustomobject]@{ok=$true;ip='192.0.2.7';country='CN';source='fixture'};Proxy=[pscustomobject]@{ip=$config.ExpectedIPv4;country='TW';milliseconds=100;matchesPin=$false;ok=$true;domains=@()};Environment=[pscustomobject]@{timezone='fixture';language='zh-TW (preference)';location='Deny';locationService='Stopped'}}
 $script:ready=$true;$controls.StartButton.IsEnabled=$true;Apply-PanelSnapshot $sample
 if($script:ready -or $controls.StartButton.IsEnabled){throw 'Changed monitored egress did not invalidate permission to start.'};$checks.Add('A changed monitored egress blocks start')
 $sample.Proxy.matchesPin=$true;Apply-PanelSnapshot $sample
 if($controls.StartButton.IsEnabled -or $controls.DNSState.Text -ne $labels.notTested -or $controls.WebRTCState.Text -ne $labels.notTested){throw 'Monitoring auto-enrolled egress or invented leak results.'};$checks.Add('Recovery requires a new guard check and does not invent leak-test results')
 $sample|Add-Member NoteProperty DNS ([pscustomobject]@{System=[pscustomobject]@{state='observed';resolvers=@('192.0.2.1')};Proxy=[pscustomobject]@{state='observed';resolvers=@('198.51.100.1')}})
 $sample|Add-Member NoteProperty WebRTC ([pscustomobject]@{state='warning';publicIPs=@('192.0.2.7')})
 $sample|Add-Member NoteProperty IPReputation ([pscustomobject]@{state='observed';score=100;cidr='198.51.100.0/24'})
 Apply-PanelSnapshot $sample
 if($controls.WebRTCState.Text -ne $labels.rtcBypass -or $controls.WebRTCMark.Text -ne '!'){throw 'Browser bypass warning was not displayed.'};$checks.Add('A browser bypass is displayed as a scoped warning')
 if($controls.WebRTCState.ToolTip -match '192\.0\.2\.7' -or $controls.ReputationState.ToolTip -match '198\.51\.100\.0'){throw 'Diagnostic details ignored IP masking.'};$checks.Add('Diagnostic details respect hidden IP display')
 if($controls.DNSState.Text -eq $labels.notTested -or $controls.ReputationState.Text -ne ($labels.reputationObserved -f 100)){throw 'Completed diagnostics remained untested.'};$checks.Add('DNS observations and third-party network score display actual result states')
 $sample|Add-Member NoteProperty UDPProtection ([pscustomobject]@{ok=$true})
 $sample.WebRTC.state='inconclusive';Apply-PanelSnapshot $sample
 if($controls.WebRTCState.Text -ne $labels.rtcBlocked){throw 'Verified UDP block was not distinguished from an empty probe.'};$checks.Add('Verified UDP rule and empty probe are reported together with scope')
 $sample.UDPProtection.ok=$false;$script:ready=$true;$controls.StartButton.IsEnabled=$true;Apply-PanelSnapshot $sample
 if($script:ready -or $controls.StartButton.IsEnabled){throw 'Missing UDP protection did not prevent a new launch.'};$checks.Add('Missing UDP protection invalidates permission to start')
 if($controls.WebRTCState.Text -ne $labels.inconclusive -or $controls.WebRTCMark.Text -eq [string][char]0x2713){throw 'Missing candidates invented a no-leak result.'};$checks.Add('Missing WebRTC candidates remain inconclusive rather than passed')
 $script:lastPhase='blocked';$controls.StatusText.Text=$labels.blocked;$controls.StageText.Text='fixture guard failure';Apply-PanelSnapshot $sample
 if($controls.StatusText.Text -ne $labels.blocked -or $controls.StageText.Text -ne 'fixture guard failure'){throw 'Panel observations hid a guard failure.'};$checks.Add('Monitor observations preserve a failed launch-protection check')
 $sample.UDPProtection.ok=$true;$sample.Proxy.matchesPin=$false;$sample.Time=([datetimeoffset]::Now.AddSeconds(-20)).ToString('o')
 $script:lastPhase='ready';$script:LastGuardVerifiedTime=[datetimeoffset]::Now;$script:ready=$true;$controls.StartButton.IsEnabled=$true
 Apply-PanelSnapshot $sample
 if(!$script:ready -or !$controls.StartButton.IsEnabled -or $controls.ClaudeReachState.Text -ne $labels.olderProbeFailed){throw 'An older failed sample overrode a newer full verification.'};$checks.Add('Older failure does not override a newer complete guard verification')
 $sample.Proxy|Add-Member NoteProperty Time $sample.Time
 $sample.Time=([datetimeoffset]::Now.AddSeconds(1)).ToString('o');Apply-PanelSnapshot $sample
 if(!$script:ready -or !$controls.StartButton.IsEnabled){throw 'Publishing old egress after diagnostics changed its observation order.'};$checks.Add('Egress ordering uses observation time rather than later publication time')
 $sample.Proxy.Time=$sample.Time;Apply-PanelSnapshot $sample
 if($script:ready -or $controls.StartButton.IsEnabled){throw 'A new failure did not override earlier verification.'};$checks.Add('A newer failure still prevents launch after a complete verification')
 function Assert-PassTone($control){$c=$control.Foreground.Color;if($c.G -le $c.R -or $c.G -le $c.B){throw 'Verified status is not visibly green.'}}
 function Assert-FailTone($control){$c=$control.Foreground.Color;if($c.R -le ($c.G*1.5) -or $c.R -le ($c.B*1.5)){throw 'Failed status is not visibly red.'}}
 $sample.Time=([datetimeoffset]::Now).ToString('o');$sample.Proxy.Time=$sample.Time;$sample.Proxy.matchesPin=$true;$script:LastGuardVerifiedTime=$null;$script:lastPhase='unknown';$script:UIBusy=$false;$script:StopRequested=$false;$script:ready=$false
 Apply-PanelSnapshot $sample;Assert-PassTone $controls.ClaudeReachState;$checks.Add('Matching egress has a visible green status badge')
 $sample.Proxy.matchesPin=$false;Apply-PanelSnapshot $sample;Assert-FailTone $controls.ClaudeReachState;Assert-FailTone $controls.StatusText;$checks.Add('New egress failure makes both row and header red')
 $sample.Proxy.matchesPin=$true;$sample.DNS.System.state='failed';Apply-PanelSnapshot $sample;Assert-FailTone $controls.DNSState;$checks.Add('A failed nested DNS probe makes the DNS status red')
 $sample.DNS.System.state='observed';$sample.WebRTC.state='warning';Apply-PanelSnapshot $sample;Assert-FailTone $controls.WebRTCState;$checks.Add('An observed browser bypass is visibly red')
 $sample.WebRTC.state='inconclusive';$sample.UDPProtection.ok=$true;Apply-PanelSnapshot $sample;Assert-PassTone $controls.WebRTCState;$checks.Add('Verified UDP protection and scoped empty probe get a green protection badge')
 $sample.UDPProtection.ok=$false;Apply-PanelSnapshot $sample;$tone=$controls.WebRTCState.Foreground.Color;if($tone.G -gt $tone.R -and $tone.G -gt $tone.B){throw 'An empty probe without UDP protection was colored green.'};$checks.Add('Empty probe without verified UDP protection cannot appear green')
 $sample.Environment.location='Allow';Apply-PanelSnapshot $sample;Assert-FailTone $controls.LocationState;$checks.Add('Enabled system location is a red privacy reminder')
 $sample.Environment.location='Deny';Apply-PanelSnapshot $sample;Assert-PassTone $controls.LocationState;$checks.Add('Disabled system location is visibly green')
 $sample.IPReputation.state='failed';Apply-PanelSnapshot $sample;Assert-FailTone $controls.ReputationState;$checks.Add('Failed third-party lookup is visibly red')
 $modeDesktop.IsChecked=$true;if($controls.ClientChoice.SelectedIndex -ne 1){throw 'Desktop tab does not select the actual desktop backend.'};$checks.Add('Desktop tab selects the existing desktop client mode')
 $controls.ClientChoice.SelectedIndex=0;if(!$modeCode.IsChecked){throw 'Client choice and active tab lost synchronization.'};$checks.Add('Client mode and active tab remain synchronized')
 Set-Busy $true;if($modeCode.IsEnabled -or $modeDesktop.IsEnabled){throw 'Client tabs remain enabled during a busy operation.'};Set-Busy $false;$checks.Add('Client tabs preserve busy-operation restrictions')
 Update-AdaptiveWindowLayout 480 720
 if(!$window.FindName('EnvironmentDisclosure').IsExpanded -or $script:AdaptiveMode -ne 'Panel'){throw 'Normal panel hides environment details'}
 $checks.Add('Normal window reveals full panel details')
 $script:ready=$false;Update-AdaptiveWindowLayout 480 560
 if($window.FindName('EnvironmentDisclosure').IsExpanded -or $script:AdaptiveMode -ne 'Widget' -or $script:ready){throw 'Widget transition corrupts presentation or safety state'}
 $checks.Add('Shrinking enters compact Widget without granting launch permission')
 $window.FindName('EnvironmentDisclosure').IsExpanded=$true;Update-AdaptiveWindowLayout 450 570
 if(!$window.FindName('EnvironmentDisclosure').IsExpanded){throw 'Resizing within Widget discards manually expanded details'}
 $checks.Add('Resizing within Widget preserves manual disclosure')
 if($window.FindName('NetworkGroup').Parent -ne $script:WidgetDiagnostics -or !$script:NetworkBody.IsAncestorOf($window.FindName('ProtectionGroup'))){throw 'Compact details swallowed launch verification.'}
 $checks.Add('Widget reuses existing detail disclosure and keeps launch verification directly visible')
 Update-AdaptiveWindowLayout 480 720
 if($window.FindName('NetworkGroup').Parent -ne $script:NetworkBody -or $window.FindName('EnvironmentDisclosure').Content -ne $script:EnvironmentContent){throw 'Panel transition did not restore original diagnostic layout.'}
 $checks.Add('Returning to full panel restores direct diagnostics and existing environment details')
 Update-AdaptiveWindowLayout 450 570
 $window.FindName('CompactButton').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
 if($window.Height -ne 720 -or $script:AdaptiveMode -ne 'Panel'){throw 'Restore panel control failed'}
 $window.FindName('CompactButton').RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
 if($window.Height -ne 560 -or $script:AdaptiveMode -ne 'Widget'){throw 'Compact control failed'}
 $checks.Add('Compact control switches both ways through its routed click handler')
 $sizeTest=Join-Path $root '.state\window-size-test.json';$window.Width=450;$window.Height=575;Save-PanelWindowSize $sizeTest
 $window.Width=480;$window.Height=720
 if(!(Restore-PanelWindowSize $sizeTest) -or $window.Width -ne 450 -or $window.Height -ne 575){throw 'Saved user dimensions failed to restore'}
 $checks.Add('User resized dimensions survive save and restore')
 if(![Windows.Shell.WindowChrome]::GetIsHitTestVisibleInChrome($modeCode.Parent.Parent) -or ![Windows.Shell.WindowChrome]::GetIsHitTestVisibleInChrome($controls.CloseButton.Parent)){throw 'Caption controls are being treated as draggable chrome'}
 $checks.Add('Client tabs and caption actions remain clickable in the drag region')
 $window.WindowState='Maximized';Sync-WindowCorners
 if($window.FindName('PanelSurface').CornerRadius.TopLeft -ne 0){throw 'Maximized window retained cut-out corners'}
 $window.WindowState='Normal';Sync-WindowCorners
 if($window.FindName('PanelSurface').CornerRadius.TopLeft -ne 24){throw 'Restored panel lost its matching corner radius'}
 $checks.Add('Maximize removes corner cutouts and restore reinstates the panel radius')
 Set-PanelTheme 'Dark';Set-UIPresentation 'blocked';Set-PanelTone 'Location' 'pass'
 $previousPhase=$script:lastPhase;$previousReady=$script:ready;$previousStart=$controls.StartButton.IsEnabled;$previousText=$controls.LocationState.Text
 $themeButton=$window.FindName('ThemeButton')
 $themeButton.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
 if($script:PanelTheme -ne 'Light' -or $window.FindName('PanelSurface').Background.Color.A -ne 216){throw 'Frosted light theme did not replace the panel surface'}
 Assert-PassTone $controls.LocationState;Assert-FailTone $controls.StatusText
 if($controls.LocationState.Foreground.Color.R -ne 8 -or $controls.StatusText.Foreground.Color.R -ne 131){throw 'Live status colors did not follow the light theme'}
 if($script:lastPhase -ne $previousPhase -or $script:ready -ne $previousReady -or $controls.StartButton.IsEnabled -ne $previousStart -or $controls.LocationState.Text -ne $previousText){throw 'Theme switch modified monitoring or launch state'}
 $checks.Add('Theme click updates light surface and live red green statuses without changing safety state')
 $themeButton.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
 if($script:PanelTheme -ne 'Dark' -or $window.FindName('PanelSurface').Background.Color.R -ne 17){throw 'Dark theme did not restore its original surface'}
 Assert-PassTone $controls.LocationState;Assert-FailTone $controls.StatusText
 $checks.Add('Theme click restores original dark palette with visible red green statuses')
 $window.FindName('EnvironmentDisclosure').IsExpanded=$false
 $protection=$window.FindName('ProtectionGroup');$protectionAncestor=$protection.Parent
 while($protectionAncestor){if($protectionAncestor -is [Windows.Controls.Expander]){throw 'Launch protection still sits inside a disclosure'};$protectionAncestor=[Windows.Media.VisualTreeHelper]::GetParent($protectionAncestor)}
 if(!$protection.IsAncestorOf($controls.ComponentState) -or !$protection.IsAncestorOf($controls.EgressState)){throw 'Verification controls were lost during relocation'}
 $checks.Add('All launch protection steps remain outside every collapsible disclosure')
  $sample.Proxy.matchesPin=$true;$sample|Add-Member NoteProperty Components ([pscustomobject]@{ok=$false;error='Fixture component changed';Time=[datetimeoffset]::Now.AddSeconds(1).ToString('o')}) -Force
 $script:ready=$true;$controls.StartButton.IsEnabled=$true;Apply-PanelSnapshot $sample
 if($script:ready -or $controls.StartButton.IsEnabled -or $controls.ComponentMark.Text -ne '!' -or $controls.ComponentState.Text -ne $labels.componentsChanged){throw 'Idle component update did not block launch and display refresh protection.'}
 $checks.Add('Background component changes block start and visibly request protection update')
 if($window.FindName('StopButton') -or $window.FindName('MaximizeButton') -or $window.FindName('MinimizeButton')){throw 'Redundant standalone action remains.'}
 if($controls.InstallButton.Parent -ne $controls.CloseButton.Parent -or $settingsMenu.Items.Count -ne 4){throw 'Settings lost an existing action during consolidation.'}
 $checks.Add('Settings remain accessible and redundant window or stop actions are consolidated')
 foreach($name in 'ThemeButton','CompactButton','CloseButton','InstallButton','WindowTopmost'){
  $control=$window.FindName($name);if($control.Content -isnot [Windows.Controls.Viewbox]){throw ('Font glyph remains: '+$name)}
 }
 $controls.DNSMark.Text='!';$statusPath=$controls.DNSMark.Parent.Children[1].Child.Children[0]
 if($statusPath.Data -ne $script:GuardIconGeometry['circle-alert']){throw 'Failure state did not update vector icon.'}
 $controls.DNSMark.Text=[string][char]0x2713
 if($statusPath.Data -ne $script:GuardIconGeometry['check']){throw 'Pass state did not update vector icon.'}
 $checks.Add('Caption and live status icons use local vector geometry rather than fonts')
 $script:mode='Launch';$script:StopRequested=$false;Set-Busy $true
 if(!$controls.StartButton.IsEnabled -or $window.FindName('LaunchLabel').Text -ne $labels.stopSession){throw 'Managed stop unavailable during launch.'}
 $script:ready=$true;$sample.Proxy.matchesPin=$false;$sample.Proxy.Time=[datetimeoffset]::Now.AddSeconds(2).ToString('o');Apply-PanelSnapshot $sample
 if($script:ready -or !$controls.StartButton.IsEnabled){throw 'Failed observation removed stop control or retained launch permission.'}
 $checks.Add('Managed stop remains usable when observations invalidate future launch')
 $script:stopPath=Join-Path $root ('.state\icon-stop-test-'+[guid]::NewGuid().ToString('N')+'.signal')
 $controls.StartButton.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
 if(!(Test-Path -LiteralPath $script:stopPath) -or [IO.File]::ReadAllText($script:stopPath) -ne 'stop' -or $controls.StartButton.IsEnabled -or !$script:StopRequested){throw 'Consolidated stop did not signal the owned session.'}
 $checks.Add('Main action routes managed stop to its existing owned stop signal and prevents duplicate requests')
 $script:mode='Check';Set-Busy $false
 if($controls.StartButton.IsEnabled -or $window.FindName('LaunchLabel').Text -ne ($labels.launchPrefix+'Claude')){throw 'Stopped action incorrectly restores permission to launch.'}
 $checks.Add('Idle action restores launch caption and keeps recheck requirement')
$receipt=[pscustomobject]@{Time=(Get-Date).ToString('o');Passed=$checks.Count;Failed=0;Tests=$checks.ToArray();RoutedControlEvents=$true;NetworkRequests=$false}
 [IO.File]::WriteAllText((Join-Path $root '.state\presentation-tests.json'),($receipt|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
 $receipt|ConvertTo-Json -Depth 4;exit 0
}
if($RenderPreview){
 if($PreviewWidth -lt 420 -or $PreviewHeight -lt 540){throw 'Preview is smaller than the supported minimum.'}
 Update-AdaptiveWindowLayout $PreviewWidth $PreviewHeight
 $visual=$window.Content
 $visual.Measure([Windows.Size]::new($PreviewWidth,$PreviewHeight));$visual.Arrange([Windows.Rect]::new(0,0,$PreviewWidth,$PreviewHeight));$visual.UpdateLayout()
 $bitmap=New-Object Windows.Media.Imaging.RenderTargetBitmap($PreviewWidth,$PreviewHeight,96,96,[Windows.Media.PixelFormats]::Pbgra32)
 $bitmap.Render($visual)
 $encoder=New-Object Windows.Media.Imaging.PngBitmapEncoder
 $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
 $filename=if($PreviewWidth -eq 840 -and $PreviewHeight -eq 840){'preview.png'}else{'preview-'+$PreviewWidth+'x'+$PreviewHeight+'.png'}
 $file=[IO.File]::Create((Join-Path $root $filename))
 try{$encoder.Save($file)}finally{$file.Dispose()}
 [pscustomobject]@{XamlLoaded=$true;Topmost=$window.Topmost;PanelResizable=($window.ResizeMode -eq 'CanResize');StartDisabled=(!$controls.StartButton.IsEnabled);Preview=(Join-Path $root $filename)}|ConvertTo-Json -Compress
}else{
 $null=Restore-PanelWindowSize (Join-Path $root '.state\ui-window-size.json')
 $window.Height=[Math]::Max($window.MinHeight,[Math]::Min($window.Height,[Windows.SystemParameters]::WorkArea.Height-20))
 Update-AdaptiveWindowLayout $window.Width $window.Height
 $window.Add_ContentRendered({$null=$window.Dispatcher.BeginInvoke([Windows.Threading.DispatcherPriority]::ContextIdle,[Action]{Read-WindowCornerState});$controls.DNSState.Text=$labels.checkActive;$controls.WebRTCState.Text=$labels.checkActive;$controls.ReputationState.Text=$labels.checkActive;Start-PanelWorker;Begin-Backend 'Check'})
 try{$timer.Start();$window.ShowDialog()|Out-Null}finally{Stop-PanelWorker;$timer.Stop()}
}