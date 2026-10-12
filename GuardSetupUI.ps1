[CmdletBinding()]
param([switch]$UiSmokeTest,[switch]$Standalone)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
$root=$PSScriptRoot; $RenderPreview=$true
New-Item -ItemType Directory -Path (Join-Path $root '.state') -Force|Out-Null
$labels=Get-Content (Join-Path $root 'setup-zh.json') -Raw -Encoding UTF8|ConvertFrom-Json
[xml]$xaml=Get-Content (Join-Path $root 'GuardSetup.xaml') -Raw -Encoding UTF8
$window=[Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($xaml))
$ui=@{};foreach($node in $xaml.SelectNodes('//*[@*[local-name()="Name" and namespace-uri()="http://schemas.microsoft.com/winfx/2006/xaml"]]')){$ui[$node.GetAttribute('Name','http://schemas.microsoft.com/winfx/2006/xaml')]=$window.FindName($node.GetAttribute('Name','http://schemas.microsoft.com/winfx/2006/xaml'))}
. (Join-Path $root 'GuardTheme.ps1'); Restore-PanelTheme
function Set-SetupSurface {
 $color=Get-PanelBrush '#DB111417';$tone=$color.Color;$tone.A=255
 $ui.PanelSurface.Background=[Windows.Media.SolidColorBrush]::new($tone)
}
Set-SetupSurface
function Test-SetupReviewCurrent {
 if(!$script:SetupCandidate -or !$script:SetupCandidate.Time){return $false}
 try{$age=([datetimeoffset]::Now-[datetimeoffset]$script:SetupCandidate.Time).TotalSeconds;return ($age -ge -10 -and $age -le 300)}catch{return $false}
}
function Get-SetupSelection {
 return @{ClientIds=@($script:SetupChecks|Where-Object IsChecked|ForEach-Object {$_.Tag.Id});Proxy=$ui.SetupProxy.Text.Trim();FlClashDirectory=$ui.FlClashFolder.Text.Trim();AllowRuntimeDownload=($ui.PrepareRuntime.IsChecked -eq $true);RequireBrowserUDP=($ui.SetupUDP.IsChecked -eq $true)}
}
function Restore-SetupSelection($selection){
 foreach($box in $script:SetupChecks){$box.IsChecked=($box.Tag.Id -in @($selection.ClientIds))}
 $ui.SetupProxy.Text=[string]$selection.Proxy;$ui.FlClashFolder.Text=[string]$selection.FlClashDirectory
 $ui.SetupUDP.IsChecked=[bool]$selection.RequireBrowserUDP;$ui.PrepareRuntime.IsChecked=[bool]$selection.AllowRuntimeDownload
 Update-SetupActions
}
function Show-SetupFailure([string]$message){
 $ui.SetupHint.Text=if($script:SetupStep -eq 1){$labels.discoverHint}else{$labels.reviewHint}
 $ui.SetupError.Text=$labels.failure+$(switch -Exact ($message){
  'The exit check expired. Test and confirm again.'{$labels.expiredHint}
  'Reviewed configuration changed. Test and confirm again.'{$labels.changedHint}
  'Exit, client or node changed after confirmation. Review the new result first.'{$labels.changedHint}
  default{$message}
 })
 $ui.SetupError.Visibility='Visible'
}
$script:SetupStep=1; $script:SetupBusy=$false; $script:SetupWorker=$null; $script:SetupCandidate=$null; $script:SetupChecks=@();$script:SetupReady=$false
function Update-SetupActions {
 $selected=@($script:SetupChecks|Where-Object IsChecked).Count -gt 0
 $review=($script:SetupStep -eq 2);$current=Test-SetupReviewCurrent
 if($review -and !$current){$ui.ConfirmExit.IsChecked=$false}
 $ui.SetupNext.IsEnabled=(!$script:SetupBusy -and $(if($review){$script:SetupCandidate -and (!$current -or $ui.ConfirmExit.IsChecked -eq $true)}else{$selected}))
 $ui.SetupBack.IsEnabled=!$script:SetupBusy; $ui.CloseSetup.IsEnabled=!$script:SetupBusy
 $ui.DiscoverySection.IsEnabled=!$script:SetupBusy; $ui.ReviewSection.IsEnabled=!$script:SetupBusy
 $ui.ConfirmExit.IsEnabled=(!$script:SetupBusy -and $current)
 $action=if(!$review){'probe'}elseif(!$current){'retest'}else{'enable'}
 if($script:SetupAction -ne $action){
  $caption=switch($action){'probe'{$labels.probeButton};'retest'{$labels.retestButton};'enable'{$labels.enableButton}}
  Set-GuardActionContent $ui.SetupNext $(if($action -eq 'enable'){'shield-check'}else{'refresh-cw'}) $caption
  $script:SetupAction=$action
 }
 if($review -and !$current -and !$script:SetupBusy){$ui.SetupHint.Text=$labels.expiredHint}
}
function Set-SetupScreen([int]$step){
 $script:SetupStep=$step
 $ui.DiscoverySection.Visibility=if($step -eq 1){'Visible'}else{'Collapsed'}
 $ui.ReviewSection.Visibility=if($step -eq 2){'Visible'}else{'Collapsed'}
 $ui.SetupTitle.Text=if($step -eq 1){$labels.discoverTitle}else{$labels.reviewTitle}
 $ui.SetupHint.Text=if($step -eq 1){$labels.discoverHint}else{$labels.reviewHint}
 $script:SetupAction=$null
 Set-GuardActionContent $ui.SetupBack $(if($step -eq 1){'refresh-cw'}else{'arrow-left'}) $(if($step -eq 1){$labels.scanButton}else{$labels.backButton})
 Update-SetupActions
}
function Set-SetupDiscovery($data){
 $script:SetupChecks=@(); $ui.SetupClientList.Children.Clear()
 foreach($client in @($data.Clients|Where-Object Supported)){
  $box=[Windows.Controls.CheckBox]::new();$box.SetResourceReference([Windows.Controls.Control]::ForegroundProperty,'Ink_E7E9EA');$box.Content=$client.Name;$box.Tag=$client;$box.IsChecked=$true;$box.Margin='0,0,0,10'
  $box.Add_Checked({Update-SetupActions});$box.Add_Unchecked({Update-SetupActions});$ui.SetupClientList.Children.Add($box)|Out-Null;$script:SetupChecks+=$box
 }
 foreach($shim in @($data.UnsupportedShims)){$text=[Windows.Controls.TextBlock]::new();$text.SetResourceReference([Windows.Controls.TextBlock]::ForegroundProperty,'Ink_A2A9AF');$text.Text=$shim.UnsupportedReason;$text.FontSize=11;$text.TextWrapping='Wrap';$text.Margin='0,0,0,8';$ui.SetupClientList.Children.Add($text)|Out-Null}
 $ui.ProxyCandidates.Items.Clear(); foreach($proxy in @($data.ProxyCandidates)){$ui.ProxyCandidates.Items.Add([string]$proxy.Proxy)|Out-Null}
 $ui.ProxyCandidates.Visibility=if($ui.ProxyCandidates.Items.Count -gt 1){'Visible'}else{'Collapsed'};if($ui.ProxyCandidates.Items.Count){$ui.ProxyCandidates.SelectedIndex=0}else{$ui.SetupProxy.Text='http://127.0.0.1:7890'}
 $ui.FlClashFolder.Text=[string]$data.FlClashDirectory
 $ui.ProxyAppsText.Text=if(@($data.ProxyApps).Count){$labels.proxyApps+(@($data.ProxyApps|ForEach-Object{if($_ -is [string]){$_}else{$_.Name}})-join ', ')}else{$labels.unknownProxy}
 Set-SetupScreen 1
 $selectionPath=Join-Path $root '.state\setup-selection.json'
 if(!$UiSmokeTest -and (Test-Path -LiteralPath $selectionPath)){
  try{Restore-SetupSelection (Get-Content -LiteralPath $selectionPath -Raw -Encoding UTF8|ConvertFrom-Json)}catch{Show-SetupFailure $_.Exception.Message}
 }
 if(!$script:SetupChecks.Count){$ui.SetupHint.Text=$labels.noClient}
}
function Set-SetupReview($candidate){
 $script:SetupCandidate=$candidate;$ui.ReviewIP.Text=$candidate.Config.ExpectedIPv4;$ui.ReviewCountry.Text=$labels.country+$candidate.Config.ExpectedCountry
 $ui.ReviewNode.Text=$labels.node+$candidate.NodeName;$ui.ReviewProxy.Text=$candidate.Config.Proxy
 $ui.ReviewPrograms.Text=$labels.programs+(@($candidate.Config.Clients.Name)-join ', ');$ui.ConfirmExit.IsChecked=$false;Set-SetupScreen 2
}
function Show-SetupProgress($progress,[int]$elapsed){
 $caption=switch($progress.Phase){
  'setup-awaiting-admin'{$labels.awaitAdmin}
  'setup-installing'{($labels.installRules -f $progress.Detail)}
  'setup-udp'{$labels.installUDP}
  'checking-components'{$labels.verifyComponents}
  'checking-firewall'{$labels.verifyFirewall}
  'checking-routing'{$labels.verifyRouting}
  'checking-egress'{$labels.verifyEgress}
  'ready'{$labels.saving}
  'setup-saving'{$labels.saving}
  default{$labels.enableBusy}
 }
 $ui.SetupHint.Text=$caption+' '+($labels.elapsed -f $elapsed)
}
function Poll-SetupProgress {
 if(!$script:SetupWorker -or $script:SetupWorker.Mode -ne 'Enable'){return}
 $progress=$null;$path=$script:SetupWorker.Result+'.progress.json'
 if(Test-Path -LiteralPath $path){try{$progress=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json}catch{}}
 Show-SetupProgress $progress ([int]([datetimeoffset]::Now-$script:SetupWorker.StartedAt).TotalSeconds)
}
function Begin-SetupWorker([string]$mode,$data){
 if($script:SetupBusy){return}
 $script:SetupBusy=$true;$ui.SetupError.Visibility='Collapsed';Update-SetupActions
 $ui.SetupHint.Text=switch($mode){'Discover'{$labels.scanBusy};'Probe'{$labels.probeBusy};'Enable'{$labels.enableBusy}}
 try{
  $id=[Guid]::NewGuid().ToString('N');$result=Join-Path $root ('.state\setup-result-'+$id+'.json')
  $arguments='-NoProfile -File "'+(Join-Path $root 'GuardSetup.ps1')+'" -Mode '+$mode+' -ResultFile "'+$result+'"'
  if($data){$inputPath=Join-Path $root ('.state\setup-input-'+$id+'.json');[IO.File]::WriteAllText($inputPath,($data|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false));$arguments+=' -InputFile "'+$inputPath+'"'}
  if($mode -eq 'Enable'){$arguments+=' -Confirmed -ReviewHash '+$script:SetupCandidate.ReviewHash}
  $process=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -WindowStyle Hidden -RedirectStandardOutput ($result+'.log') -RedirectStandardError ($result+'.err') -PassThru
  $script:SetupWorker=@{Process=$process;Result=$result;Mode=$mode;StartedAt=[datetimeoffset]::Now}
 }catch{$script:SetupBusy=$false;Show-SetupFailure $_.Exception.Message;Update-SetupActions}
}
$ui.ProxyCandidates.Add_SelectionChanged({if($ui.ProxyCandidates.SelectedItem){$ui.SetupProxy.Text=[string]$ui.ProxyCandidates.SelectedItem}})
$ui.ThemeButton.Add_Click({$theme=if($script:PanelTheme -eq 'Dark'){'Light'}else{'Dark'};Set-PanelTheme $theme -Persist:(!$UiSmokeTest);Set-SetupSurface})
$ui.CloseSetup.Add_Click({$window.Close()})
$ui.ConfirmExit.Add_Checked({Update-SetupActions});$ui.ConfirmExit.Add_Unchecked({Update-SetupActions})
$ui.SetupBack.Add_Click({if($script:SetupStep -eq 2){Set-SetupScreen 1}else{Begin-SetupWorker 'Discover' $null}})
function Invoke-SetupNext {
 if($script:SetupStep -eq 1){
  $selection=Get-SetupSelection
  if(!$UiSmokeTest){[IO.File]::WriteAllText((Join-Path $root '.state\setup-selection.json'),($selection|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))}
  Begin-SetupWorker 'Probe' $selection
 }elseif(!(Test-SetupReviewCurrent)){
  $ui.ConfirmExit.IsChecked=$false;Begin-SetupWorker 'Probe' (Get-SetupSelection)
 }elseif($ui.ConfirmExit.IsChecked){Begin-SetupWorker 'Enable' $script:SetupCandidate}
}
$ui.SetupNext.Add_Click({Invoke-SetupNext})
$timer=[Windows.Threading.DispatcherTimer]::new();$timer.Interval=[TimeSpan]::FromMilliseconds(300)
$timer.Add_Tick({
 if(!$script:SetupWorker -or !$script:SetupWorker.Process.HasExited){Poll-SetupProgress;if(!$script:SetupBusy -and $script:SetupStep -eq 2){Update-SetupActions};return}
 $worker=$script:SetupWorker;$script:SetupWorker=$null;$script:SetupBusy=$false
 try{
  if(!(Test-Path -LiteralPath $worker.Result)){throw ('Setup worker exited '+$worker.Process.ExitCode+'. See '+$worker.Result+'.err')}
  $result=Get-Content -LiteralPath $worker.Result -Raw -Encoding UTF8|ConvertFrom-Json
  if(!$result.Ok){throw [string]$result.Error}
  switch($worker.Mode){'Discover'{Set-SetupDiscovery $result.Data};'Probe'{Set-SetupReview $result.Data};'Enable'{$script:SetupReady=$true;$window.Close()}}
 }catch{Show-SetupFailure $_.Exception.Message}
 Update-SetupActions
})
$window.Add_Closing({param($sender,$e) if($script:SetupBusy){$e.Cancel=$true}else{$timer.Stop()}})
Set-SetupScreen 1
if($UiSmokeTest){
 $passed=0
 function Assert-SetupUI([bool]$ok,[string]$name){if(!$ok){throw ('Setup UI assertion: '+$name)};$script:passed++}
 Assert-SetupUI (!$ui.SetupNext.IsEnabled) 'No installed client cannot continue'
 $fixture=[pscustomobject]@{Clients=@([pscustomobject]@{Id='claude-code';Name='Claude Code';Kind='Code';Path='C:\fixture\claude.exe';Supported=$true});UnsupportedShims=@();ProxyCandidates=@(@{Proxy='http://127.0.0.1:17890'});FlClashDirectory='C:\fixture\FlClash';ProxyApps=@(@{Name='FlClash'})}
 Set-SetupDiscovery $fixture
 Assert-SetupUI ($ui.SetupNext.IsEnabled -and $ui.SetupProxy.Text -eq 'http://127.0.0.1:17890') 'Installed-only selection and variable HTTP port'
 $selection=@{ClientIds=@('claude-code');Proxy='http://127.0.0.1:17890';FlClashDirectory='C:\fixture\FlClash';RequireBrowserUDP=$true;AllowRuntimeDownload=$true}
 Restore-SetupSelection $selection
 Assert-SetupUI ($ui.SetupNext.IsEnabled -and $ui.SetupUDP.IsChecked -and $ui.SetupProxy.Text -eq $selection.Proxy) 'Setup selections can be restored without approving an exit'
 $selection.ClientIds=@('missing-client');Restore-SetupSelection $selection
 Assert-SetupUI (!$ui.SetupNext.IsEnabled) 'Restored missing clients do not silently enroll another program'
 $selection.ClientIds=@('claude-code');Restore-SetupSelection $selection
 $review=@{Time=[datetimeoffset]::Now.ToString('o');Config=@{ExpectedIPv4='192.0.2.10';ExpectedCountry='TW';Proxy=$ui.SetupProxy.Text;Clients=$fixture.Clients};NodeName='Fixture node'}
 Set-SetupReview $review
 Assert-SetupUI (!$ui.SetupNext.IsEnabled) 'Observation is not approval'
 $ui.ConfirmExit.IsChecked=$true
 Assert-SetupUI ($ui.SetupNext.IsEnabled) 'Explicit confirmation enables protection'
 $ui.ConfirmExit.IsChecked=$false
 Assert-SetupUI (!$ui.SetupNext.IsEnabled) 'Revoked confirmation disables protection'
 $review.Time=[datetimeoffset]::Now.AddMinutes(-6).ToString('o');$ui.ConfirmExit.IsChecked=$true;Update-SetupActions
 Assert-SetupUI (!$ui.ConfirmExit.IsChecked -and !$ui.ConfirmExit.IsEnabled -and $ui.SetupNext.IsEnabled -and $script:SetupAction -eq 'retest') 'Expired confirmation is revoked and the main action becomes retest'
 function Show-SetupProgress($progress,[int]$elapsed){
 $caption=switch($progress.Phase){
  'setup-awaiting-admin'{$labels.awaitAdmin}
  'setup-installing'{($labels.installRules -f $progress.Detail)}
  'setup-udp'{$labels.installUDP}
  'checking-components'{$labels.verifyComponents}
  'checking-firewall'{$labels.verifyFirewall}
  'checking-routing'{$labels.verifyRouting}
  'checking-egress'{$labels.verifyEgress}
  'ready'{$labels.saving}
  'setup-saving'{$labels.saving}
  default{$labels.enableBusy}
 }
 $ui.SetupHint.Text=$caption+' '+($labels.elapsed -f $elapsed)
}
function Poll-SetupProgress {
 if(!$script:SetupWorker -or $script:SetupWorker.Mode -ne 'Enable'){return}
 $progress=$null;$path=$script:SetupWorker.Result+'.progress.json'
 if(Test-Path -LiteralPath $path){try{$progress=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json}catch{}}
 Show-SetupProgress $progress ([int]([datetimeoffset]::Now-$script:SetupWorker.StartedAt).TotalSeconds)
}
function Begin-SetupWorker([string]$mode,$data){$script:SmokeMode=$mode;$script:SmokeSelection=$data}
 $script:SmokeMode='';$ui.SetupNext.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
 Assert-SetupUI ($script:SmokeMode -eq 'Probe' -and $script:SmokeSelection.ClientIds[0] -eq 'claude-code' -and $script:SmokeSelection.Proxy -eq 'http://127.0.0.1:17890') 'Expired routed action rechecks the same selection without installing'
 $ui.SetupHint.Text=$labels.enableBusy;Show-SetupFailure 'The exit check expired. Test and confirm again.';Update-SetupActions
 Assert-SetupUI ($ui.SetupError.Text -eq ($labels.failure+$labels.expiredHint) -and $ui.SetupHint.Text -eq $labels.expiredHint) 'Expiry failure is localized and does not leave an installing hint'
 $review.Time=[datetimeoffset]::Now.ToString('o');Set-SetupReview $review
 Assert-SetupUI (!$ui.ConfirmExit.IsChecked -and !$ui.SetupNext.IsEnabled -and $ui.ConfirmExit.IsEnabled) 'A fresh result requires another explicit confirmation'
 $ui.ConfirmExit.IsChecked=$true;$script:SmokeMode='';$ui.SetupNext.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Button]::ClickEvent))
 Assert-SetupUI ($script:SmokeMode -eq 'Enable') 'A fresh explicitly confirmed routed action enables protection'
 $ui.SetupHint.Text=$labels.enableBusy;Show-SetupFailure 'fixture install failure'
 Assert-SetupUI ($ui.SetupHint.Text -eq $labels.reviewHint -and $ui.SetupError.Text -like '*fixture install failure') 'Other installation failures restore the review hint and retain the error'
 Show-SetupProgress ([pscustomobject]@{Phase='setup-installing';Detail='2/33'}) 15
 Assert-SetupUI ($ui.SetupHint.Text.Contains('2/33') -and !$ui.SetupHint.Text.Contains($labels.awaitAdmin)) 'Installing reports component progress instead of asking again for UAC'
 Show-SetupProgress ([pscustomobject]@{Phase='checking-firewall';Detail=''}) 90
 Assert-SetupUI ($ui.SetupHint.Text.Contains($labels.verifyFirewall) -and $ui.SetupHint.Text.Contains('90')) 'Slow firewall verification shows its actual stage and elapsed time'
 Show-SetupProgress ([pscustomobject]@{Phase='setup-awaiting-admin';Detail=''}) 3
 Assert-SetupUI ($ui.SetupHint.Text.Contains($labels.awaitAdmin)) 'Only the elevation stage asks for administrator authorization'
 Show-SetupFailure 'fixture progress failure'
 Assert-SetupUI ($ui.SetupHint.Text -eq $labels.reviewHint) 'Failure clears the busy progress stage'
 $testProgress=Join-Path $root ('.state\setup-smoke-progress-'+[guid]::NewGuid().ToString('N'))
 $script:SetupWorker=@{Mode='Enable';Result=$testProgress;StartedAt=[datetimeoffset]::Now.AddSeconds(-7)}
 try{
  [IO.File]::WriteAllText(($testProgress+'.progress.json'),'{"Phase":"checking-egress"}',[Text.UTF8Encoding]::new($false))
  Poll-SetupProgress
  Assert-SetupUI ($ui.SetupHint.Text.Contains($labels.verifyEgress) -and $ui.SetupHint.Text.Contains('7')) 'Running worker progress file reaches the visible setup hint'
 }finally{$script:SetupWorker=$null;Remove-Item -LiteralPath ($testProgress+'.progress.json') -ErrorAction SilentlyContinue}
 foreach($theme in @('Dark','Light')){
  Set-PanelTheme $theme;Set-SetupSurface
  foreach($box in @($script:SetupChecks)+@($ui.PrepareRuntime,$ui.SetupUDP,$ui.ConfirmExit)){
   $checked=$box.IsChecked;$box.IsEnabled=$true;$box.ApplyTemplate()|Out-Null
   $surface=$box.Template.FindName('CheckSurface',$box);$mark=$box.Template.FindName('CheckMark',$box);$checkRoot=$box.Template.FindName('CheckRoot',$box);$focus=$box.Template.FindName('CheckFocus',$box)
   $box.IsChecked=$false
   Assert-SetupUI ($surface -and $focus -and $surface.Width -eq 18 -and $surface.CornerRadius.TopLeft -eq 5 -and $box.MinHeight -eq 28 -and $mark.Visibility -eq 'Collapsed') ($theme+' custom checkbox supports unchecked and keyboard focus states')
   $box.IsChecked=$true
   Assert-SetupUI ($mark.Visibility -eq 'Visible' -and $surface.Background.Color -eq (Get-PanelBrush '#183127').Color -and $surface.BorderBrush.Color -eq (Get-PanelBrush '#68DA9C').Color -and $mark.Stroke.Color -eq (Get-PanelBrush '#68DA9C').Color) ($theme+' checkbox selection follows the panel palette')
   $box.IsEnabled=$false
   Assert-SetupUI ($checkRoot.Opacity -eq .45 -and $box.Cursor -eq [Windows.Input.Cursors]::Arrow) ($theme+' checkbox disabled state remains distinct')
   $box.IsEnabled=$true;$box.IsChecked=$checked
  }
 }
 foreach($theme in @('Dark','Light')){Set-PanelTheme $theme;Set-SetupSurface;foreach($step in @(1,2)){
  Set-SetupScreen $step;$window.Content.Measure([Windows.Size]::new(520,710));$window.Content.Arrange([Windows.Rect]::new(0,0,520,710));$window.Content.UpdateLayout()
  foreach($name in @('SetupNext','SetupBack','ThemeButton','CloseSetup')){$control=$ui[$name];$point=$control.TranslatePoint([Windows.Point]::new(0,0),$window.Content);if($point.X -lt 0 -or $point.Y -lt 0 -or ($point.X+$control.ActualWidth) -gt 521 -or ($point.Y+$control.ActualHeight) -gt 711){throw ('Layout overflow: '+$name)}}
  $bitmap=[Windows.Media.Imaging.RenderTargetBitmap]::new(520,710,96,96,[Windows.Media.PixelFormats]::Pbgra32);$bitmap.Render($window.Content)
  $pixel=New-Object byte[] 4;$bitmap.CopyPixels([Windows.Int32Rect]::new(300,20,1,1),$pixel,4,0);if($pixel[3] -ne 255){throw 'Wizard background lets other window text show through'}
  $encoder=[Windows.Media.Imaging.PngBitmapEncoder]::new();$encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
  $file=[IO.File]::Create((Join-Path $root ('.state\setup-preview-'+$theme+'-'+$step+'.png')));try{$encoder.Save($file)}finally{$file.Dispose()}
  Assert-SetupUI $true ($theme+' step '+$step)
 }}
 [pscustomobject]@{Passed=$passed;Failed=0;ExplicitConfirmation=$true;Layouts=4;NetworkRequests=$false}|ConvertTo-Json
 return
}
$window.Add_ContentRendered({Begin-SetupWorker 'Discover' $null});$timer.Start()
try{$window.ShowDialog()|Out-Null;if($Standalone){if($script:SetupReady){exit 0}else{exit 2}};return $script:SetupReady}finally{$timer.Stop()}