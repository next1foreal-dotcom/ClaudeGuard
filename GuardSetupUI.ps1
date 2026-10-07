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
$script:SetupStep=1; $script:SetupBusy=$false; $script:SetupWorker=$null; $script:SetupCandidate=$null; $script:SetupChecks=@();$script:SetupReady=$false
function Update-SetupActions {
 $selected=@($script:SetupChecks|Where-Object IsChecked).Count -gt 0
 $ui.SetupNext.IsEnabled=(!$script:SetupBusy -and $(if($script:SetupStep -eq 2){$ui.ConfirmExit.IsChecked -eq $true}else{$selected}))
 $ui.SetupBack.IsEnabled=!$script:SetupBusy; $ui.CloseSetup.IsEnabled=!$script:SetupBusy
 $ui.DiscoverySection.IsEnabled=!$script:SetupBusy; $ui.ReviewSection.IsEnabled=!$script:SetupBusy
}
function Set-SetupScreen([int]$step){
 $script:SetupStep=$step
 $ui.DiscoverySection.Visibility=if($step -eq 1){'Visible'}else{'Collapsed'}
 $ui.ReviewSection.Visibility=if($step -eq 2){'Visible'}else{'Collapsed'}
 $ui.SetupTitle.Text=if($step -eq 1){$labels.discoverTitle}else{$labels.reviewTitle}
 $ui.SetupHint.Text=if($step -eq 1){$labels.discoverHint}else{$labels.reviewHint}
 $ui.SetupNext.Content=if($step -eq 1){$labels.probeButton}else{$labels.enableButton}
 $ui.SetupBack.Content=if($step -eq 1){$labels.scanButton}else{$labels.backButton}
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
 if(!$script:SetupChecks.Count){$ui.SetupHint.Text=$labels.noClient}
}
function Set-SetupReview($candidate){
 $script:SetupCandidate=$candidate;$ui.ReviewIP.Text=$candidate.Config.ExpectedIPv4;$ui.ReviewCountry.Text=$labels.country+$candidate.Config.ExpectedCountry
 $ui.ReviewNode.Text=$labels.node+$candidate.NodeName;$ui.ReviewProxy.Text=$candidate.Config.Proxy
 $ui.ReviewPrograms.Text=$labels.programs+(@($candidate.Config.Clients.Name)-join ', ');$ui.ConfirmExit.IsChecked=$false;Set-SetupScreen 2
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
  $script:SetupWorker=@{Process=$process;Result=$result;Mode=$mode}
 }catch{$script:SetupBusy=$false;$ui.SetupError.Text=$labels.failure+$_.Exception.Message;$ui.SetupError.Visibility='Visible';Update-SetupActions}
}
$ui.ProxyCandidates.Add_SelectionChanged({if($ui.ProxyCandidates.SelectedItem){$ui.SetupProxy.Text=[string]$ui.ProxyCandidates.SelectedItem}})
$ui.ThemeButton.Add_Click({$theme=if($script:PanelTheme -eq 'Dark'){'Light'}else{'Dark'};Set-PanelTheme $theme -Persist:(!$UiSmokeTest)})
$ui.CloseSetup.Add_Click({$window.Close()})
$ui.ConfirmExit.Add_Checked({Update-SetupActions});$ui.ConfirmExit.Add_Unchecked({Update-SetupActions})
$ui.SetupBack.Add_Click({if($script:SetupStep -eq 2){Set-SetupScreen 1}else{Begin-SetupWorker 'Discover' $null}})
$ui.SetupNext.Add_Click({
 if($UiSmokeTest){return}
 if($script:SetupStep -eq 1){
  $selection=@{ClientIds=@($script:SetupChecks|Where-Object IsChecked|ForEach-Object {$_.Tag.Id});Proxy=$ui.SetupProxy.Text.Trim();FlClashDirectory=$ui.FlClashFolder.Text.Trim();AllowRuntimeDownload=($ui.PrepareRuntime.IsChecked -eq $true);RequireBrowserUDP=($ui.SetupUDP.IsChecked -eq $true)}
  Begin-SetupWorker 'Probe' $selection
 }elseif($ui.ConfirmExit.IsChecked){Begin-SetupWorker 'Enable' $script:SetupCandidate}
})
$timer=[Windows.Threading.DispatcherTimer]::new();$timer.Interval=[TimeSpan]::FromMilliseconds(300)
$timer.Add_Tick({
 if(!$script:SetupWorker -or !$script:SetupWorker.Process.HasExited){return}
 $worker=$script:SetupWorker;$script:SetupWorker=$null;$script:SetupBusy=$false
 try{
  if(!(Test-Path -LiteralPath $worker.Result)){throw ('Setup worker exited '+$worker.Process.ExitCode+'. See '+$worker.Result+'.err')}
  $result=Get-Content -LiteralPath $worker.Result -Raw -Encoding UTF8|ConvertFrom-Json
  if(!$result.Ok){throw [string]$result.Error}
  switch($worker.Mode){'Discover'{Set-SetupDiscovery $result.Data};'Probe'{Set-SetupReview $result.Data};'Enable'{$script:SetupReady=$true;$window.Close()}}
 }catch{$ui.SetupError.Text=$labels.failure+$_.Exception.Message;$ui.SetupError.Visibility='Visible'}
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
 $review=@{Config=@{ExpectedIPv4='192.0.2.10';ExpectedCountry='TW';Proxy=$ui.SetupProxy.Text;Clients=$fixture.Clients};NodeName='Fixture node'}
 Set-SetupReview $review
 Assert-SetupUI (!$ui.SetupNext.IsEnabled) 'Observation is not approval'
 $ui.ConfirmExit.IsChecked=$true
 Assert-SetupUI ($ui.SetupNext.IsEnabled) 'Explicit confirmation enables protection'
 $ui.ConfirmExit.IsChecked=$false
 Assert-SetupUI (!$ui.SetupNext.IsEnabled) 'Revoked confirmation disables protection'
 foreach($theme in @('Dark','Light')){Set-PanelTheme $theme;foreach($step in @(1,2)){
  Set-SetupScreen $step;$window.Content.Measure([Windows.Size]::new(520,710));$window.Content.Arrange([Windows.Rect]::new(0,0,520,710));$window.Content.UpdateLayout()
  foreach($name in @('SetupNext','SetupBack','ThemeButton','CloseSetup')){$control=$ui[$name];$point=$control.TranslatePoint([Windows.Point]::new(0,0),$window.Content);if($point.X -lt 0 -or $point.Y -lt 0 -or ($point.X+$control.ActualWidth) -gt 521 -or ($point.Y+$control.ActualHeight) -gt 711){throw ('Layout overflow: '+$name)}}
  $bitmap=[Windows.Media.Imaging.RenderTargetBitmap]::new(520,710,96,96,[Windows.Media.PixelFormats]::Pbgra32);$bitmap.Render($window.Content)
  $encoder=[Windows.Media.Imaging.PngBitmapEncoder]::new();$encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
  $file=[IO.File]::Create((Join-Path $root ('.state\setup-preview-'+$theme+'-'+$step+'.png')));try{$encoder.Save($file)}finally{$file.Dispose()}
  Assert-SetupUI $true ($theme+' step '+$step)
 }}
 [pscustomobject]@{Passed=$passed;Failed=0;ExplicitConfirmation=$true;Layouts=4;NetworkRequests=$false}|ConvertTo-Json
 return
}
$window.Add_ContentRendered({Begin-SetupWorker 'Discover' $null});$timer.Start()
try{$window.ShowDialog()|Out-Null;if($Standalone){if($script:SetupReady){exit 0}else{exit 2}};return $script:SetupReady}finally{$timer.Stop()}