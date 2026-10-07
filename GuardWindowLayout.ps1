$script:WindowMetrics=@{PanelWidth=480.0;PanelHeight=720.0;WidgetWidth=480.0;WidgetHeight=560.0;BreakpointHeight=640.0;CornerRadius=24.0}
$script:AdaptiveMode=$null
function Update-AdaptiveWindowLayout([double]$width,[double]$height) {
 $mode=if($height -lt $script:WindowMetrics.BreakpointHeight){'Widget'}else{'Panel'}
 if($mode -eq $script:AdaptiveMode){return}
 $script:AdaptiveMode=$mode
 $window.FindName('EnvironmentDisclosure').IsExpanded=($mode -eq 'Panel')
 $controls.StageText.TextWrapping=if($mode -eq 'Panel'){'Wrap'}else{'NoWrap'}
 $controls.StageText.TextTrimming=if($mode -eq 'Panel'){'None'}else{'CharacterEllipsis'}
 $button=$window.FindName('CompactButton')
 $button.Content=if($mode -eq 'Widget'){[string][char]0x2197}else{[string][char]0x2199}
 $button.ToolTip=if($mode -eq 'Widget'){$labels.expandPanel}else{$labels.shrinkWidget}
}
function Toggle-PanelWidget {
 $target=if($script:AdaptiveMode -eq 'Widget'){'Panel'}else{'Widget'}
 $window.WindowState='Normal'
 $window.Width=$script:WindowMetrics[$target+'Width'];$window.Height=$script:WindowMetrics[$target+'Height']
 Update-AdaptiveWindowLayout $window.Width $window.Height
}
function Restore-PanelWindowSize([string]$path) {
 if(!(Test-Path -LiteralPath $path)){return $false}
 try {
  $saved=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
  $width=[double]$saved.Width;$height=[double]$saved.Height
  if([double]::IsNaN($width) -or [double]::IsNaN($height) -or [double]::IsInfinity($width) -or [double]::IsInfinity($height) -or $width -lt $window.MinWidth -or $height -lt $window.MinHeight){return $false}
  $window.Width=[Math]::Max($window.MinWidth,[Math]::Min($width,[Windows.SystemParameters]::WorkArea.Width-20))
  $window.Height=[Math]::Max($window.MinHeight,[Math]::Min($height,[Windows.SystemParameters]::WorkArea.Height-20))
  return $true
 }catch{return $false}
}
function Save-PanelWindowSize([string]$path) {
 $saved=[ordered]@{Width=$window.Width;Height=$window.Height;Time=(Get-Date).ToString('o')}
 [IO.File]::WriteAllText($path,($saved|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
}
function Sync-WindowCorners {
 $maximized=($window.WindowState -eq 'Maximized')
 $window.FindName('PanelSurface').CornerRadius=[Windows.CornerRadius]::new($(if($maximized){0.0}else{$script:WindowMetrics.CornerRadius}))
 if(!('ClaudeGuardBackdrop' -as [type])){return}
 $handle=[Windows.Interop.WindowInteropHelper]::new($window).Handle
 if($handle -eq [IntPtr]::Zero){return}
 $result=[ordered]@{Time=(Get-Date).ToString('o');UIProcessId=$PID;LogicalRadius=$script:WindowMetrics.CornerRadius;Maximized=$maximized;Success=$false;Error=$null}
 try{
  $native=[ClaudeGuardBackdrop]::SynchronizeCorners($handle,[int]$script:WindowMetrics.CornerRadius,$maximized)
  $result.Success=($native[0] -eq 1 -and $native[5] -eq 1);$result.PhysicalWidth=$native[1];$result.PhysicalHeight=$native[2];$result.DPI=$native[3];$result.PhysicalRadius=$native[4];$result.NativeMaskVerified=($native[5] -eq 1)
 }catch{$result.Error=$_.Exception.Message}
 if(!$UiSmokeTest -and !$RenderPreview){[IO.File]::WriteAllText((Join-Path $root '.state\window-corners-current.json'),($result|ConvertTo-Json),[Text.UTF8Encoding]::new($false))}
}
function Read-WindowCornerState {
 if(!('ClaudeGuardBackdrop' -as [type])){return}
 $handle=[Windows.Interop.WindowInteropHelper]::new($window).Handle
 if($handle -eq [IntPtr]::Zero){return}
 $surface=$window.FindName('PanelSurface');$origin=$surface.TransformToAncestor($window).Transform([Windows.Point]::new(0,0))
 $source=[Windows.Interop.HwndSource]::FromHwnd($handle);$scale=$source.CompositionTarget.TransformToDevice
 $data=[ClaudeGuardBackdrop]::InspectCorners($handle,[int]$script:WindowMetrics.CornerRadius,($window.WindowState -eq 'Maximized'))
 $surfaceMode=[ClaudeGuardBackdrop]::InspectSurfaceMode($handle)
 $r=[ordered]@{SurfaceMode=$surfaceMode;AllowsTransparency=$window.AllowsTransparency;NativeAcrylicEnabled=($surfaceMode[1] -eq 3);Time=(Get-Date).ToString('o');UIProcessId=$PID;NativeRegionKind=$data[0];NativeWidth=$data[1];NativeHeight=$data[2];DPI=$data[3];PhysicalRadius=$data[4];CornersClipped=($data[5] -eq 1);ExactNativeMaskMatch=($data[6] -eq 1);SurfaceWidth=$surface.ActualWidth;SurfaceHeight=$surface.ActualHeight;SurfaceX=$origin.X;SurfaceY=$origin.Y;WindowActualWidth=$window.ActualWidth;WindowActualHeight=$window.ActualHeight;ScaleX=$scale.M11;ScaleY=$scale.M22;SurfaceRadius=$surface.CornerRadius.TopLeft}
 [IO.File]::WriteAllText((Join-Path $root '.state\window-corners-stable.json'),($r|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
}