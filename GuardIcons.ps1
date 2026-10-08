$script:GuardIconAssets=Get-Content -LiteralPath (Join-Path $root 'icons\lucide.json') -Raw -Encoding UTF8|ConvertFrom-Json
$script:GuardIconGeometry=[Collections.Generic.Dictionary[string,Windows.Media.Geometry]]::new()
foreach($entry in $script:GuardIconAssets.Geometry.PSObject.Properties){
 $geometry=[Windows.Media.Geometry]::Parse($entry.Value);$geometry.Freeze();$script:GuardIconGeometry.Add($entry.Name,$geometry)
}
if(!('ClaudeGuardIconConverter' -as [type])){
 $previousLib=$env:LIB
 try{$env:LIB=$null;Add-Type -Path (Join-Path $root 'GuardIconConverter.cs') -ReferencedAssemblies PresentationFramework,PresentationCore,WindowsBase}
 finally{$env:LIB=$previousLib}
}
$script:GuardMarkConverter=[ClaudeGuardIconConverter]::new();$script:GuardMarkConverter.Icons=$script:GuardIconGeometry
function New-GuardIcon([string]$name,[double]$size=18,$foregroundSource){
 if(!$script:GuardIconGeometry.ContainsKey($name)){throw ('Unknown vector icon: '+$name)}
 $box=[Windows.Controls.Viewbox]::new();$box.Width=$size;$box.Height=$size;$box.Stretch='Uniform';$box.IsHitTestVisible=$false;$box.Tag=$name
 $canvas=[Windows.Controls.Canvas]::new();$canvas.Width=24;$canvas.Height=24
 $path=[Windows.Shapes.Path]::new();$path.Data=$script:GuardIconGeometry[$name]
 $path.SetResourceReference([Windows.UIElement]::EffectProperty,'ClearTextEffect')
 $path.StrokeThickness=$script:GuardIconAssets.StrokeWidth;$path.StrokeStartLineCap='Round';$path.StrokeEndLineCap='Round';$path.StrokeLineJoin='Round'
 $binding=[Windows.Data.Binding]::new('Foreground');$binding.Source=$foregroundSource
 [Windows.Data.BindingOperations]::SetBinding($path,[Windows.Shapes.Shape]::StrokeProperty,$binding)|Out-Null
 $canvas.Children.Add($path)|Out-Null;$box.Child=$canvas
 return $box
}
function Set-GuardButtonIcon($button,[string]$name,[double]$size=18){
 if($button){$button.Content=New-GuardIcon $name $size $button}
}
function Set-GuardActionIcon($button,$iconHost,[string]$name){$iconHost.Content=New-GuardIcon $name 16 $button}
function Set-GuardActionContent($button,[string]$name,[string]$text){
 $row=[Windows.Controls.StackPanel]::new();$row.Orientation='Horizontal';$row.VerticalAlignment='Center'
 $icon=New-GuardIcon $name 16 $button;$icon.Margin='0,0,8,0';$row.Children.Add($icon)|Out-Null
 $caption=[Windows.Controls.TextBlock]::new();$caption.Text=$text;$caption.VerticalAlignment='Center';$row.Children.Add($caption)|Out-Null
 $button.Content=$row
}
function Initialize-GuardIcons {
 foreach($pair in @(@('InstallButton','sliders-horizontal'),@('CloseButton','x'),@('CloseSetup','x'),@('CompactButton','minimize-2'),@('WindowTopmost','pin'))){
  Set-GuardButtonIcon ($window.FindName($pair[0])) $pair[1]
 }
 $check=$window.FindName('CheckButton');if($check){Set-GuardActionContent $check 'refresh-cw' ([string]$check.Content)}
 $launch=$window.FindName('StartButton');if($launch){Set-GuardActionIcon $launch ($window.FindName('LaunchIcon')) 'play'}
 foreach($name in 'StatusGlyph','ComponentMark','FirewallMark','RoutingMark','EgressMark','ClaudeReachMark','DNSMark','WebRTCMark','ReputationMark'){
  $mark=$window.FindName($name);if(!$mark){continue}
  $parent=$mark.Parent;$holder=[Windows.Controls.Grid]::new();$holder.Width=if($name -eq 'StatusGlyph'){18}else{15};$holder.Height=$holder.Width
  $holder.Margin=$mark.Margin;$holder.HorizontalAlignment=$mark.HorizontalAlignment;$holder.VerticalAlignment='Center'
  [Windows.Controls.Grid]::SetColumn($holder,[Windows.Controls.Grid]::GetColumn($mark));[Windows.Controls.Grid]::SetRow($holder,[Windows.Controls.Grid]::GetRow($mark))
  $index=if($parent -is [Windows.Controls.Panel]){$parent.Children.IndexOf($mark)}else{-1}
  if($index -ge 0){$parent.Children.Remove($mark);$parent.Children.Insert($index,$holder)}elseif($parent -is [Windows.Controls.Border]){$parent.Child=$holder}else{throw ('Unsupported state icon parent: '+$name)}
  $mark.Visibility='Collapsed';$mark.Margin='0';$holder.Children.Add($mark)|Out-Null
  $icon=New-GuardIcon 'circle' $holder.Width $mark
  $binding=[Windows.Data.Binding]::new('Text');$binding.Source=$mark;$binding.Converter=$script:GuardMarkConverter
  [Windows.Data.BindingOperations]::SetBinding($icon.Child.Children[0],[Windows.Shapes.Path]::DataProperty,$binding)|Out-Null
  $holder.Children.Add($icon)|Out-Null
 }
}
Initialize-GuardIcons