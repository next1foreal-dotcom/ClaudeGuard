. (Join-Path $root 'GuardIcons.ps1')
$script:ThemePalette=Get-Content -LiteralPath (Join-Path $root 'ui-palette.json') -Raw -Encoding UTF8|ConvertFrom-Json
$script:PanelTheme='Dark'
$script:ThemeBindings=@{}
function Get-PanelBrush([string]$color){
 $key='Ink_'+$color.TrimStart('#').ToUpperInvariant()
 $brush=$window.Resources[$key]
 if(!$brush){throw ('Missing theme brush: '+$key)}
 return $brush
}
function Set-GlassFinish([string]$theme){
 $finish=$window.FindName('GlassTexture')
 if($finish){$finish.Visibility='Collapsed';$finish.Background=$null}
 if($theme -eq 'Light'){
  $shadow=[Windows.Media.Effects.DropShadowEffect]::new();$shadow.Color=[Windows.Media.Colors]::Black
  $shadow.BlurRadius=3;$shadow.ShadowDepth=0;$shadow.Opacity=.95;$shadow.RenderingBias='Quality';$shadow.Freeze()
  $window.Resources['ClearTextEffect']=$shadow
 }else{$window.Resources.Remove('ClearTextEffect')}
}
function Set-PanelTheme([ValidateSet('Dark','Light')][string]$theme,[switch]$Persist){
 $script:PanelTheme=$theme
 Set-GlassFinish $theme
 foreach($property in $script:ThemePalette.PSObject.Properties){
  $key=$property.Name.TrimStart('#');$color=[Windows.Media.ColorConverter]::ConvertFromString($property.Value.$theme)
  $window.Resources['Tone_'+$key]=$color
  $window.Resources['Ink_'+$key]=[Windows.Media.SolidColorBrush]::new($color)
 }
 $button=$window.FindName('ThemeButton')
 Set-GuardButtonIcon $button $(if($theme -eq 'Dark'){'sun'}else{'moon'})
 $button.ToolTip=if($theme -eq 'Dark'){$labels.switchLight}else{$labels.switchDark}
 foreach($entry in @($script:ThemeBindings.Values)){$entry.Control.SetValue($entry.Property,(Get-PanelBrush $entry.Color))}
 if($Persist){[IO.File]::WriteAllText((Join-Path $root '.state\ui-theme.json'),(@{Theme=$theme}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))}
 if(!$UiSmokeTest -and !$RenderPreview){
  [IO.File]::WriteAllText((Join-Path $root '.state\ui-theme-current.json'),(@{Time=(Get-Date).ToString('o');UIProcessId=$PID;Theme=$theme;SurfaceAlpha=$window.FindName('PanelSurface').Background.Color.A;Surface=$window.FindName('PanelSurface').Background.Color.ToString();GlassFinish=($window.FindName('GlassTexture').Visibility -eq 'Visible');ProtectionAlwaysExpanded=$true;IconLibrary=$script:GuardIconAssets.Library;IconSourceCommit=$script:GuardIconAssets.Commit;LocalVectorIcons=$script:GuardIconGeometry.Count}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
 }
}
function Set-ThemeBrush($control,[string]$property,[string]$color){
 $dp=switch($property){'Foreground'{[Windows.Controls.Control]::ForegroundProperty};'Background'{[Windows.Controls.Control]::BackgroundProperty};'Fill'{[Windows.Shapes.Shape]::FillProperty}}
 if($control -is [Windows.Controls.TextBlock] -and $property -eq 'Foreground'){$dp=[Windows.Controls.TextBlock]::ForegroundProperty}
 if($control -is [Windows.Controls.Border] -and $property -eq 'Background'){$dp=[Windows.Controls.Border]::BackgroundProperty}
 if(!$dp){throw ('Unsupported theme property: '+$property)}
 $control.SetValue($dp,(Get-PanelBrush $color))
 $key=[string][Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($control)+':'+$property
 $script:ThemeBindings[$key]=@{Control=$control;Property=$dp;Color=$color}
}
function Restore-PanelTheme {
 $theme='Dark';$path=Join-Path $root '.state\ui-theme.json'
 if(Test-Path -LiteralPath $path){try{$saved=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json;if($saved.Theme -in @('Dark','Light')){$theme=$saved.Theme}}catch{}}
 Set-PanelTheme $theme
}