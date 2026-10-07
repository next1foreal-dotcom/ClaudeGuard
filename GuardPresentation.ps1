function Set-PanelTone([string]$name,[string]$tone) {
 $ink='#A2A9AF';$wash='#272D32'
 switch($tone){'pass'{$ink='#62DB98';$wash='#18372A'}'fail'{$ink='#FF757C';$wash='#45262B'}'pending'{$ink='#D3AE67';$wash='#3B3425'}}
 $state=$controls[$name+'State'];if(!$state){return}
 Set-ThemeBrush $state Foreground $ink
 if($state.Parent -is [Windows.Controls.Border]){Set-ThemeBrush $state.Parent Background $wash}
 $mark=$controls[$name+'Mark'];if($mark){Set-ThemeBrush $mark Foreground $ink}
}
$script:LastInspectionStep=-1
function Set-UIPresentation([string]$phase) {
 $steps=@('checking-components','checking-firewall','checking-routing','checking-egress')
 $names=@('Component','Firewall','Routing','Egress')
 $step=[Array]::IndexOf($steps,$phase)
 if($phase -eq 'checking'){$script:LastInspectionStep=-1}
 if($step -ge 0){$script:LastInspectionStep=$step}
 if($phase -in @('ready','running')){$script:LastInspectionStep=4}
 for($i=0;$i -lt 4;$i++){
  $text=$labels.checkPending;$mark=[string][char]0x25cb;$color='#A2A9AF'
  if($phase -in @('ready','running') -or ($step -ge 0 -and $i -lt $step)){$text=$labels.checkPass;$mark=[string][char]0x2713;$color='#62DB98'}
  elseif($step -eq $i -and $step -ge 0){$text=$labels.checkActive;$mark=[string][char]0x2022;$color='#EBEBE5'}
  elseif($phase -eq 'blocked'){
   if($script:LastInspectionStep -ge 0 -and $script:LastInspectionStep -lt 4){
    if($i -lt $script:LastInspectionStep){$text=$labels.checkPass;$mark=[string][char]0x2713;$color='#62DB98'}
    elseif($i -eq $script:LastInspectionStep){$text=$labels.checkFailed;$mark='!';$color='#FF757C'}
   }else{$text=$labels.checkReview;$color='#D3AE67'}
  }elseif($phase -eq 'stopped'){$text=$labels.checkReview}
  $controls[$names[$i]+'State'].Text=$text
  Set-ThemeBrush $controls[$names[$i]+'State'] Foreground $color
  $controls[$names[$i]+'Mark'].Text=$mark
  Set-ThemeBrush $controls[$names[$i]+'Mark'] Foreground $color
 }
 $glyph='?';$glyphColor='#D3AE67';$background='#272D32';$footer=$labels.footerUnknown;$dot='#A2A9AF'
 switch($phase){
  'ready' {$glyph=[string][char]0x2713;$glyphColor='#62DB98';$background='#18372A';$footer=$labels.footerReady;$dot='#62DB98'}
  'running' {$glyph=[string][char]0x2713;$glyphColor='#62DB98';$background='#18372A';$footer=$labels.footerRunning;$dot='#62DB98'}
  'blocked' {$glyph='!';$glyphColor='#FF757C';$background='#45262B';$footer=$labels.footerBlocked;$dot='#FF757C'}
  'stopped' {$glyph=[string][char]0x2013;$glyphColor='#A2A9AF';$background='#272D32';$footer=$labels.footerStopped}
  default {if($phase -eq 'checking' -or $step -ge 0){$glyph=[string][char]0x2026;$glyphColor='#A2A9AF';$background='#272D32';$footer=$labels.checking}}
 }
 $controls.StatusGlyph.Text=$glyph
 Set-ThemeBrush $controls.StatusGlyph Foreground $glyphColor
 Set-ThemeBrush $controls.StatusIconBackground Background $background
 Set-ThemeBrush $controls.StatusText Foreground $(if($phase -in @('ready','running')){'#62DB98'}elseif($phase -eq 'blocked'){'#FF757C'}else{'#E7E9EA'})
 $controls.FooterStatus.Text=$footer
 Set-ThemeBrush $controls.FooterDot Fill $dot
}