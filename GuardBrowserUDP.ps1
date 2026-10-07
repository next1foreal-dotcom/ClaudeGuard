$script:BrowserUDPGroup='ClaudeGuard-BrowserUDP-01a1169a'
$script:BrowserUDPRemote=@('0.0.0.0-126.255.255.255','128.0.0.0-255.255.255.255','::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
function ConvertTo-BrowserUDPPath([string]$path) {
 if($path.StartsWith('\\?\UNC\',[StringComparison]::OrdinalIgnoreCase)){$path='\\'+$path.Substring(8)}
 elseif($path.StartsWith('\\?\',[StringComparison]::OrdinalIgnoreCase)){$path=$path.Substring(4)}
 return [IO.Path]::GetFullPath($path)
}
function Get-BrowserUDPPrograms {
 $paths=@(
  (Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'),
  (Join-Path ${env:ProgramFiles(x86)} 'Google\Chrome\Application\chrome.exe'),
  (Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'),
  (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe'),
  (Join-Path $env:ProgramFiles 'Mozilla Firefox\firefox.exe')
 )
 $processes=Get-CimInstance Win32_Process -ErrorAction Stop
 foreach($process in $processes){
  if($process.ExecutablePath -and ($process.Name -in @('chrome.exe','msedge.exe','firefox.exe') -or ($process.Name -eq 'ChatGPT.exe' -and $process.ExecutablePath -match '\\WindowsApps\\OpenAI\.Codex_[^\\]+\\app\\ChatGPT\.exe$') -or ($process.Name -eq 'codex.exe' -and $process.ExecutablePath -match '\\@openai\\codex\\vendor\\[^\\]+\\bin\\codex\.exe$'))){$paths+=$process.ExecutablePath}
 }
 return @($paths|Where-Object{$_ -and (Test-Path -LiteralPath $_ -PathType Leaf)}|ForEach-Object{ConvertTo-BrowserUDPPath $_}|Sort-Object -Unique)
}
function Get-BrowserUDPRuleName([string]$path) {
 $path=ConvertTo-BrowserUDPPath $path
 $sha=[Security.Cryptography.SHA256]::Create()
 try{$bytes=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($path.ToLowerInvariant()));return $script:BrowserUDPGroup+'-'+[BitConverter]::ToString($bytes).Replace('-','').Substring(0,16)}finally{$sha.Dispose()}
}
function Assert-BrowserUDPRule([string]$path) {
 $path=ConvertTo-BrowserUDPPath $path
 $rule=Get-NetFirewallRule -PolicyStore ActiveStore -Name (Get-BrowserUDPRuleName $path) -ErrorAction Stop
 if($rule.Group -ne $script:BrowserUDPGroup -or $rule.Enabled -ne 'True' -or $rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Block' -or $rule.Profile -ne 'Any'){throw 'Browser UDP rule properties changed.'}
 if(($rule|Get-NetFirewallApplicationFilter).Program -ine $path){throw 'Browser UDP rule has a different executable.'}
 $port=$rule|Get-NetFirewallPortFilter
 if($port.Protocol -notin @('UDP','17') -or $port.RemotePort -ne 'Any' -or $port.LocalPort -ne 'Any'){throw 'Browser UDP rule does not block all UDP ports.'}
 if(@(Compare-Object @($script:BrowserUDPRemote|Sort-Object) @(($rule|Get-NetFirewallAddressFilter).RemoteAddress|Sort-Object)).Count){throw 'Browser UDP address ranges changed.'}
}
function Get-BrowserUDPStatus {
 $programs=Get-BrowserUDPPrograms
 $items=@();$active=$true;$errorText=$null
 try{
  if((Get-Service MpsSvc -ErrorAction Stop).Status -ne 'Running' -or @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop|Where-Object{$_.Enabled -ne 'True'}).Count){throw 'Windows Firewall is not fully enabled.'}
 }catch{$active=$false;$errorText=$_.Exception.Message}
 foreach($path in $programs){
  $ok=$false;$detail=$null
  try{Assert-BrowserUDPRule $path;$ok=$true}catch{$detail=$_.Exception.Message;$active=$false}
  $items+=@([pscustomobject]@{program=$path;ok=$ok;error=$detail})
 }
 if(!$programs.Count){$active=$false;$errorText='No browser executables were discovered.'}
 return [pscustomobject]@{Time=(Get-Date).ToString('o');state=$(if($active){'verified'}else{'missing'});ok=$active;programs=$items;error=$errorText;scope='Discovered Chrome, Edge, Firefox and running Codex executable paths; external UDP blocked, TCP and loopback unchanged.'}
}
function Assert-BrowserUDPProtection {
 $status=Get-BrowserUDPStatus
 if(!$status.ok){throw 'Browser/Codex UDP direct-connection protection is missing or changed. Run Install-Browser-UDP.cmd.'}
}