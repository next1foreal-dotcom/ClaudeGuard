[CmdletBinding()]
param([ValidateSet('Install','Check','Remove')][string]$Mode='Check')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GuardBrowserUDP.ps1')
$state=Join-Path $PSScriptRoot '.state'
$receiptPath=Join-Path $state 'browser-udp-install.json'
$created=@()
try {
 $isAdmin=([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if($Mode -ne 'Check' -and !$isAdmin){
  $arguments='-NoProfile -File "'+$PSCommandPath+'" -Mode '+$Mode
  $child=Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -PassThru
  $null=$child.Handle;$child.WaitForExit()
  if($child.ExitCode -ne 0){throw ('Elevated UDP operation failed, exit '+$child.ExitCode+'. See browser-udp-install.json.')}
  Get-Content -LiteralPath $receiptPath -Raw -Encoding UTF8
  exit 0
 }
 if($Mode -eq 'Remove'){
  Get-NetFirewallRule -Group $script:BrowserUDPGroup -ErrorAction SilentlyContinue|Remove-NetFirewallRule
  $receipt=[pscustomobject]@{ok=$true;mode=$Mode;Time=(Get-Date).ToString('o');removedGroup=$script:BrowserUDPGroup}
 }elseif($Mode -eq 'Install'){
  $programs=Get-BrowserUDPPrograms
  if(!$programs.Count){throw 'No eligible browser or Codex executables found.'}
  foreach($path in $programs){
   $name=Get-BrowserUDPRuleName $path
   if(!(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)){
    New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName ('ClaudeGuard UDP: '+[IO.Path]::GetFileName($path)) -Group $script:BrowserUDPGroup -Description 'Block non-loopback outbound UDP for this browser/Codex executable. TCP, loopback and proxy service are unchanged.' -Enabled True -Direction Outbound -Action Block -Profile Any -Program $path -Protocol UDP -RemoteAddress $script:BrowserUDPRemote|Out-Null
    $created+=$name
   }
   Assert-BrowserUDPRule $path
  }
  $status=Get-BrowserUDPStatus;if(!$status.ok){throw 'UDP rule verification failed.'}
  $receipt=[pscustomobject]@{ok=$true;mode=$Mode;Time=(Get-Date).ToString('o');createdRules=$created;Programs=$programs;status=$status}
 }else{
  $receipt=Get-BrowserUDPStatus
  if(!$receipt.ok){$receipt|ConvertTo-Json -Depth 6;exit 1}
 }
 [IO.File]::WriteAllText($receiptPath,($receipt|ConvertTo-Json -Depth 7),[Text.UTF8Encoding]::new($false))
 $receipt|ConvertTo-Json -Depth 7
 exit 0
}catch{
 # Only rules created by this failed operation are rolled back.
 foreach($name in $created){Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue|Remove-NetFirewallRule -ErrorAction SilentlyContinue}
 $receipt=[pscustomobject]@{ok=$false;mode=$Mode;Time=(Get-Date).ToString('o');error=$_.Exception.Message;rolledBackRules=$created}
 [IO.File]::WriteAllText($receiptPath,($receipt|ConvertTo-Json -Depth 5),[Text.UTF8Encoding]::new($false))
 $receipt|ConvertTo-Json -Depth 5;exit 1
}