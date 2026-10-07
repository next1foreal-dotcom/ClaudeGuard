$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GuardCore.ps1')
. (Join-Path $PSScriptRoot 'GuardInventory.ps1')
. (Join-Path $PSScriptRoot 'GuardRouting.ps1')
$config=Get-GuardConfig
Import-GuardJob
$results=New-Object Collections.Generic.List[object]
function Test-Case([string]$name,[scriptblock]$test){
 try {& $test; $results.Add([pscustomobject]@{Name=$name;Passed=$true});Write-Host ('PASS '+$name)}
 catch {$results.Add([pscustomobject]@{Name=$name;Passed=$false;Error=$_.Exception.Message});Write-Host ('FAIL '+$name+': '+$_.Exception.Message)}
}
function Must-Reject([scriptblock]$action){$rejected=$false;try{& $action}catch{$rejected=$true};if(!$rejected){throw 'Unsafe input was accepted.'}}
Test-Case 'All registered firewall rules active' {Assert-GuardFirewall (@($config.ProtectedPrograms)+@(Get-GuardProbePath))}
Test-Case 'Physical IPv6 disabled and no default IPv6 route' {Assert-GuardIPv6}
Test-Case 'Approved trace accepted' {Assert-GuardTrace ("ip="+$config.ExpectedIPv4+"`nloc="+$config.ExpectedCountry) $config}
Test-Case 'Changed IPv4 refused' {Must-Reject {Assert-GuardTrace "ip=192.0.2.25`nloc=TW" $config}}
Test-Case 'Changed country refused' {Must-Reject {Assert-GuardTrace ("ip="+$config.ExpectedIPv4+"`nloc=US") $config}}
Test-Case 'Malformed trace refused' {Must-Reject {Assert-GuardTrace '<html>error</html>' $config}}
Test-Case 'IPv6 egress refused' {Must-Reject {Assert-GuardTrace "ip=2001:db8::1`nloc=TW" $config}}
Test-Case 'Live protected probe uses approved proxy for both AI domains' {Assert-GuardProxyPort $config;Assert-GuardEgress $config}
Test-Case 'Protected probe blocked while unprotected control reaches same target' {
 $control=& (Join-Path $env:SystemRoot 'System32\curl.exe') --silent --show-error --fail --ipv4 --noproxy '*' --connect-timeout 3 --max-time 6 https://www.baidu.com/ 2>&1
 if($LASTEXITCODE -ne 0){throw 'Unprotected control failed; cannot attribute failure to firewall.'}
 $previous=$ErrorActionPreference
 try {$ErrorActionPreference='Continue';$output=& (Get-GuardProbePath) --silent --show-error --ipv4 --noproxy '*' --connect-timeout 2 --max-time 3 https://www.baidu.com/ 2>&1;$code=$LASTEXITCODE} finally {$ErrorActionPreference=$previous}
 if($code -notin @(7,28)){throw ('Expected network denial, curl returned '+$code)}
}
Test-Case 'Dead proxy refused' {
 $dead=$config | ConvertTo-Json -Depth 8 | ConvertFrom-Json
 $dead.Proxy='http://127.0.0.1:1'
 Must-Reject {Assert-GuardProxyPort $dead}
 Must-Reject {Assert-GuardEgress $dead}
}
Test-Case 'Failure invokes cleanup (mock job, no external process)' {
 $fake=[pscustomobject]@{IsRunning=$true;Disposed=$false;ExitCode=0}
 $fake|Add-Member -MemberType ScriptMethod -Name Dispose -Value {$this.Disposed=$true;$this.IsRunning=$false}
 Must-Reject {Invoke-GuardWatch $fake {throw 'Simulated proxy failure'} {} 2}
 if(!$fake.Disposed){throw 'Cleanup not invoked.'}
}
Test-Case 'Normal exit code returned (mock job)' {
 $fake=[pscustomobject]@{IsRunning=$false;Disposed=$false;ExitCode=7}
 $fake|Add-Member -MemberType ScriptMethod -Name Dispose -Value {$this.Disposed=$true}
 $result=Invoke-GuardWatch $fake {} {} 2
 if($result -ne 7 -or !$fake.Disposed){throw 'Incorrect exit-code or cleanup behavior.'}
}
Test-Case 'Current desktop and native components covered' {Assert-GuardInventory $config (Get-GuardInventory $config)}
Test-Case 'New executable forces re-install before launch' {
 $invent=[pscustomobject]@{Programs=@($config.ProtectedPrograms)+@('C:\guard-test-only\new-component.exe');DesktopPath=$config.DesktopPath}
 Must-Reject {Assert-GuardInventory $config $invent}
}
Test-Case 'Desktop version path change refused' {
 $invent=[pscustomobject]@{Programs=@($config.ProtectedPrograms);DesktopPath='C:\guard-test-only\new-version\claude.exe'}
 Must-Reject {Assert-GuardInventory $config $invent}
}
Test-Case 'Real routing audit and approved node pin pass' {Assert-GuardRouting $config;Assert-GuardRoutingUnchanged $config}
Test-Case 'Routing baseline change refused' {
 $saved=$script:GuardRoutingBaseline
 try {$script:GuardRoutingBaseline='changed';Must-Reject {Assert-GuardRoutingUnchanged $config}}finally{$script:GuardRoutingBaseline=$saved}
}
Test-Case 'Unavailable local proxy closes an isolated localhost process' {
 $owned=[ClaudeGuardJob]::new((Join-Path $env:SystemRoot 'System32\ping.exe'),[string[]]@('-n','30','127.0.0.1'),$PSScriptRoot,$false)
 $ownedId=$owned.ProcessId
 $unavailable=[pscustomobject]@{Proxy='http://127.0.0.1:1'}
 try {
  if(!$owned.IsRunning){throw 'Owned localhost test did not start.'}
  Must-Reject {Invoke-GuardWatch $owned {Assert-GuardProxyPort $unavailable} {} 2}
  Start-Sleep -Milliseconds 500
  if(Get-Process -Id $ownedId -ErrorAction SilentlyContinue){throw 'Owned localhost process survived proxy failure.'}
 }finally{$owned.Dispose()}
}
Test-Case 'Windows PowerShell status updates replace the existing JSON atomically' {
 $savedPath=$script:GuardStatusPath
 $script:GuardStatusPath=Join-Path $PSScriptRoot ('.state\status-regression-'+[guid]::NewGuid().ToString('N')+'.json')
 try {
  Write-GuardStatus 'checking-components' 'first'
  Write-GuardStatus 'ready' 'second'
  $actual=Get-Content -LiteralPath $script:GuardStatusPath -Raw -Encoding UTF8|ConvertFrom-Json
  if($actual.Phase -ne 'ready' -or $actual.Detail -ne 'second' -or $actual.MonitorPid -ne $PID){throw 'Repeated status update was not preserved.'}
 }finally{$script:GuardStatusPath=$savedPath}
}
$receipt=[pscustomobject]@{Time=(Get-Date).ToString('o');Passed=@($results | Where-Object Passed).Count;Failed=@($results | Where-Object {!$_.Passed}).Count;RealProcessShutdownTested=$true;Tests=@($results.ToArray())}
[IO.File]::WriteAllText((Join-Path $PSScriptRoot '.state\test-results.json'),($receipt|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
$receipt | Select-Object Time,Passed,Failed,RealProcessShutdownTested | ConvertTo-Json -Compress
if($receipt.Failed){exit 1}