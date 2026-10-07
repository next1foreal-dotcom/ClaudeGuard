$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GuardSetupCore.ps1')
$tests=[Collections.Generic.List[string]]::new()
function Verify([string]$name,[scriptblock]$body){& $body;$tests.Add($name)}
function Reject([scriptblock]$body){$rejected=$false;try{& $body}catch{$rejected=$true};if(!$rejected){throw 'Expected rejection'}}
$cc=[pscustomobject]@{Id='claude-code';Name='Claude Code';Kind='Code';Path='C:\fixture\claude.exe';Programs=@('C:\fixture\claude.exe');Version='1';Supported=$true;ProgramStamps=@(@{Path='C:\fixture\claude.exe';Length=123;Modified='100'})}
$desktop=[pscustomobject]@{Id='claude-desktop';Kind='Desktop';Path='C:\fixture\desktop.exe';Programs=@('C:\fixture\desktop.exe');Version='1';Supported=$true}
$fixture=[pscustomobject]@{Clients=@($cc,$desktop)}
$config=[pscustomobject]@{SchemaVersion=3;Clients=@($cc);ProtectedPrograms=@($cc.Path);CodePath=$cc.Path;DesktopPath='';Proxy='http://127.0.0.1:17890';ExpectedIPv4='192.0.2.10';ExpectedCountry='TW';RoutingPin=@{Group='Review';ProfileId='1';SelectedNodeSHA256=('a'*64)};ProbeUrls=@('https://claude.ai/cdn-cgi/trace');ProtectedDomains=@('claude.ai');IPv6Policy='PerProgram';RequireBrowserUDP=$false;FlClashDirectory='C:\fixture\FlClash';PythonPath='C:\fixture\python.exe'}
Verify 'Only selected installed client is registered' {$inventory=Get-GuardInventory $config $fixture;Assert-GuardInventory $config $inventory;if($inventory.Programs.Count -ne 1 -or $inventory.DesktopPath){throw 'Unselected desktop included'}}
Verify 'Missing selected program blocks launch' {Reject {Get-GuardInventory $config ([pscustomobject]@{Clients=@($desktop)})}}
Verify 'New executable blocks launch' {$copy=$cc|ConvertTo-Json -Depth 8|ConvertFrom-Json;$copy.Programs+=@('C:\fixture\new.exe');Reject {Assert-GuardInventory $config (Get-GuardInventory $config ([pscustomobject]@{Clients=@($copy)}))}}
Verify 'Same-path binary update blocks launch' {$copy=$cc|ConvertTo-Json -Depth 8|ConvertFrom-Json;$copy.ProgramStamps[0].Modified='200';Reject {Assert-GuardInventory $config (Get-GuardInventory $config ([pscustomobject]@{Clients=@($copy)}))}}
Verify 'Shared node runtime is excluded' {$native=@(Get-GuardClientsFromSources -Sources @([pscustomobject]@{Id='codex-code';Path='C:\fixture\codex.exe';Programs=@('C:\fixture\codex.exe','C:\fixture\node.exe')}));if($native.Count -ne 1 -or $native[0].Programs.Count -ne 1){throw 'Shared runtime was included'}}
Verify 'Native Claude PATH path is recognized' {if((Get-GuardClientIdForPath 'C:\fixture\.local\bin\claude.exe') -ne 'claude-code'){throw 'Native path missed'}}
Verify 'Variable HTTP port accepted' {Assert-SetupProxy $config.Proxy}
Verify 'SOCKS and credentials rejected' {Reject {Assert-SetupProxy 'socks5://127.0.0.1:1080'};Reject {Assert-SetupProxy 'http://user:secret@127.0.0.1:7890'};Reject {Assert-SetupProxy 'http://127.0.0.1:7890/path'}}
Verify 'Proxy discovery does not approve a candidate' {$proxies=@(Get-GuardProxyCandidatesFromSources -Environment @{HTTP_PROXY='http://127.0.0.1:17890';ALL_PROXY='socks5://127.0.0.1:1080'});if($proxies.Count -ne 1 -or $proxies[0].Confirmed){throw 'Candidate auto approved'}}
$config|Add-Member NoteProperty Approval $null -Force
$candidate=[pscustomobject]@{Config=$config;ReviewHash=(Get-SetupReviewHash $config);OwnerSID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Time=[datetimeoffset]::Now.ToString('o')}
Verify 'Unconfirmed observed exit rejected before installation' {Reject {Assert-SetupReview $candidate $false $candidate.ReviewHash}}
Verify 'Explicit confirmed exact result accepted' {Assert-SetupReview $candidate $true $candidate.ReviewHash}
Verify 'Changed IP requires another confirmation' {$config.ExpectedIPv4='192.0.2.11';Reject {Assert-SetupReview $candidate $true $candidate.ReviewHash};$config.ExpectedIPv4='192.0.2.10'}
Verify 'Changed node requires another confirmation' {$config.RoutingPin.SelectedNodeSHA256='b'*64;Reject {Assert-SetupReview $candidate $true $candidate.ReviewHash};$config.RoutingPin.SelectedNodeSHA256='a'*64}
Verify 'Expired observation rejected' {$candidate.Time=[datetimeoffset]::Now.AddMinutes(-6).ToString('o');Reject {Assert-SetupReview $candidate $true $candidate.ReviewHash};$candidate.Time=[datetimeoffset]::Now.ToString('o')}
Verify 'Different reviewer rejected' {$sid=$candidate.OwnerSID;$candidate.OwnerSID='S-1-0-0';Reject {Assert-SetupReview $candidate $true $candidate.ReviewHash};$candidate.OwnerSID=$sid}
Verify 'Private and IPv6 exit rejected' {Reject {Get-SetupTrace "ip=192.168.1.2`nloc=TW"};Reject {Get-SetupTrace "ip=2001:db8::1`nloc=TW"}}
Verify 'Monitor supports one, two and three selected trace endpoints' {
 foreach($count in @(1,2,3)){$samples=@(1..$count|ForEach-Object{[pscustomobject]@{ok=$true;ip='192.0.2.10';country='TW'}});if(!(Test-GuardTraceObservations $samples $count)){throw 'Fixed endpoint count remains'}}
 $samples[2].ip='192.0.2.11';if(Test-GuardTraceObservations $samples 3){throw 'Disagreeing exit passed'}
 $samples[2].ok=$false;if(Test-GuardTraceObservations $samples 3){throw 'Missing endpoint passed'}
}
# Exercise the complete persistence transaction in an owned fixture directory.
# Child processes are mocked; no administrator prompt or firewall operation occurs.
$realRoot=$script:GuardRoot;$sandbox=Join-Path $realRoot ('.state\setup-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $sandbox '.state') -Force|Out-Null
$script:FixtureCandidate=$candidate;$script:FixtureCandidate|Add-Member NoteProperty RoutingSHA256 ('c'*64) -Force
$script:MockInstallExit=0;$script:MockCheckExit=0;$script:MockCalls=0
function Get-GuardDiscovery {return [pscustomobject]@{Clients=@($cc);PythonPath=$config.PythonPath}}
function New-SetupCandidate($selection,$discovery){return $script:FixtureCandidate}
function Start-Process {
 param($FilePath,$ArgumentList,[switch]$PassThru,[switch]$Wait,$WindowStyle)
 $script:MockCalls++
 if($ArgumentList -match '-Mode Install'){return [pscustomobject]@{ExitCode=$script:MockInstallExit}}
 if($ArgumentList -match '-Mode Check'){return [pscustomobject]@{ExitCode=$script:MockCheckExit}}
 throw 'Unexpected setup child process'
}
try{
 $script:GuardRoot=$sandbox;$existing=Join-Path $sandbox 'guard-config.json';[IO.File]::WriteAllText($existing,'{"Existing":"preserve"}',[Text.UTF8Encoding]::new($false));$saved=(Get-FileHash $existing).Hash
 Verify 'No confirmation means no installer or config write' {$script:MockCalls=0;Reject {Enable-SetupCandidate $candidate $false $candidate.ReviewHash};if($script:MockCalls -or (Get-FileHash $existing).Hash -ne $saved){throw 'Unconfirmed setup changed state'}}
 Verify 'Failed administrator installation preserves old configuration' {$script:MockInstallExit=1;$script:MockCalls=0;Reject {Enable-SetupCandidate $candidate $true $candidate.ReviewHash};if($script:MockCalls -ne 1 -or (Get-FileHash $existing).Hash -ne $saved){throw 'Failed install replaced approved config'}}
 Verify 'Failed post-install check preserves old configuration' {$script:MockInstallExit=0;$script:MockCheckExit=1;$script:MockCalls=0;Reject {Enable-SetupCandidate $candidate $true $candidate.ReviewHash};if($script:MockCalls -ne 2 -or (Get-FileHash $existing).Hash -ne $saved){throw 'Failed verification replaced approved config'}}
 Verify 'Only completed installation and verification persist approval' {$script:MockCheckExit=0;$script:MockCalls=0;$result=Enable-SetupCandidate $candidate $true $candidate.ReviewHash;$stored=Get-Content $existing -Raw|ConvertFrom-Json;if(!$result.Ready -or !$stored.SetupComplete -or !$stored.Approval.Confirmed -or $script:MockCalls -ne 2){throw 'Incomplete setup was persisted'}}
}finally{$script:GuardRoot=$realRoot}
[pscustomobject]@{Passed=$tests.Count;Failed=0;Tests=$tests.ToArray();NetworkRequests=$false;FirewallMutations=$false}|ConvertTo-Json -Depth 4