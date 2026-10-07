. (Join-Path $PSScriptRoot 'GuardCore.ps1')
. (Join-Path $PSScriptRoot 'GuardRouting.ps1')
. (Join-Path $PSScriptRoot 'GuardInventory.ps1')
. (Join-Path $PSScriptRoot 'GuardRuntime.ps1')
function Get-SetupDomains($clients){
 $domains=@()
 if(@($clients|Where-Object{$_.Kind -in @('Code','Desktop')}).Count){$domains+=@('claude.ai','api.anthropic.com','auth.anthropic.com','claude.com','claudeusercontent.com','claudemcpclient.com','claudemcpcontent.com')}
 if(@($clients|Where-Object{$_.Kind -in @('CodexCode','CodexDesktop')}).Count){$domains+=@('chatgpt.com','api.openai.com','auth.openai.com','ab.chatgpt.com','cdn.oaistatic.com','files.oaiusercontent.com')}
 return $domains
}
function Assert-SetupProxy([string]$proxy){
 $uri=$null
 if(![uri]::TryCreate($proxy,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'http' -or $uri.Host -ne '127.0.0.1' -or $uri.Port -lt 1 -or $uri.Port -gt 65535 -or $uri.UserInfo -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment){throw 'Use an explicit loopback HTTP proxy.'}
}
function Get-SetupTrace([string]$text){
 $fields=@{};foreach($line in $text -split '\r?\n'){if($line -match '^([a-z_]+)=(.*)$'){$fields[$matches[1]]=$matches[2].Trim()}}
 $ip=$null
 if(!$fields.ip -or ![ipaddress]::TryParse($fields.ip,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $fields.loc -notmatch '^[A-Z]{2}$'){throw 'The HTTP proxy did not return a valid IPv4 exit.'}
 $b=$ip.GetAddressBytes()
 if($b[0] -in @(0,10,127) -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)){throw 'The observed exit is not a public IPv4 address.'}
 return [pscustomobject]@{IP=$ip.ToString();Country=$fields.loc}
}
function Invoke-SetupTrace([string]$proxy,[string]$url){
 Assert-SetupProxy $proxy
 $curl=Join-Path $env:SystemRoot 'System32\curl.exe';$previous=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$raw=& $curl --silent --show-error --fail --ipv4 --proxy $proxy --noproxy 'localhost,127.0.0.1,::1' --connect-timeout 2 --max-time 8 $url 2>&1;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$previous}
 if($code -ne 0){throw ('HTTP proxy probe failed for '+([uri]$url).Host+' (curl '+$code+'). No direct fallback was attempted.')}
 return Get-SetupTrace ($raw -join "`n")
}
function Get-SetupReviewHash($config){
 $review=[ordered]@{Proxy=$config.Proxy;FlClashDirectory=$config.FlClashDirectory;PythonPath=$config.PythonPath;IP=$config.ExpectedIPv4;Country=$config.ExpectedCountry;RoutingPin=$config.RoutingPin;Clients=@($config.Clients|Sort-Object Id|ForEach-Object{[ordered]@{Id=$_.Id;Path=$_.Path;Version=$_.Version;Stamps=@($_.ProgramStamps);Programs=@($_.Programs|Sort-Object -Unique)}});ProbeUrls=@($config.ProbeUrls);Domains=@($config.ProtectedDomains);UDP=[bool]$config.RequireBrowserUDP;IPv6Policy=$config.IPv6Policy}
 $sha=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($review|ConvertTo-Json -Depth 15 -Compress)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
}
function New-SetupCandidate($selection,$discovery){
 Assert-SetupProxy ([string]$selection.Proxy)
 $ids=@($selection.ClientIds|Sort-Object -Unique)
 if(!$ids.Count){throw 'Select at least one installed client.'}
 $clients=@($discovery.Clients|Where-Object{$_.Id -in $ids -and $_.Supported -ne $false})
 if($clients.Count -ne $ids.Count){throw 'A selected client is unavailable or unsupported. Scan again.'}
 $fl=if($selection.FlClashDirectory){[string]$selection.FlClashDirectory}else{[string]$discovery.FlClashDirectory}
 foreach($file in 'config.yaml','shared_preferences.json','database.sqlite'){if(!(Test-Path -LiteralPath (Join-Path $fl $file) -PathType Leaf)){throw 'A working FlClash configuration is required. Select its configuration folder.'}}
 $python=Ensure-GuardPython ([string]$discovery.PythonPath) ([string]$selection.Proxy) ([bool]$selection.AllowRuntimeDownload)
 $urls=@();if(@($clients|Where-Object{$_.Kind -in @('Code','Desktop')}).Count){$urls+=@('https://api.anthropic.com/cdn-cgi/trace','https://claude.ai/cdn-cgi/trace')};if(@($clients|Where-Object{$_.Kind -in @('CodexCode','CodexDesktop')}).Count){$urls+='https://chatgpt.com/cdn-cgi/trace'}
 $config=[pscustomobject]@{SchemaVersion=3;Proxy=[string]$selection.Proxy;ExpectedIPv4='';ExpectedCountry='';ProbeTimeoutSeconds=8;CheckIntervalSeconds=5;ProbeUrls=$urls;Clients=$clients;CodePath=[string]($clients|Where-Object Kind -eq 'Code'|Select-Object -First 1).Path;DesktopPath=[string]($clients|Where-Object Kind -eq 'Desktop'|Select-Object -First 1).Path;ProtectedPrograms=@($clients|ForEach-Object{@($_.Programs)+@($_.Path)}|Sort-Object -Unique);ProtectedDomains=@(Get-SetupDomains $clients);FlClashDirectory=$fl;PythonPath=$python;RoutingPin=$null;RequireBrowserUDP=[bool]$selection.RequireBrowserUDP;IPv6Policy='PerProgram';Approval=$null}
 $inputPath=Join-Path $script:GuardRoot ('.state\setup-audit-'+[guid]::NewGuid().ToString('N')+'.json')
 [IO.File]::WriteAllText($inputPath,($config|ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))
 $raw=& $python -X utf8 (Join-Path $script:GuardRoot 'GuardRouteAudit.py') $inputPath;$exit=$LASTEXITCODE
 $route=($raw -join "`n")|ConvertFrom-Json
 if($exit -ne 0 -or !$route.ok){throw ('FlClash routing is not ready: '+$route.error)}
 $config.RoutingPin=[pscustomobject]@{Group=$route.group;ProfileId=$route.profileId;SelectedNodeSHA256=$route.selectedNodeSHA256}
 $exitInfo=$null
 foreach($url in $urls){$observed=Invoke-SetupTrace $config.Proxy $url;if($exitInfo -and ($observed.IP -ne $exitInfo.IP -or $observed.Country -ne $exitInfo.Country)){throw 'Selected clients do not share one exit. Align routing and test again.'};$exitInfo=$observed}
 $config.ExpectedIPv4=$exitInfo.IP;$config.ExpectedCountry=$exitInfo.Country
 [IO.File]::WriteAllText($inputPath,($config|ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))
 $raw=& $python -X utf8 (Join-Path $script:GuardRoot 'GuardRouteAudit.py') $inputPath;$code=$LASTEXITCODE
 $final=($raw -join "`n")|ConvertFrom-Json
 if($code -ne 0 -or !$final.ok -or $final.configSHA256 -ne $route.configSHA256){throw 'Routing changed during the exit check. Test again.'}
 return [pscustomobject]@{Time=([datetimeoffset]::Now).ToString('o');Config=$config;NodeName=$route.selectedNode;RoutingSHA256=$route.configSHA256;ReviewHash=(Get-SetupReviewHash $config);Confirmed=$false;OwnerSID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
}
function Assert-SetupReview($candidate,[bool]$confirmed,[string]$reviewHash){
 if(!$confirmed){throw 'Exit confirmation is required before enabling protection.'}
 if(!$candidate.Config -or $reviewHash -notmatch '^[a-f0-9]{64}$' -or $reviewHash -ne $candidate.ReviewHash -or $reviewHash -ne (Get-SetupReviewHash $candidate.Config)){throw 'Reviewed configuration changed. Test and confirm again.'}
 $age=[datetimeoffset]::Now-[datetimeoffset]$candidate.Time
 if($age.TotalSeconds -lt -10 -or $age.TotalMinutes -gt 5){throw 'The exit check expired. Test and confirm again.'}
 if($candidate.OwnerSID -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'The Windows user who reviewed the result must enable it.'}
 Assert-SetupProxy $candidate.Config.Proxy
}
function Enable-SetupCandidate($candidate,[bool]$confirmed,[string]$reviewHash){
 Assert-SetupReview $candidate $confirmed $reviewHash
 $config=$candidate.Config
 $selection=[pscustomobject]@{ClientIds=@($config.Clients.Id);Proxy=$config.Proxy;FlClashDirectory=$config.FlClashDirectory;AllowRuntimeDownload=$false;RequireBrowserUDP=$config.RequireBrowserUDP}
 $discovery=Get-GuardDiscovery;$discovery.PythonPath=$config.PythonPath
 $fresh=New-SetupCandidate $selection $discovery
 if($fresh.ReviewHash -ne $reviewHash -or $fresh.RoutingSHA256 -ne $candidate.RoutingSHA256){throw 'Exit, client or node changed after confirmation. Review the new result first.'}
 $config.Approval=[pscustomobject]@{Confirmed=$true;ReviewedAt=([datetimeoffset]::Now).ToString('o');ReviewHash=$reviewHash;OwnerSID=$candidate.OwnerSID}
 $approvedPath=Join-Path $script:GuardRoot ('.state\setup-approved-'+[guid]::NewGuid().ToString('N')+'.json')
 [IO.File]::WriteAllText($approvedPath,($config|ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))
 $powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $arguments='-NoProfile -File "'+(Join-Path $script:GuardRoot 'ClaudeGuard.ps1')+'" -Mode Install -ConfigFile "'+$approvedPath+'" -ReviewHash '+$reviewHash
 $proc=Start-Process -FilePath $powershell -ArgumentList $arguments -WindowStyle Hidden -PassThru -Wait
 if($proc.ExitCode -ne 0){throw 'Protection installation failed or administrator authorization was canceled. Existing configuration was preserved.'}
 $arguments='-NoProfile -File "'+(Join-Path $script:GuardRoot 'ClaudeGuard.ps1')+'" -Mode Check -Client '+[string]$config.Clients[0].Kind+' -ConfigFile "'+$approvedPath+'"'
 $proc=Start-Process -FilePath $powershell -ArgumentList $arguments -WindowStyle Hidden -PassThru -Wait
 if($proc.ExitCode -ne 0){throw 'Post-install checks failed. Previous configuration was preserved; direct-block rules remain fail-closed.'}
 $config=Get-Content -LiteralPath $approvedPath -Raw -Encoding UTF8|ConvertFrom-Json
 $config|Add-Member NoteProperty SetupComplete $true -Force
 $config|Add-Member NoteProperty InstalledAt ([datetimeoffset]::Now).ToString('o') -Force
 $path=Join-Path $script:GuardRoot 'guard-config.json';$temp=Join-Path $script:GuardRoot ('.state\setup-final-'+[guid]::NewGuid().ToString('N')+'.json')
 [IO.File]::WriteAllText($temp,($config|ConvertTo-Json -Depth 15),[Text.UTF8Encoding]::new($false))
 if(Test-Path -LiteralPath $path){[IO.File]::Replace($temp,$path,(Join-Path $script:GuardRoot ('.state\setup-before-'+[guid]::NewGuid().ToString('N')+'.json')))}else{[IO.File]::Move($temp,$path)}
 return [pscustomobject]@{Ready=$true;Programs=@($config.ProtectedPrograms).Count;Clients=@($config.Clients).Count}
}
function Test-SetupRequired {
 $path=Join-Path $script:GuardRoot 'guard-config.json'
 if(!(Test-Path -LiteralPath $path)){return $true}
 try{$config=Get-Content -LiteralPath $path -Raw -Encoding UTF8|ConvertFrom-Json
  if($config.SchemaVersion -ge 3){return (!$config.SetupComplete -or !$config.Approval.Confirmed)}
  return (!$config.ExpectedIPv4 -or $config.ExpectedIPv4 -eq '192.0.2.10' -or !(Test-Path -LiteralPath $config.FlClashDirectory))
 }catch{return $true}
}