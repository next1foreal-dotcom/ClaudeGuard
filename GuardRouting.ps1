function Get-GuardRoutingSHA256([string]$path) {
 $stream=[IO.File]::OpenRead($path);$sha=[Security.Cryptography.SHA256]::Create()
 try{return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','')}finally{$sha.Dispose();$stream.Dispose()}
}
function Assert-GuardRouting($config) {
    if(!$config.RoutingPin -or !$config.RoutingPin.SelectedNodeSHA256){throw 'No approved proxy node pin is recorded.'}
    $raw=& $config.PythonPath -X utf8 (Join-Path $script:GuardRoot 'GuardRouteAudit.py') $(if($script:GuardConfigPath){$script:GuardConfigPath}else{Join-Path $script:GuardRoot 'guard-config.json'})
    $code=$LASTEXITCODE
    $result=$raw|ConvertFrom-Json
    if($code -ne 0 -or !$result.ok){throw ('Routing audit failed: '+$result.error)}
    if($script:GuardRoutingBaseline -and $script:GuardRoutingBaseline -ne $result.configSHA256){throw 'FlClash generated configuration changed during this session.'}
    $script:GuardRoutingBaseline=$result.configSHA256
    [IO.File]::WriteAllText((Join-Path $script:GuardRoot '.state\routing-receipt.json'),($result|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
}
function Assert-GuardRoutingUnchanged($config) {
    if((Get-GuardRoutingSHA256 (Join-Path $config.FlClashDirectory 'config.yaml')) -ine $script:GuardRoutingBaseline){throw 'FlClash configuration changed; the current Claude session must stop.'}
    $prefs=(Get-Content -LiteralPath (Join-Path $config.FlClashDirectory 'shared_preferences.json') -Raw -Encoding UTF8|ConvertFrom-Json).'flutter.config'|ConvertFrom-Json
    if($prefs.patchClashConfig.mode -ne 'rule'){throw 'FlClash was changed out of rule mode.'}
}
function Write-GuardStatus([string]$phase,[string]$detail) {
    if(!$script:GuardStatusPath){return}
    $data=[pscustomobject]@{Phase=$phase;Detail=$detail;Time=(Get-Date).ToString('o');MonitorPid=$PID;Client=$Client;ExpectedIPv4=$config.ExpectedIPv4;ExpectedCountry=$config.ExpectedCountry;ProtectedPrograms=@($config.ProtectedPrograms).Count}
    $temp=$script:GuardStatusPath+'.tmp'
    [IO.File]::WriteAllText($temp,($data|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
    if(Test-Path -LiteralPath $script:GuardStatusPath){[IO.File]::Replace($temp,$script:GuardStatusPath,[NullString]::Value)}else{[IO.File]::Move($temp,$script:GuardStatusPath)}
}
function Get-GuardStatePath([string]$path) {
    if(!$path){return $null}
    $full=[IO.Path]::GetFullPath($path)
    $root=[IO.Path]::GetFullPath((Join-Path $script:GuardRoot '.state'))+[IO.Path]::DirectorySeparatorChar
    if(!$full.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)){throw 'UI signal/status files must be inside ClaudeGuard/.state.'}
    return $full
}