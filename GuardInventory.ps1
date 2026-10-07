function Get-LegacyGuardInventory($config) {
    $paths=New-Object Collections.Generic.List[string]
    foreach($p in @($config.ProtectedPrograms)) {if(Test-Path -LiteralPath $p -PathType Leaf){$paths.Add([IO.Path]::GetFullPath($p))}}
    $packages=@(Get-AppxPackage -Name Claude -ErrorAction Stop)
    if($packages.Count -ne 1){throw 'Expected exactly one installed Claude Desktop package for the current user.'}
    $package=$packages[0]
    $desktopRoot=Join-Path $package.InstallLocation 'app'
    $desktopPaths=@(Get-ChildItem -LiteralPath $desktopRoot -Filter '*.exe' -File -Recurse -ErrorAction Stop | Select-Object -ExpandProperty FullName)
    foreach($p in $desktopPaths){$paths.Add($p)}
    foreach($root in @((Join-Path $env:APPDATA 'npm\node_modules\@anthropic-ai\claude-code'),(Join-Path $env:LOCALAPPDATA 'Claude-3p\claude-code'))){
        if(Test-Path -LiteralPath $root){foreach($p in @(Get-ChildItem -LiteralPath $root -Filter '*.exe' -File -Recurse -ErrorAction Stop | Select-Object -ExpandProperty FullName)){$paths.Add($p)}}
    }
    $desktop=Join-Path $desktopRoot 'claude.exe'
    if(!(Test-Path -LiteralPath $config.CodePath -PathType Leaf)){throw 'Configured Claude Code executable is missing; review its new installation path.'}
    if(!(Test-Path -LiteralPath $desktop -PathType Leaf)){throw 'Claude Desktop main executable is missing.'}
    return [pscustomobject]@{Programs=@($paths.ToArray()|Sort-Object -Unique);DesktopPath=$desktop;DesktopVersion=$package.Version.ToString();DesktopComponents=$desktopPaths.Count;CodePath=$config.CodePath}
}
function Assert-LegacyGuardInventory($config,$inventory) {
    $missing=@($inventory.Programs|Where-Object {$_ -notin $config.ProtectedPrograms})
    if($missing.Count -or $inventory.DesktopPath -ine $config.DesktopPath){throw ('New Claude version or '+$missing.Count+' unregistered executable(s) found. Run Install-Protection.cmd before starting Claude.')}
}
function Save-LegacyGuardInventory($config,$inventory) {
    $config.ProtectedPrograms=@($inventory.Programs)
    $config.DesktopPath=$inventory.DesktopPath
    $config.SchemaVersion=2
    $path=if($script:GuardConfigPath){$script:GuardConfigPath}else{Join-Path $script:GuardRoot 'guard-config.json'}
    $temp=Join-Path $script:GuardRoot '.state\guard-config-next.json'
    $backup=Join-Path $script:GuardRoot ('.state\guard-config-before-'+(Get-Date -Format 'yyyyMMdd-HHmmssfff')+'.json')
    [IO.File]::WriteAllText($temp,($config|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    [IO.File]::Replace($temp,$path,$backup)
}
. (Join-Path $PSScriptRoot 'GuardDiscovery.ps1')
function Get-GuardInventory($config,$Discovery){
 if($config.SchemaVersion -lt 3){return Get-LegacyGuardInventory $config}
 if(!$Discovery){$Discovery=[pscustomobject]@{Clients=@(Get-GuardClients)}}
 $selected=@()
 foreach($registered in @($config.Clients)){
  $client=@($Discovery.Clients|Where-Object{$_.Id -eq $registered.Id -and $_.Supported -ne $false})|Select-Object -First 1
  if(!$client){throw ('Registered client is no longer installed: '+$registered.Id)}
  $selected+=@($client)
 }
 if(!$selected.Count){throw 'No selected installed client.'}
 $programs=@($selected|ForEach-Object{@($_.Programs)+@($_.Path)}|Where-Object{$_}|Sort-Object -Unique)
 if(@($programs|Where-Object{[IO.Path]::GetFileName($_) -match '^node(?:64)?\.exe$'}).Count){throw 'Shared Node.js cannot be registered as a client.'}
 $code=$selected|Where-Object Kind -eq 'Code'|Select-Object -First 1
 $desktop=$selected|Where-Object Kind -eq 'Desktop'|Select-Object -First 1
 return [pscustomobject]@{Programs=$programs;Clients=$selected;CodePath=[string]$code.Path;DesktopPath=[string]$desktop.Path;DesktopVersion=[string]$desktop.Version;DesktopComponents=@($desktop.Programs).Count}
}
function Assert-GuardInventory($config,$inventory){
 if($config.SchemaVersion -lt 3){Assert-LegacyGuardInventory $config $inventory;return}
 $difference=@(Compare-Object @($config.ProtectedPrograms|Sort-Object -Unique) @($inventory.Programs|Sort-Object -Unique))
 $moved=@($config.Clients|Where-Object{$old=$_;!@($inventory.Clients|Where-Object{$_.Id -eq $old.Id -and $_.Path -ieq $old.Path}).Count})
  $updated=@($config.Clients|Where-Object{
  $registered=$_;$live=@($inventory.Clients|Where-Object Id -eq $registered.Id)[0]
  $registered.Version -ne $live.Version -or ((@($registered.ProgramStamps)|ConvertTo-Json -Depth 5 -Compress) -ne (@($live.ProgramStamps)|ConvertTo-Json -Depth 5 -Compress))
 })
 if($difference.Count -or $moved.Count -or $updated.Count){throw 'A selected client was updated or moved. Update protection before starting it.'}
}
function Save-GuardInventory($config,$inventory){
 if($config.SchemaVersion -lt 3){Save-LegacyGuardInventory $config $inventory;return}
 $config.ProtectedPrograms=@($inventory.Programs);$config.Clients=@($inventory.Clients)
 $config.CodePath=$inventory.CodePath;$config.DesktopPath=$inventory.DesktopPath
 $path=if($script:GuardConfigPath){$script:GuardConfigPath}else{Join-Path $script:GuardRoot 'guard-config.json'}
 $temp=Join-Path $script:GuardRoot ('.state\inventory-'+[guid]::NewGuid().ToString('N')+'.json')
 [IO.File]::WriteAllText($temp,($config|ConvertTo-Json -Depth 12),[Text.UTF8Encoding]::new($false))
 [IO.File]::Replace($temp,$path,(Join-Path $script:GuardRoot ('.state\inventory-before-'+[guid]::NewGuid().ToString('N')+'.json')))
}