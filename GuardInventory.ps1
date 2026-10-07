function Get-GuardInventory($config) {
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
function Assert-GuardInventory($config,$inventory) {
    $missing=@($inventory.Programs|Where-Object {$_ -notin $config.ProtectedPrograms})
    if($missing.Count -or $inventory.DesktopPath -ine $config.DesktopPath){throw ('New Claude version or '+$missing.Count+' unregistered executable(s) found. Run Install-Protection.cmd before starting Claude.')}
}
function Save-GuardInventory($config,$inventory) {
    $config.ProtectedPrograms=@($inventory.Programs)
    $config.DesktopPath=$inventory.DesktopPath
    $config.SchemaVersion=2
    $path=Join-Path $script:GuardRoot 'guard-config.json'
    $temp=Join-Path $script:GuardRoot '.state\guard-config-next.json'
    $backup=Join-Path $script:GuardRoot ('.state\guard-config-before-'+(Get-Date -Format 'yyyyMMdd-HHmmssfff')+'.json')
    [IO.File]::WriteAllText($temp,($config|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
    [IO.File]::Replace($temp,$path,$backup)
}