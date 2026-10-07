# ClaudeGuard read-only client and local proxy discovery.
# This file deliberately uses narrow, known roots. It does not launch network probes.

$script:GuardClientIds = @('claude-code','claude-desktop','codex-code','codex-desktop')
$script:GuardProxyProcessPattern = '(?i)(^|[\\/._ -])(flclash|clash|mihomo|sing-box|singbox|clash[- ]?verge)([.]exe)?$'
$script:GuardUnsupportedShims = @()

function ConvertTo-GuardFullPath {
    param([string]$Path)
    if([string]::IsNullOrWhiteSpace($Path)){ return '' }
    try { return [IO.Path]::GetFullPath($Path) } catch { return $Path }
}

function Test-GuardNativeExecutablePath {
    param([string]$Path)
    if([string]::IsNullOrWhiteSpace($Path)){ return $false }
    $leaf=[IO.Path]::GetFileName($Path)
    if([string]::IsNullOrWhiteSpace($leaf) -or $leaf -notmatch '(?i)[.]exe$'){ return $false }
    if($leaf -match '(?i)^node(?:64)?[.]exe$'){ return $false }
    return $true
}

function Get-GuardClientIdForPath {
    param([string]$Path,[string]$Kind)
    if($Kind){
        switch -Regex ($Kind) {
            '(?i)^Code$|ClaudeCode|claude-code' { return 'claude-code' }
            '(?i)^Desktop$|ClaudeDesktop|claude-desktop' { return 'claude-desktop' }
            '(?i)CodexCode|codex-code|CodexCLI' { return 'codex-code' }
            '(?i)CodexDesktop|codex-desktop' { return 'codex-desktop' }
        }
    }
    $p=([string]$Path).Replace('/','\\')
    if($p -match '(?i)\\WindowsApps\\Claude_[^\\]+\\app\\claude[.]exe$' -or $p -match '(?i)\\Claude[^\\]*\\app\\claude[.]exe$'){ return 'claude-desktop' }
    if($p -match '(?i)\\WindowsApps\\OpenAI[.]Codex_[^\\]+\\app\\ChatGPT[.]exe$'){ return 'codex-desktop' }
    if($p -match '(?i)\\[.]local\\(?:bin\\claude|share\\claude\\.*\\claude)[.]exe$' -or $p -match '(?i)\\node_modules\\@anthropic-ai\\claude-code\\.*\\claude[.]exe$'){ return 'claude-code' }
    if($p -match '(?i)\\node_modules\\@openai\\codex(?:-[^\\]+)?\\vendor\\.*\\codex[.]exe$' -or $p -match '(?i)\\@openai\\codex\\.*\\vendor\\.*\\codex[.]exe$'){ return 'codex-code' }
    return ''
}

function Get-GuardClientName {
    param([string]$Id)
    switch($Id){
        'claude-code' { return 'Claude Code' }
        'claude-desktop' { return 'Claude Desktop' }
        'codex-code' { return 'Codex CLI' }
        'codex-desktop' { return 'Codex Desktop' }
        default { return $Id }
    }
}

function Get-GuardClientKind {
    param([string]$Id)
    switch($Id){
        'claude-code' { return 'Code' }
        'claude-desktop' { return 'Desktop' }
        'codex-code' { return 'CodexCode' }
        'codex-desktop' { return 'CodexDesktop' }
        default { return '' }
    }
}

function Get-GuardVersionFromPath {
    param([string]$Path)
    if(!(Test-GuardNativeExecutablePath $Path) -or !(Test-Path -LiteralPath $Path -PathType Leaf)){ return '' }
    try {
        $v=(Get-Item -LiteralPath $Path -ErrorAction Stop).VersionInfo.ProductVersion
        if($v){ return [string]$v }
    } catch {}
    return ''
}

function New-GuardClientObject {
    param(
        [string]$Id,
        [string]$Path,
        [object[]]$Programs=@(),
        [string]$Version='',
        [bool]$Supported=$true,
        [string]$UnsupportedReason=''
    )
    if(!$Id){ return $null }
    $paths=New-Object Collections.Generic.List[string]
    foreach($candidate in @($Programs)+@($Path)){
        if(!(Test-GuardNativeExecutablePath ([string]$candidate))){ continue }
        $full=ConvertTo-GuardFullPath ([string]$candidate)
        if(!(@($paths | Where-Object { $_ -ieq $full }).Count)){ [void]$paths.Add($full) }
    }
    $main=''
    $prefer=@($paths | Where-Object {$_ -match '(?i)\\[.]local\\bin\\claude[.]exe$'}) | Select-Object -First 1
    if($prefer){$main=[string]$prefer}
    if(!$main){
        $prefer=@($paths | Where-Object {$_ -match '(?i)\\app\\(?:claude|ChatGPT)[.]exe$'}) | Select-Object -First 1
        if($prefer){$main=[string]$prefer}
    }
    if(!$main){
        $prefer=@($paths | Where-Object {$_ -match '(?i)\\(?:bin\\)?codex[.]exe$'}) | Select-Object -First 1
        if($prefer){$main=[string]$prefer}
    }
    if(!$main -and $paths.Count){$main=[string](@($paths|Sort-Object -Descending {[IO.File]::GetLastWriteTimeUtc($_)})[0])}
    if($Version -eq '' -and $main){$Version=Get-GuardVersionFromPath $main}
    return [pscustomobject]@{
        Id=$Id
        Name=(Get-GuardClientName $Id)
        Kind=(Get-GuardClientKind $Id)
        Path=$main
        Programs=@($paths | Sort-Object -Unique)
        Version=$Version
        ProgramStamps=@($paths|Sort-Object|ForEach-Object{if(Test-Path -LiteralPath $_ -PathType Leaf){$f=Get-Item -LiteralPath $_;[pscustomobject]@{Path=$f.FullName;Length=$f.Length;Modified=$f.LastWriteTimeUtc.Ticks.ToString()}}})
        Installed=([bool]$Supported -and [bool]$main)
        Supported=[bool]$Supported
        UnsupportedReason=$UnsupportedReason
    }
}

function Add-GuardSourceValue {
    param([hashtable]$Groups,[string]$Id,[string]$Path,[object[]]$Programs=@(),[string]$Version='',[string]$UnsupportedReason='')
    if(!$Id){ return }
    if(!$Groups.ContainsKey($Id)){
        $Groups[$Id]=[pscustomobject]@{Paths=New-Object Collections.Generic.List[string];Programs=New-Object Collections.Generic.List[string];Versions=New-Object Collections.Generic.List[string];UnsupportedReasons=New-Object Collections.Generic.List[string]}
    }
    $g=$Groups[$Id]
    foreach($p in @($Path)+@($Programs)){
        if(Test-GuardNativeExecutablePath ([string]$p)){
            $full=ConvertTo-GuardFullPath ([string]$p)
            if(!(@($g.Paths|Where-Object {$_ -ieq $full}).Count)){[void]$g.Paths.Add($full)}
            if(!(@($g.Programs|Where-Object {$_ -ieq $full}).Count)){[void]$g.Programs.Add($full)}
        }
    }
    if($Version){[void]$g.Versions.Add([string]$Version)}
    if($UnsupportedReason){[void]$g.UnsupportedReasons.Add([string]$UnsupportedReason)}
}

function Get-GuardClientsFromSources {
    [CmdletBinding()]
    param(
        [object[]]$Sources=@(),
        [object[]]$AppxPackages=@(),
        [object[]]$RunningProcesses=@(),
        [switch]$IncludeUnsupported
    )
    $groups=@{}
    foreach($source in @($Sources)){
        if($null -eq $source){continue}
        if($source -is [string]){
            $path=[string]$source; $id=Get-GuardClientIdForPath $path
            if($id){Add-GuardSourceValue $groups $id $path @() ''}
            continue
        }
        $path=''; foreach($prop in @('Path','ExecutablePath','Program','NativePath')){if($source.PSObject.Properties.Name -contains $prop -and $source.$prop){$path=[string]$source.$prop;break}}
        $id=''; if($source.PSObject.Properties.Name -contains 'Id'){$id=Get-GuardClientIdForPath $path ([string]$source.Id)}
        if(!$id -and $source.PSObject.Properties.Name -contains 'Kind'){$id=Get-GuardClientIdForPath $path ([string]$source.Kind)}
        if(!$id -and $source.PSObject.Properties.Name -contains 'Name'){$id=Get-GuardClientIdForPath $path ([string]$source.Name)}
        if(!$id){$id=Get-GuardClientIdForPath $path}
        if(!$id -and $source.PSObject.Properties.Name -contains 'UnsupportedReason'){
            $id='codex-code'
        }
        if(!$id){continue}
        $programs=@(); if($source.PSObject.Properties.Name -contains 'Programs'){$programs=@($source.Programs)}
        $version=''; if($source.PSObject.Properties.Name -contains 'Version' -and $source.Version){$version=[string]$source.Version}
        $reason=''; if($source.PSObject.Properties.Name -contains 'UnsupportedReason'){$reason=[string]$source.UnsupportedReason}
        if($source.PSObject.Properties.Name -contains 'Installed' -and $source.Installed -eq $false -and !$reason){$reason='Source reported that the executable is not installed.'}
        Add-GuardSourceValue $groups $id $path $programs $version $reason
    }
    foreach($pkg in @($AppxPackages)){
        if($null -eq $pkg){continue}
        $label=([string]$pkg.Name)+' '+([string]$pkg.PackageFamilyName)+' '+([string]$pkg.PackageFullName)
        $id=if($label -match '(?i)OpenAI[.]Codex|Codex'){ 'codex-desktop' } elseif($label -match '(?i)Claude'){ 'claude-desktop' } else {''}
        if(!$id){continue}
        $root=''; if($pkg.PSObject.Properties.Name -contains 'InstallLocation'){$root=[string]$pkg.InstallLocation}
        $programs=@(); $main=''
        if($root -and (Test-Path -LiteralPath $root -PathType Container)){
            $appRoot=Join-Path $root 'app'; if(Test-Path -LiteralPath $appRoot -PathType Container){$root=$appRoot}
            $programs=@(Get-ChildItem -LiteralPath $root -Filter '*.exe' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
            if($id -eq 'claude-desktop'){$main=@($programs|Where-Object {$_ -match '(?i)\\claude[.]exe$'}|Select-Object -First 1)}
            else {$main=@($programs|Where-Object {$_ -match '(?i)\\ChatGPT[.]exe$'}|Select-Object -First 1)}
        }
        if(!$main -and $pkg.PSObject.Properties.Name -contains 'Path'){$main=[string]$pkg.Path}
        $version=''; if($pkg.PSObject.Properties.Name -contains 'Version' -and $pkg.Version){$version=[string]$pkg.Version}
        Add-GuardSourceValue $groups $id ([string]$main) $programs $version
    }
    foreach($proc in @($RunningProcesses)){
        if($null -eq $proc){continue}
        $name=''; foreach($prop in @('Name','ProcessName','ImageName')){if($proc.PSObject.Properties.Name -contains $prop -and $proc.$prop){$name=[string]$proc.$prop;break}}
        $path=''; foreach($prop in @('Path','ExecutablePath','MainModulePath')){if($proc.PSObject.Properties.Name -contains $prop -and $proc.$prop){$path=[string]$proc.$prop;break}}
        $id=Get-GuardClientIdForPath $path $name
        if(!$id){continue}
        Add-GuardSourceValue $groups $id $path @() ''
    }
    $result=New-Object Collections.Generic.List[object]
    foreach($id in $script:GuardClientIds){
        if(!$groups.ContainsKey($id)){continue}
        $g=$groups[$id]
        $version=@($g.Versions|Where-Object {$_}|Select-Object -First 1)
        $client=New-GuardClientObject $id '' @($g.Programs) ([string]$version) $true ''
        if($client -and $client.Path){[void]$result.Add($client)}
        if($IncludeUnsupported -and @($g.UnsupportedReasons).Count -and (!$client -or !$client.Path)){
            $reason=[string](@($g.UnsupportedReasons)[0])
            [void]$result.Add([pscustomobject]@{Id=$id;Name=(Get-GuardClientName $id);Kind=(Get-GuardClientKind $id);Path='';Programs=@();Version='';Installed=$false;Supported=$false;UnsupportedReason=$reason})
        }
    }
    return @($result.ToArray())
}

function Get-GuardKnownProcessRecords {
    $records=New-Object Collections.Generic.List[object]
    $names=@('claude','codex','ChatGPT','FlClash','clash','mihomo','sing-box','singbox','clash-verge','clashverge')
    foreach($name in $names){
        foreach($p in @(Get-Process -Name $name -ErrorAction SilentlyContinue)){
            $path=''; try {$path=[string]$p.Path} catch {}
            if(!$path){try {$path=[string]$p.MainModule.FileName} catch {}}
            [void]$records.Add([pscustomobject]@{Id=$p.Id;Name=$p.ProcessName;Path=$path;ExecutablePath=$path})
        }
    }
    try {
        foreach($p in @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {$_.Name -match '(?i)^(claude|codex|ChatGPT|FlClash|clash|mihomo|sing-box|singbox|clash-verge|clashverge)([.]exe)?$'})){
            $path=''; if($p.ExecutablePath){$path=[string]$p.ExecutablePath}
            if(!(@($records|Where-Object {$_.Id -eq $p.ProcessId -and $_.Path -ieq $path}).Count)){
                [void]$records.Add([pscustomobject]@{Id=$p.ProcessId;Name=$p.Name;Path=$path;ExecutablePath=$path;CommandLine=[string]$p.CommandLine})
            }
        }
    } catch {}
    return @($records.ToArray())
}

function Get-GuardNativePathsUnderRoot {
    param([string]$Root,[string]$Filter='*.exe',[string]$Pattern='')
    if([string]::IsNullOrWhiteSpace($Root) -or !(Test-Path -LiteralPath $Root -PathType Container)){return @()}
    $paths=@(Get-ChildItem -LiteralPath $Root -Filter $Filter -File -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    if($Pattern){$paths=@($paths|Where-Object {$_ -match $Pattern})}
    return @($paths|Where-Object {Test-GuardNativeExecutablePath $_}|Sort-Object -Unique)
}

function Get-GuardCommandNativePath {
    param([string]$CommandName,[string]$MatchPattern)
    $found=New-Object Collections.Generic.List[string]
    foreach($cmd in @(Get-Command $CommandName -ErrorAction SilentlyContinue)){
        $path=[string]$cmd.Source; if(!$path){$path=[string]$cmd.Path}
        if((Test-GuardNativeExecutablePath $path) -and (!$MatchPattern -or $path -match $MatchPattern)){[void]$found.Add($path);continue}
        if(!$path -or !(Test-Path -LiteralPath $path -PathType Leaf)){continue}
        try {
            $text=Get-Content -LiteralPath $path -Raw -ErrorAction Stop
            foreach($m in [regex]::Matches($text,'["'']([^"'']+[.]exe)')){
                $candidate=[string]$m.Groups[1].Value
                if($candidate -match '^(?i)[A-Z]:[\\/]' -and (Test-GuardNativeExecutablePath $candidate) -and (!$MatchPattern -or $candidate -match $MatchPattern) -and (Test-Path -LiteralPath $candidate -PathType Leaf)){[void]$found.Add($candidate);continue}
                $basedir=Split-Path $path -Parent
                $candidate=Join-Path $basedir $candidate
                if((Test-GuardNativeExecutablePath $candidate) -and (!$MatchPattern -or $candidate -match $MatchPattern) -and (Test-Path -LiteralPath $candidate -PathType Leaf)){[void]$found.Add($candidate)}
            }
        } catch {}
    }
    return @($found|Sort-Object -Unique)
}

function Get-GuardClients {
    [CmdletBinding()]
    param(
        [object[]]$SourceRecords,
        [object[]]$AppxPackages,
        [object[]]$RunningProcesses,
        [switch]$IncludeUnsupported
    )
    $hasFixtures=$PSBoundParameters.ContainsKey('SourceRecords') -or $PSBoundParameters.ContainsKey('AppxPackages') -or $PSBoundParameters.ContainsKey('RunningProcesses')
    if($hasFixtures){
        $items=@(Get-GuardClientsFromSources -Sources @($SourceRecords) -AppxPackages @($AppxPackages) -RunningProcesses @($RunningProcesses) -IncludeUnsupported:$IncludeUnsupported)
        $script:GuardUnsupportedShims=@($items|Where-Object {$_.Supported -eq $false})
        if(!$IncludeUnsupported){$items=@($items|Where-Object {$_.Supported -ne $false})}
        return @($items)
    }
    $records=New-Object Collections.Generic.List[object]
    $claudeRoots=@()
    if($env:USERPROFILE){$claudeRoots+=@(Join-Path $env:USERPROFILE '.local\bin');$claudeRoots+=@(Join-Path $env:USERPROFILE '.local\share\claude')}
    $claudeRoots+=@(Join-Path $env:APPDATA 'npm\node_modules\@anthropic-ai\claude-code')
    $claudeRoots+=@(Join-Path $env:LOCALAPPDATA 'Claude-3p\claude-code')
    foreach($root in $claudeRoots){foreach($p in @(Get-GuardNativePathsUnderRoot $root 'claude.exe' '(?i)\\claude[.]exe$')){[void]$records.Add([pscustomobject]@{Id='claude-code';Path=$p;Programs=@($p)})}}
    foreach($p in @(Get-GuardCommandNativePath 'claude' '(?i)\\claude[.]exe$')){[void]$records.Add([pscustomobject]@{Id='claude-code';Path=$p;Programs=@($p)})}
    $appx=@()
    try { $appx+=@(Get-AppxPackage -Name Claude -ErrorAction SilentlyContinue) } catch {}
    try { $appx+=@(Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '(?i)^(OpenAI[.]Codex|Codex)'}) } catch {}
    foreach($pkg in @($appx)){
        $label=([string]$pkg.Name)+' '+([string]$pkg.PackageFullName)
        $id=if($label -match '(?i)OpenAI[.]Codex|Codex'){'codex-desktop'}else{'claude-desktop'}
        $root=Join-Path ([string]$pkg.InstallLocation) 'app'
        $programs=@(Get-GuardNativePathsUnderRoot $root '*.exe')
        $main=if($id -eq 'claude-desktop'){@($programs|Where-Object {$_ -match '(?i)\\claude[.]exe$'}|Select-Object -First 1)}else{@($programs|Where-Object {$_ -match '(?i)\\ChatGPT[.]exe$'}|Select-Object -First 1)}
        [void]$records.Add([pscustomobject]@{Id=$id;Path=[string]$main;Programs=$programs;Version=[string]$pkg.Version})
    }
    $codexRoots=@()
    if($env:APPDATA){$codexRoots+=@(Join-Path $env:APPDATA 'npm\node_modules\@openai\codex')}
    if($env:LOCALAPPDATA){$codexRoots+=@(Join-Path $env:LOCALAPPDATA 'pnpm\global\5\node_modules\@openai\codex');$codexRoots+=@(Join-Path $env:LOCALAPPDATA 'pnpm\global\5\.pnpm')}
    foreach($root in $codexRoots){foreach($p in @(Get-GuardNativePathsUnderRoot $root '*.exe' '(?i)\\@openai\\codex[^\\]*\\vendor\\.*\\codex[.]exe$')){[void]$records.Add([pscustomobject]@{Id='codex-code';Path=$p;Programs=@($p)})}}
    foreach($p in @(Get-GuardCommandNativePath 'codex' '(?i)\\@openai\\codex[^\\]*\\vendor\\.*\\codex[.]exe$')){[void]$records.Add([pscustomobject]@{Id='codex-code';Path=$p;Programs=@($p)})}
    foreach($proc in @(Get-GuardKnownProcessRecords)){
        $id=Get-GuardClientIdForPath ([string]$proc.Path) ([string]$proc.Name)
        if($id){[void]$records.Add([pscustomobject]@{Id=$id;Path=[string]$proc.Path;Programs=@([string]$proc.Path)})}
    }
    $native=@(Get-GuardClientsFromSources -Sources $records.ToArray() -AppxPackages @($appx) -RunningProcesses @())
    $shim=@(Get-Command codex -ErrorAction SilentlyContinue | Where-Object {[string]$_.Path -match '(?i)[.](cmd|ps1|bat)$'})
    $unsupported=New-Object Collections.Generic.List[object]
    if(!(@($native|Where-Object {$_.Id -eq 'codex-code'}).Count) -and $shim.Count){
        [void]$unsupported.Add([pscustomobject]@{Id='codex-code';Name='Codex CLI';Kind='CodexCode';Path='';Programs=@();Version='';Installed=$false;Supported=$false;UnsupportedReason='Codex CLI shim was found, but no native vendor codex.exe was resolved. Shared node.exe is not an approved protected executable.'})
    }
    $script:GuardUnsupportedShims=@($unsupported.ToArray())
    if($IncludeUnsupported){return @($native)+@($unsupported.ToArray())}
    return @($native)
}

function ConvertTo-GuardHttpProxyCandidate {
    param([string]$Value,[string]$Source)
    if([string]::IsNullOrWhiteSpace($Value)){return $null}
    $raw=$Value.Trim()
    if($raw -match '(?i)^[^:/?#]+:[^@/]+@'){return $null}
    if($raw -notmatch '^[a-zA-Z][a-zA-Z0-9+.-]*://'){$raw='http://'+$raw}
    try {$uri=[uri]$raw} catch {return $null}
    if($uri.Scheme -ine 'http' -or $uri.UserInfo){return $null}
    $proxyHost=$uri.Host
    $loop=$false
    try {$ip=[ipaddress]$proxyHost;$loop=[ipaddress]::IsLoopback($ip)} catch {$loop=($proxyHost -ieq 'localhost')}
    if(!$loop){return $null}
    $port=$uri.Port; if($port -lt 1 -or $port -gt 65535){return $null}
    $hostOut=if($proxyHost -ieq 'localhost'){'127.0.0.1'}else{$proxyHost}
    return [pscustomobject]@{Proxy=('http://'+$hostOut+':'+$port);Source=[string]$Source}
}

function Get-GuardProxyCandidatesFromSources {
    [CmdletBinding()]
    param(
        [object[]]$TcpConnections=@(),
        [object[]]$RunningProcesses=@(),
        [object]$SystemProxy,
        [hashtable]$Environment
    )
    $items=New-Object Collections.Generic.List[object]
    $add={param($value,$source) $candidate=ConvertTo-GuardHttpProxyCandidate ([string]$value) ([string]$source); if($candidate -and !(@($items|Where-Object {$_.Proxy -ieq $candidate.Proxy}).Count)){[void]$items.Add($candidate)}}
    $envMap=@{}; if($Environment){foreach($key in $Environment.Keys){$envMap[[string]$key]=[string]$Environment[$key]}}
    if(!$Environment){foreach($key in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')){$envMap[$key]=[string](Get-Item -Path ('Env:'+ $key) -ErrorAction SilentlyContinue).Value}}
    foreach($key in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')){if($envMap.ContainsKey($key)){&$add $envMap[$key] ('env:'+ $key.ToLowerInvariant())}}
    if($SystemProxy){
        $values=New-Object Collections.Generic.List[object]
        foreach($prop in @('ProxyServer','Http','Https','Address','Proxy','Url')){if($SystemProxy.PSObject.Properties.Name -contains $prop -and $SystemProxy.$prop){[void]$values.Add([pscustomobject]@{Value=[string]$SystemProxy.$prop;Source='system:'+ $prop})}}
        foreach($v in @($values.ToArray())){
            foreach($part in ([string]$v.Value -split ';')){
                $piece=$part.Trim(); if(!$piece){continue}
                $schemeSource=[string]$v.Source
                if($piece -match '^([^=]+)=(.+)$'){$scheme=$matches[1].Trim();$piece=$matches[2].Trim();$schemeSource+=':'+ $scheme.ToLowerInvariant();if($scheme -match '(?i)socks|ftp') {continue}}
                &$add $piece $schemeSource
            }
        }
    }
    $known=@{}
    foreach($proc in @($RunningProcesses)){
        $id=''; foreach($prop in @('Id','ProcessId','OwningProcess')){if($proc.PSObject.Properties.Name -contains $prop -and $proc.$prop){$id=[string]$proc.$prop;break}}
        $name=''; foreach($prop in @('Name','ProcessName','ImageName')){if($proc.PSObject.Properties.Name -contains $prop -and $proc.$prop){$name=[string]$proc.$prop;break}}
        if($id){$known[$id]=$name}
    }
    foreach($conn in @($TcpConnections)){
        $state='Listen'; if($conn.PSObject.Properties.Name -contains 'State' -and $conn.State){$state=[string]$conn.State}
        if($state -notmatch '(?i)listen'){continue}
        $name=''; if($conn.PSObject.Properties.Name -contains 'ProcessName'){$name=[string]$conn.ProcessName}
        $owner=''; foreach($prop in @('OwningProcess','ProcessId','Id')){if($conn.PSObject.Properties.Name -contains $prop -and $conn.$prop){$owner=[string]$conn.$prop;break}}
        if(!$name -and $owner -and $known.ContainsKey($owner)){$name=[string]$known[$owner]}
        if($name -notmatch $script:GuardProxyProcessPattern){continue}
        $addr=''; foreach($prop in @('LocalAddress','Address','IPAddress')){if($conn.PSObject.Properties.Name -contains $prop -and $conn.$prop){$addr=[string]$conn.$prop;break}}
        if($addr -and $addr -notmatch '^(?:::|0[.]0[.]0[.]0|127[.]0[.]0[.]1|[[]::1[]]|::1)$' -and $addr -notmatch '(?i)^localhost$'){continue}
        $port=0; foreach($prop in @('LocalPort','Port')){if($conn.PSObject.Properties.Name -contains $prop -and $conn.$prop){$port=[int]$conn.$prop;break}}
        if($port -ge 1 -and $port -le 65535){&$add ('http://127.0.0.1:'+ $port) ('process:'+ $name +':'+ $port)}
    }
    return @($items.ToArray())
}

function Get-GuardSystemProxySource {
    try {
        $r=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
        if($r.ProxyEnable -eq 1 -and $r.ProxyServer){return [pscustomobject]@{ProxyServer=[string]$r.ProxyServer}}
    } catch {}
    return $null
}

function Get-GuardFlClashDirectory {
    [CmdletBinding()]
    param([string[]]$CandidateDirectories,[object[]]$RunningProcesses)
    $candidates=New-Object Collections.Generic.List[string]
    if($CandidateDirectories){foreach($p in $CandidateDirectories){if($p){[void]$candidates.Add([string]$p)}}}
    else {
        foreach($p in @((Join-Path $env:APPDATA 'com.follow\clash'),(Join-Path $env:APPDATA 'FlClash'),(Join-Path $env:APPDATA 'flclash'),(Join-Path $env:LOCALAPPDATA 'FlClash'),(Join-Path $env:APPDATA 'clash'))){if($p){[void]$candidates.Add($p)}}
        foreach($proc in @(Get-GuardKnownProcessRecords)){
            $name=[string]$proc.Name; $path=[string]$proc.Path
            if($name -match $script:GuardProxyProcessPattern -and $path -and (Test-Path -LiteralPath $path -PathType Leaf)){[void]$candidates.Add((Split-Path $path -Parent))}
        }
    }
    foreach($p in @($candidates|Select-Object -Unique)){
        if((Test-Path -LiteralPath $p -PathType Container) -and (Test-Path -LiteralPath (Join-Path $p 'config.yaml') -PathType Leaf) -and (Test-Path -LiteralPath (Join-Path $p 'shared_preferences.json') -PathType Leaf) -and (Test-Path -LiteralPath (Join-Path $p 'database.sqlite') -PathType Leaf)){return (ConvertTo-GuardFullPath $p)}
    }
    return ''
}

function Test-GuardPythonYamlDirectory {
    param([string]$Path)
    if(!$Path){return $false}
    $dir=Split-Path $Path -Parent
    $candidates=@((Join-Path $dir 'Lib\site-packages\yaml\__init__.py'),(Join-Path (Split-Path $dir -Parent) 'Lib\site-packages\yaml\__init__.py'),(Join-Path $dir 'site-packages\yaml\__init__.py'))
    foreach($p in $candidates){if(Test-Path -LiteralPath $p -PathType Leaf){return $true}}
    return $false
}

function Get-GuardPythonPath {
    [CmdletBinding()]
    param([object[]]$Candidates)
    if($PSBoundParameters.ContainsKey('Candidates')){
        foreach($candidate in @($Candidates)){
            if($candidate -is [string]){$path=[string]$candidate;$has=$null;$exists=Test-Path -LiteralPath $path -PathType Leaf}
            else {$path=[string]$candidate.Path;$has=if($candidate.PSObject.Properties.Name -contains 'HasYaml'){$candidate.HasYaml}else{$null};$exists=if($candidate.PSObject.Properties.Name -contains 'Exists'){$candidate.Exists}else{Test-Path -LiteralPath $path -PathType Leaf}}
            if($exists -and ($has -eq $true -or ($null -eq $has -and (Test-GuardPythonYamlDirectory $path)))){return (ConvertTo-GuardFullPath $path)}
        }
        return ''
    }
    foreach($cmd in @(Get-Command python -ErrorAction SilentlyContinue)){ $path=[string]$cmd.Source;if(!$path){$path=[string]$cmd.Path};if((Test-Path -LiteralPath $path -PathType Leaf) -and (Test-GuardPythonYamlDirectory $path)){return (ConvertTo-GuardFullPath $path)} }
    foreach($candidate in @((Join-Path $env:LOCALAPPDATA 'Programs\Python\Python314\python.exe'),(Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'),(Join-Path $env:ProgramFiles 'Python314\python.exe'),(Join-Path $env:ProgramFiles 'Python313\python.exe'))){if((Test-Path -LiteralPath $candidate -PathType Leaf) -and (Test-GuardPythonYamlDirectory $candidate)){return (ConvertTo-GuardFullPath $candidate)}}
    return ''
}

function Get-GuardDiscovery {
    [CmdletBinding()]
    param(
        [object[]]$SourceRecords,
        [object[]]$AppxPackages,
        [object[]]$RunningProcesses,
        [object[]]$TcpConnections,
        [object]$SystemProxy,
        [hashtable]$Environment,
        [string[]]$FlClashDirectories,
        [object[]]$PythonCandidates
    )
    $fixture=$PSBoundParameters.ContainsKey('SourceRecords') -or $PSBoundParameters.ContainsKey('AppxPackages') -or $PSBoundParameters.ContainsKey('RunningProcesses') -or $PSBoundParameters.ContainsKey('TcpConnections') -or $PSBoundParameters.ContainsKey('SystemProxy') -or $PSBoundParameters.ContainsKey('Environment') -or $PSBoundParameters.ContainsKey('FlClashDirectories') -or $PSBoundParameters.ContainsKey('PythonCandidates')
    if($fixture){
        $clients=@(Get-GuardClients -SourceRecords @($SourceRecords) -AppxPackages @($AppxPackages) -RunningProcesses @($RunningProcesses))
        $unsupported=@(Get-GuardClients -SourceRecords @($SourceRecords) -AppxPackages @($AppxPackages) -RunningProcesses @($RunningProcesses) -IncludeUnsupported|Where-Object {$_.Supported -eq $false})
        $proxies=@(Get-GuardProxyCandidatesFromSources -TcpConnections @($TcpConnections) -RunningProcesses @($RunningProcesses) -SystemProxy $SystemProxy -Environment $Environment)
        $fl=Get-GuardFlClashDirectory -CandidateDirectories $FlClashDirectories -RunningProcesses $RunningProcesses
        $py=Get-GuardPythonPath -Candidates $PythonCandidates
    } else {
        $running=@(Get-GuardKnownProcessRecords)
        $clients=@(Get-GuardClients)
        $connections=@(); try {$connections=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)} catch {}
        $system=Get-GuardSystemProxySource
        $proxies=@(Get-GuardProxyCandidatesFromSources -TcpConnections $connections -RunningProcesses $running -SystemProxy $system)
        $fl=Get-GuardFlClashDirectory -RunningProcesses $running
        $py=Get-GuardPythonPath
        $unsupported=@($script:GuardUnsupportedShims)
    }
    $apps=New-Object Collections.Generic.List[string]
    foreach($proc in @($(if($fixture){$RunningProcesses}else{$running}))){$name='';foreach($prop in @('Name','ProcessName','ImageName')){if($proc.PSObject.Properties.Name -contains $prop -and $proc.$prop){$name=[string]$proc.$prop;break}};if($name -and $name -match $script:GuardProxyProcessPattern -and !(@($apps|Where-Object {$_ -ieq $name}).Count)){[void]$apps.Add($name)}}
    foreach($candidate in @($proxies|Where-Object {$_.Source -match '^process:'})){$n=([string]$candidate.Source -replace '^process:','') -replace ':[0-9]+$','';if($n -and !(@($apps|Where-Object {$_ -ieq $n}).Count)){[void]$apps.Add($n)}}
    return [pscustomobject]@{Clients=@($clients);UnsupportedShims=@($unsupported);ProxyCandidates=@($proxies);FlClashDirectory=[string]$fl;PythonPath=[string]$py;ProxyApps=@($apps|Sort-Object -Unique)}
}