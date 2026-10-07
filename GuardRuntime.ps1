function Expand-GuardRuntimeArchive([string]$archive,[string]$destination){
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $rootPath=[IO.Path]::GetFullPath($destination)+[IO.Path]::DirectorySeparatorChar
 $zip=[IO.Compression.ZipFile]::OpenRead($archive)
 try{foreach($entry in $zip.Entries){$target=[IO.Path]::GetFullPath((Join-Path $destination $entry.FullName));if(!$target.StartsWith($rootPath,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe runtime archive path.'}}}finally{$zip.Dispose()}
 [IO.Compression.ZipFile]::ExtractToDirectory($archive,$destination)
}
function Save-GuardRuntimeDownload($item,[string]$path,[string]$proxy){
 $uri=[uri]$item.Url
 if($uri.Scheme -ne 'https' -or $uri.Host -notin @('www.python.org','files.pythonhosted.org') -or $item.SHA256 -notmatch '^[a-f0-9]{64}$'){throw 'Unexpected runtime download source.'}
 $client=[Net.WebClient]::new();$client.Proxy=[Net.WebProxy]::new($proxy)
 try{$client.DownloadFile($item.Url,$path)}finally{$client.Dispose()}
 if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $item.SHA256){throw 'Runtime download checksum mismatch.'}
}
function Ensure-GuardPython([string]$path,[string]$proxy,[bool]$allowDownload){
 if($path -and (Test-Path -LiteralPath $path -PathType Leaf)){
  $null=& $path -I -c 'import yaml,sqlite3' 2>$null
  if($LASTEXITCODE -eq 0){return $path}
 }
 $local=Join-Path $PSScriptRoot '.state\runtime\python\python.exe'
 if(Test-Path -LiteralPath $local){$null=& $local -I -c 'import yaml,sqlite3' 2>$null;if($LASTEXITCODE -eq 0){return $local}}
 if(!$allowDownload){throw 'Python with PyYAML is missing. Allow the tool-only runtime preparation or provide a working Python installation.'}
 if($env:PROCESSOR_ARCHITECTURE -ne 'AMD64'){throw 'Automatic runtime preparation currently requires Windows x64.'}
 $lock=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'runtime-lock.json') -Raw -Encoding UTF8|ConvertFrom-Json
 $stage=Join-Path $PSScriptRoot ('.state\runtime-stage-'+[guid]::NewGuid().ToString('N'))
 New-Item -ItemType Directory -Path $stage|Out-Null
 $pythonZip=Join-Path $stage 'python.zip';$yamlZip=Join-Path $stage 'yaml.zip'
 Save-GuardRuntimeDownload $lock.Python $pythonZip $proxy
 Save-GuardRuntimeDownload $lock.PyYAML $yamlZip $proxy
 $folder=Join-Path $stage 'python';Expand-GuardRuntimeArchive $pythonZip $folder
 $packages=Join-Path $folder 'site-packages';Expand-GuardRuntimeArchive $yamlZip $packages
 [IO.File]::WriteAllText((Join-Path $folder 'python313._pth'),"python313.zip`n.`nsite-packages`n..\..\..`nimport site`n",[Text.UTF8Encoding]::new($false))
 $exe=Join-Path $folder 'python.exe';$null=& $exe -I -c 'import yaml,sqlite3' 2>$null
 if($LASTEXITCODE -ne 0){throw 'Prepared runtime failed its import check.'}
 $runtime=Join-Path $PSScriptRoot '.state\runtime';New-Item -ItemType Directory -Path $runtime -Force|Out-Null
 $destination=Join-Path $runtime 'python'
 if(Test-Path -LiteralPath $destination){Move-Item -LiteralPath $destination -Destination (Join-Path $runtime ('python-before-'+[guid]::NewGuid().ToString('N')))}
 Move-Item -LiteralPath $folder -Destination $destination
 return (Join-Path $destination 'python.exe')
}