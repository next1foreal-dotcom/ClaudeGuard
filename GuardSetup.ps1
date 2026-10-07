param([ValidateSet('Discover','Probe','Enable')][string]$Mode='Discover',[string]$InputFile,[string]$ResultFile,[string]$ReviewHash,[switch]$Confirmed)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'GuardSetupCore.ps1')
New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot '.state') -Force|Out-Null
$ResultFile=Get-GuardStatePath $ResultFile
if(!$ResultFile){throw 'Setup result path is required.'}
try{
 if($Mode -eq 'Discover'){$data=Get-GuardDiscovery}
 else{$InputFile=Get-GuardStatePath $InputFile;$request=Get-Content -LiteralPath $InputFile -Raw -Encoding UTF8|ConvertFrom-Json
  if($Mode -eq 'Probe'){$data=New-SetupCandidate $request (Get-GuardDiscovery)}else{$data=Enable-SetupCandidate $request ([bool]$Confirmed) $ReviewHash}}
 $result=@{ok=$true;Mode=$Mode;Data=$data;Time=(Get-Date).ToString('o')}
}catch{$result=@{ok=$false;Mode=$Mode;error=$_.Exception.Message;Time=(Get-Date).ToString('o')}}
[IO.File]::WriteAllText($ResultFile,($result|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))
if(!$result.ok){exit 1}