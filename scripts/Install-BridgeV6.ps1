# ROTA62 Bridge V6 guarded local installer. Does not download or run remote code.
# Usage from a manually reviewed trusted checkout:
#   .\scripts\Install-BridgeV6.ps1 -PinnedPublicKeyPath C:\trusted\bridge-public.xml -Install
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$PinnedPublicKeyPath,
 [string]$Destination=(Join-Path $env:LOCALAPPDATA 'ROTA62_BridgeV6'),
 [switch]$Install
)
$ErrorActionPreference='Stop'
function Fail([string]$code){Write-Output "[BLOQUEADO] $code";exit 2}
try {
 $root=[IO.Path]::GetFullPath($Destination)
 $source=$PSScriptRoot
 $publicKey=[IO.Path]::GetFullPath($PinnedPublicKeyPath)
 if(-not (Test-Path -LiteralPath $publicKey -PathType Leaf)){Fail 'PINNED_PUBLIC_KEY_MISSING'}
 if($root -eq $source -or $root.StartsWith($source+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){Fail 'DESTINATION_INSIDE_SOURCE'}
 $xml=[IO.File]::ReadAllText($publicKey,[Text.Encoding]::UTF8)
 if($xml -notmatch '^\s*<RSAKeyValue>' -or $xml -match '<D>|<P>|<Q>|<DP>|<DQ>|<InverseQ>'){Fail 'PUBLIC_KEY_INVALID'}
 $rsa=New-Object Security.Cryptography.RSACryptoServiceProvider
 try {$rsa.PersistKeyInCsp=$false; $rsa.FromXmlString($xml); if($rsa.KeySize -lt 2048){Fail 'PUBLIC_KEY_TOO_WEAK'}} finally {$rsa.Dispose()}
 $required=@('Receive-BridgeV6.ps1','Verify-BridgeV6Request.ps1','Test-BridgeV6ReplayGuard.ps1')
 foreach($file in $required){
   $path=Join-Path $source $file
   if(-not (Test-Path -LiteralPath $path -PathType Leaf)){Fail 'REQUIRED_SOURCE_MISSING'}
   $tokens=$null;$errors=$null
   [void][Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
   if($errors.Count -gt 0){Fail 'POWERSHELL_SYNTAX_INVALID'}
 }
 if(-not $Install){
   Write-Output '[OK] LOCAL_INSTALL_PREFLIGHT_PASSED'
   Write-Output '[BLOQUEADO] DRY_RUN_ONLY_USE_EXPLICIT_INSTALL'
   exit 0
 }
 if(Test-Path -LiteralPath (Join-Path $root 'installed.version')){Fail 'EXISTING_INSTALL_REQUIRES_MIGRATION_REVIEW'}
 [IO.Directory]::CreateDirectory($root)|Out-Null
 $scripts=Join-Path $root 'scripts'
 [IO.Directory]::CreateDirectory($scripts)|Out-Null
 foreach($file in $required){Copy-Item -LiteralPath (Join-Path $source $file) -Destination (Join-Path $scripts $file) -ErrorAction Stop}
 $keyDest=Join-Path $root 'bridge-public.xml'
 if(Test-Path -LiteralPath $keyDest){Fail 'PUBLIC_KEY_ALREADY_PINNED'}
 [IO.File]::WriteAllText($keyDest,$xml,[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllText((Join-Path $root 'installed.version'),'6.0-candidate',[Text.UTF8Encoding]::new($false))
 Write-Output '[OK] BRIDGE_V6_FILES_STAGED'
 Write-Output '[INFO] NOT_STARTED_NO_AUTOSTART_NO_REMOTE_COMMAND_EXECUTION'
} catch {
 Write-Output '[BLOQUEADO] INSTALL_PREFLIGHT_OR_STAGING_FAILED'
 exit 2
}
