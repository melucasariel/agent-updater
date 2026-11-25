# ROTA62 Guardian v3 manifest signer. Offline: does not upload or execute the update.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidatePattern('^3\.[0-9]{1,4}\.[0-9]{1,4}$')][string]$Version,
  [Parameter(Mandatory=$true)][string]$BundleZip,
  [Parameter(Mandatory=$true)][string]$BundleUrl,
  [Parameter(Mandatory=$true)][string]$OutputDir
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security -ErrorAction Stop
$root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$privateFile=Join-Path $root 'signing-private.dpapi'
if (!(Test-Path -LiteralPath $privateFile)){throw 'Run Initialize-GuardianSigning.ps1 locally first.'}
$u=$null
if(-not [Uri]::TryCreate($BundleUrl,[UriKind]::Absolute,[ref]$u) -or $u.Scheme -cne 'https' -or $u.Host -cne 'github.com' -or $u.AbsolutePath -notmatch '^/melucasariel/agent-updater/releases/download/'){throw 'Package URL must be official Guardian GitHub Release URL.'}
if (!(Test-Path -LiteralPath $BundleZip -PathType Leaf)){throw 'Package ZIP not found.'}
if((Get-Item -LiteralPath $BundleZip).Length -gt 2000000){throw 'Package exceeds 2 MB.'}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $BundleZip).Path)
try{
 $entries=@($archive.Entries)
 if($entries.Count -ne 1 -or $entries[0].FullName -cne 'GuardianAgent.ps1' -or $entries[0].Length -gt 100000){throw 'Only a single GuardianAgent.ps1 file is authorized inside ZIP.'}
}finally{$archive.Dispose()}
$hash=(Get-FileHash -LiteralPath $BundleZip -Algorithm SHA256).Hash.ToLowerInvariant()
$payload=$Version+"`n"+$BundleUrl+"`n"+$hash
$protected=[IO.File]::ReadAllBytes($privateFile)
$plain=[System.Security.Cryptography.ProtectedData]::Unprotect($protected,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)
$rsa=New-Object Security.Cryptography.RSACryptoServiceProvider
try{
 $rsa.PersistKeyInCsp=$false
 $xml=[Text.Encoding]::UTF8.GetString($plain)
 $rsa.FromXmlString($xml)
 $signature=[Convert]::ToBase64String($rsa.SignData([Text.Encoding]::UTF8.GetBytes($payload),'SHA256'))
}finally{
 [Array]::Clear($plain,0,$plain.Length)
 $rsa.Dispose()
}
if(!(Test-Path -LiteralPath $OutputDir)){New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null}
$manifest=[ordered]@{version=$Version;bundle_url=$BundleUrl;bundle_sha256=$hash;signature_base64=$signature}
$outFile=Join-Path $OutputDir 'release.json'
[IO.File]::WriteAllText($outFile,($manifest|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
Write-Output '[OK] Signed release.json generated locally.'
Write-Output ('MANIFEST_PATH='+$outFile)
Write-Output ('BUNDLE_SHA256='+$hash)
Write-Output '[SECURITY] This script did not upload or install the package.'
