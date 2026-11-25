# Offline regression tests for GuardianUpdatePolicy-v3.1.ps1.
# No networking, Docker, SQL or installed Guardian files touched.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\candidates\GuardianUpdatePolicy-v3.1.ps1')
$count=0
function Good([string]$label,[scriptblock]$test) {& $test; $script:count++; Write-Output ('PASS='+$label)}
function Block([string]$label,[scriptblock]$test) {
 $blocked=$false
 try {& $test | Out-Null$global:LASTEXITCODE=0
} catch {$blocked=$true}
 if(-not $blocked){throw ('EXPECTED_BLOCK_MISSING:'+ $label)}
 $script:count++; Write-Output ('PASS='+$label)
}
$rsa=New-Object Security.Cryptography.RSACryptoServiceProvider(3072)
try {
 $rsa.PersistKeyInCsp=$false
 $public=$rsa.ToXmlString($false)
 $v='3.0.1'; $url='https://github.com/melucasariel/agent-updater/releases/download/v3.0.1/guardian-3.0.1.zip'
 $sha=('a'*64)
 $payload=$v+"`n"+$url+"`n"+$sha
 $sig=[Convert]::ToBase64String($rsa.SignData([Text.Encoding]::UTF8.GetBytes($payload),'SHA256'))
 $m=[pscustomobject]@{version=$v;bundle_url=$url;bundle_sha256=$sha;signature_base64=$sig}
 Good 'VALID_SIGNED_RELEASE' {if(-not (Assert-R62Manifest -Manifest $m -PinnedPublicKeyXml $public -CurrentVersion '3.0.0')){throw 'VALIDATION_FAILED'}}
 Block 'DOWNGRADE' {Assert-R62Upgrade '3.0.2' '3.0.1'}
 Block 'REPLAY' {Assert-R62Upgrade '3.0.1' '3.0.1'}
 Good 'NUMERIC_COMPARISON' {Assert-R62Upgrade '3.0.9' '3.0.10'}
 Block 'BAD_VERSION' {ConvertTo-R62Version '3.01.2'}
 Block 'WRONG_DOMAIN' {Assert-R62ReleaseUri 'https://evil.example/releases/download/v3.0.1/package.zip'}
 Block 'WRONG_REPO' {Assert-R62ReleaseUri 'https://github.com/other/repo/releases/download/v3.0.1/package.zip'}
 Block 'MALICIOUS_QUERY' {Assert-R62ReleaseUri ($url+'?x=1')}
 Block 'VERSION_MISMATCH' {
  $x=[pscustomobject]@{version='3.0.2';bundle_url=$url;bundle_sha256=$sha;signature_base64=$sig}
  Assert-R62Manifest -Manifest $x -PinnedPublicKeyXml $public -CurrentVersion '3.0.0'
 }
 Block 'TAMPERED_HASH' {
  $x=[pscustomobject]@{version=$v;bundle_url=$url;bundle_sha256=('b'*64);signature_base64=$sig}
  Assert-R62Manifest -Manifest $x -PinnedPublicKeyXml $public -CurrentVersion '3.0.0'
 }
 Block 'TAMPERED_SIGNATURE' {
  $x=[pscustomobject]@{version=$v;bundle_url=$url;bundle_sha256=$sha;signature_base64=([Convert]::ToBase64String((New-Object byte[] 384)))}
  Assert-R62Manifest -Manifest $x -PinnedPublicKeyXml $public -CurrentVersion '3.0.0'
 }
 Write-Output ('TESTS_DESIGNED='+$count)
 Write-Output '[LIMIT] Requires offline execution on Windows PowerShell; no installation tested.'
} finally {$rsa.Dispose()}
