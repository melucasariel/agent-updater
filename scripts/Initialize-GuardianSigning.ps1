# ROTA62 Guardian - one-time local key generation. NEVER run this on a shared machine.
# Windows PowerShell 5.1. Private key is DPAPI-protected for CurrentUser.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$keyPath = Join-Path $root 'signing-private.dpapi'
$pubPath = Join-Path $root 'signing-public.xml'
if (Test-Path -LiteralPath $keyPath) { throw 'Signing key already exists. Refusing to overwrite it.' }
if (!(Test-Path -LiteralPath $root)) { New-Item -Path $root -ItemType Directory -Force | Out-Null }
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(3072)
try {
  $rsa.PersistKeyInCsp = $false
  $privateXml = $rsa.ToXmlString($true)
  $publicXml = $rsa.ToXmlString($false)
  $plain = [Text.Encoding]::UTF8.GetBytes($privateXml)
  $protected = [Security.Cryptography.ProtectedData]::Protect($plain,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
  [IO.File]::WriteAllBytes($keyPath,$protected)
  [IO.File]::WriteAllText($pubPath,$publicXml,(New-Object Text.UTF8Encoding($false)))
  [Array]::Clear($plain,0,$plain.Length)
  Write-Output '[OK] Local signing key created; private key is DPAPI CurrentUser encrypted.'
  Write-Output ('PUBLIC_KEY_FILE='+$pubPath)
  Write-Output '[NEXT] Configure Guardian update_source.json with public_key_xml from public file and an approved manifest_url.'
  Write-Output '[SECURITY] Never upload signing-private.dpapi, private XML or secrets to GitHub.'
} finally { $rsa.Dispose() }
