# ROTA62 Guardian - one-time LOCAL signing trust bootstrap.
# This does NOT turn on automatic updates or install remotely downloaded scripts.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$agent = Join-Path $root 'GuardianAgent_v3.ps1'
$updater = Join-Path $root 'GuardianUpdater.ps1'
$privateFile = Join-Path $root 'signing-private.dpapi'
$publicFile = Join-Path $root 'signing-public.xml'
$feedFile = Join-Path $root 'update_source.json'
try {
  if (!(Test-Path -LiteralPath $agent -PathType Leaf) -or !(Test-Path -LiteralPath $updater -PathType Leaf)) {
    throw 'Guardian v3 local not found. No files changed.'
  }
  if (!(Test-Path -LiteralPath $root -PathType Container)) { throw 'Guardian config directory missing.' }
  $rsa = $null
  if (!(Test-Path -LiteralPath $privateFile)) {
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(3072)
    $rsa.PersistKeyInCsp = $false
    $privateXml = $rsa.ToXmlString($true)
    $publicXml = $rsa.ToXmlString($false)
    $bytes = [Text.Encoding]::UTF8.GetBytes($privateXml)
    try {
      $encrypted = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
      [IO.File]::WriteAllBytes($privateFile, $encrypted)
      [IO.File]::WriteAllText($publicFile, $publicXml, (New-Object Text.UTF8Encoding($false)))
    } finally { [Array]::Clear($bytes,0,$bytes.Length) }
    Write-Output '[OK] Local signing key initialized with DPAPI CurrentUser.'
  } else {
    if (!(Test-Path -LiteralPath $publicFile)) { throw 'Private key exists but public key missing. No replacement performed.' }
    Write-Output '[OK] Existing local signing key preserved.'
  }
  if (!(Test-Path -LiteralPath $feedFile)) {
    $safe = [ordered]@{ manifest_url=''; public_key_xml='' }
    [IO.File]::WriteAllText($feedFile, ($safe | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
    Write-Output '[OK] Empty trusted feed configuration created. Remote updates DISABLED.'
  } else {
    $cfg = Get-Content -LiteralPath $feedFile -Raw | ConvertFrom-Json
    if ([string]::IsNullOrWhiteSpace([string]$cfg.manifest_url) -or [string]::IsNullOrWhiteSpace([string]$cfg.public_key_xml)) {
      Write-Output '[OK] Remote updates remain disabled.'
    } else {
      Write-Output '[INFO] Feed already configured; this script did not modify it.'
    }
  }
  Write-Output '[OK] Guardian files unchanged; no Docker, SQL or HTTP request executed.'
  Write-Output '[NEXT] Harden updater and validate signature/rollback before enabling remote install.'
  $safeReport = 'GUARDIAN_TRUST_BOOTSTRAP=OK; DPAPI_KEY=LOCAL_ONLY; REMOTE_UPDATE=UNCHANGED'
  try { Set-Clipboard -Value $safeReport -ErrorAction Stop; Write-Output '[OK] Safe report copied to clipboard.' }
  catch { Write-Output '[INFO] Clipboard not available; status printed above.' }
} catch {
  $safeError = $_.Exception.Message -replace '(?i)[a-f0-9]{32,}', '[OCULTO]'
  Write-Output ('[BLOQUEADO] '+$safeError)
  exit 1
} finally { if ($rsa) { $rsa.Dispose() } }
