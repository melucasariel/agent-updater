# ROTA62 Bridge V6 offline replay guard. NO COMMAND EXECUTION.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$RequestPath,
 [Parameter(Mandatory=$true)][string]$PinnedPublicKeyPath,
 [Parameter(Mandatory=$true)][string]$ReplayDirectory
)
$ErrorActionPreference='Stop'
function Block([string]$message){ Write-Output "[BLOQUEADO] $message"; exit 2 }
try {
 $verify=Join-Path $PSScriptRoot 'Verify-BridgeV6Request.ps1'
 $output=@(& $verify -RequestPath $RequestPath -PinnedPublicKeyPath $PinnedPublicKeyPath)
 if($LASTEXITCODE -ne 3 -or $output -notcontains '[OK] REQUEST_SIGNATURE_VERIFIED'){Block 'INVALID_OR_UNAUTHENTICATED_REQUEST'}
 $req=Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
 $directory=[IO.Path]::GetFullPath($ReplayDirectory)
 if(-not [IO.Directory]::Exists($directory)){Block 'REPLAY_DIR_MISSING'}
 $id=([string]$req.request_id).ToLowerInvariant()
 if($id -cnotmatch '^[a-z0-9-]{8,64}$'){Block 'INVALID_REQUEST_ID'}
 $nonce=[string]$req.nonce
 if($nonce -cnotmatch '^[a-zA-Z0-9_-]{16,128}$'){Block 'INVALID_NONCE'}
 # Reused request IDs are rejected even if a new nonce is signed.
 $sha=[Security.Cryptography.SHA256]::Create()
 $replayKey=([Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("ROTA62-V6-REQUEST-ID|$id")))).Replace('/','_').Replace('+','-').TrimEnd('=')
 $sha.Dispose()
 $file=Join-Path $directory ($replayKey+'.seen')
 # Atomic creation: a successful open is a reservation, and any existing file denies replay.
 $stream=[IO.File]::Open($file,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try {
  $bytes=[Text.Encoding]::UTF8.GetBytes([string]$req.expires_at)
  $stream.Write($bytes,0,$bytes.Length)
 } finally {$stream.Dispose()}
 Write-Output '[OK] SIGNATURE_VERIFIED_AND_REPLAY_RECORDED'
 Write-Output '[BLOQUEADO] NO_COMMAND_EXECUTION_TRANSPORT_NOT_CONFIGURED'
 exit 3
} catch [IO.IOException] {
 Block 'REPLAY_OR_STORAGE_ERROR'
} catch {
 Block 'REPLAY_GUARD_ERROR'
}
