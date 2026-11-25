# ROTA62 Bridge V6: offline contract validator; NEVER executes a request.
# PowerShell 5.1+; no network, database, Docker, or secret access.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RequestPath)
$ErrorActionPreference = 'Stop'
function Reject([string]$why) { Write-Output ("[BLOQUEADO] " + $why); exit 2 }
try {
  $item = Get-Item -LiteralPath $RequestPath -ErrorAction Stop
  if ($item.PSIsContainer -or $item.Length -gt 4096) { Reject 'INVALID_REQUEST_SIZE' }
  $json = [IO.File]::ReadAllText($item.FullName, [Text.Encoding]::UTF8)
  $req = ConvertFrom-Json -InputObject $json
  $expected = @('protocol_version','request_id','command','issued_at','expires_at','nonce','signature')
  $actual = @($req.PSObject.Properties.Name)
  if (@($actual | Where-Object { $_ -notin $expected }).Count -gt 0 -or
      @($expected | Where-Object { $_ -notin $actual }).Count -gt 0) { Reject 'INVALID_FIELDS' }
  if ($req.protocol_version -cne '6.0') { Reject 'INVALID_PROTOCOL' }
  if ($req.command -cnotin @('SELFTEST','AUDIT_PREFLIGHT','STOP')) { Reject 'DISALLOWED_COMMAND' }
  if ([string]$req.request_id -cnotmatch '^[a-zA-Z0-9-]{8,64}$') { Reject 'INVALID_REQUEST_ID' }
  if ([string]$req.nonce -cnotmatch '^[a-zA-Z0-9_-]{16,128}$') { Reject 'INVALID_NONCE' }
  if ([string]$req.signature -notmatch '^[A-Za-z0-9+/]+={0,2}$' -or [string]$req.signature -eq '') { Reject 'SIGNATURE_MISSING' }
  $issued = [DateTimeOffset]::Parse([string]$req.issued_at, [Globalization.CultureInfo]::InvariantCulture)
  $expires = [DateTimeOffset]::Parse([string]$req.expires_at, [Globalization.CultureInfo]::InvariantCulture)
  $now = [DateTimeOffset]::UtcNow
  if ($issued -gt $now.AddMinutes(2) -or $expires -le $now -or $expires -gt $issued.AddMinutes(5)) { Reject 'INVALID_TIME_WINDOW' }
  # A syntactically valid signature is NOT an authenticated signature.
  # Authenticity, replay prevention and destination must be checked by a future trusted agent.
  Write-Output '[OK] REQUEST_STRUCTURE_VALID'
  Write-Output '[BLOQUEADO] SIGNATURE_NOT_VERIFIED_NO_EXECUTION'
  exit 3
} catch {
  Write-Output '[BLOQUEADO] INVALID_REQUEST_OR_ENVIRONMENT'
  exit 2
}
