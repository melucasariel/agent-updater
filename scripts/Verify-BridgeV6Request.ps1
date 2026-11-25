# ROTA62 Bridge V6: cryptographic request validator only. No execution.
# Compatible with Windows PowerShell 5.1 and PowerShell 7+.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$RequestPath,
  [Parameter(Mandatory=$true)][string]$PinnedPublicKeyPath
)
$ErrorActionPreference='Stop'
function Deny([string]$code) { Write-Output "[BLOQUEADO] $code"; exit 2 }
try {
  $file=Get-Item -LiteralPath $RequestPath -ErrorAction Stop
  $key=Get-Item -LiteralPath $PinnedPublicKeyPath -ErrorAction Stop
  if($file.PSIsContainer -or $file.Length -gt 4096 -or $key.PSIsContainer -or $key.Length -gt 8192) { Deny 'INVALID_INPUT_SIZE' }
  $req=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($file.FullName,[Text.Encoding]::UTF8))
  $fields=@('protocol_version','request_id','command','issued_at','expires_at','nonce','signature')
  $actual=@($req.PSObject.Properties.Name)
  if(@($actual | Where-Object {$_ -cnotin $fields}).Count -gt 0 -or @($fields | Where-Object {$_ -cnotin $actual}).Count -gt 0) { Deny 'INVALID_FIELDS' }
  if($req.protocol_version -cne '6.0') { Deny 'INVALID_PROTOCOL' }
  if($req.command -cnotin @('SELFTEST','AUDIT_PREFLIGHT','STOP')) { Deny 'DISALLOWED_COMMAND' }
  if([string]$req.request_id -cnotmatch '^[a-zA-Z0-9-]{8,64}$') { Deny 'INVALID_REQUEST_ID' }
  if([string]$req.nonce -cnotmatch '^[a-zA-Z0-9_-]{16,128}$') { Deny 'INVALID_NONCE' }
  if([string]$req.signature -cnotmatch '^[A-Za-z0-9+/]+={0,2}$') { Deny 'INVALID_SIGNATURE_ENCODING' }
  $issued=[DateTimeOffset]::ParseExact([string]$req.issued_at,'yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)
  $expires=[DateTimeOffset]::ParseExact([string]$req.expires_at,'yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)
  $now=[DateTimeOffset]::UtcNow
  if($issued -gt $now.AddMinutes(2) -or $expires -le $now -or $expires -le $issued -or $expires -gt $issued.AddMinutes(5)) { Deny 'INVALID_TIME_WINDOW' }
  $sig=[Convert]::FromBase64String([string]$req.signature)
  $xml=[IO.File]::ReadAllText($key.FullName,[Text.Encoding]::UTF8)
  if($xml -notmatch '^\s*<RSAKeyValue>' -or $xml -match '<D>|<P>|<Q>|<DP>|<DQ>|<InverseQ>') { Deny 'INVALID_PINNED_PUBLIC_KEY' }
  # Exact UTF-8 payload: domain separation + LF-delimited fields, no trailing LF.
  $payload='ROTA62-BRIDGE-V6' + "`n" + $req.protocol_version + "`n" + $req.request_id + "`n" + $req.command + "`n" + $req.issued_at + "`n" + $req.expires_at + "`n" + $req.nonce
  $data=[Text.Encoding]::UTF8.GetBytes($payload)
  $rsa=New-Object Security.Cryptography.RSACryptoServiceProvider
  try {
    $rsa.PersistKeyInCsp=$false
    $rsa.FromXmlString($xml)
    if($rsa.KeySize -lt 2048) { Deny 'WEAK_PUBLIC_KEY' }
    if(-not $rsa.VerifyData($data,'SHA256',$sig)) { Deny 'SIGNATURE_VERIFICATION_FAILED' }
  } finally { $rsa.Dispose() }
  Write-Output '[OK] REQUEST_SIGNATURE_VERIFIED'
  Write-Output '[BLOQUEADO] NO_LOCAL_EXECUTION_REPLAY_PROTECTION_REQUIRED'
  exit 3
} catch {
  Write-Output '[BLOQUEADO] INVALID_REQUEST_OR_CRYPTO_ENVIRONMENT'
  exit 2
}
