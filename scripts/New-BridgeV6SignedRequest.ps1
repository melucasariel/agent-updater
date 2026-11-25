# ROTA62 Bridge V6 - offline test request signer.
# Only signs three named commands. The private key is read locally and never printed.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet('SELFTEST','AUDIT_PREFLIGHT','STOP')][string]$Command,
 [Parameter(Mandatory=$true)][string]$PrivateKeyXmlPath,
 [Parameter(Mandatory=$true)][string]$OutputPath
)
$ErrorActionPreference='Stop'
try {
 $path=[IO.Path]::GetFullPath($PrivateKeyXmlPath)
 $k=Get-Item -LiteralPath $path
 if($k.PSIsContainer -or $k.Length -gt 16384){throw 'Invalid private key file'}
 $xml=[IO.File]::ReadAllText($path,[Text.Encoding]::UTF8)
 if($xml -notmatch '<D>' -or $xml -notmatch '<RSAKeyValue>'){throw 'Expected local RSA private key'}
 $rsa=[Security.Cryptography.RSACryptoServiceProvider]::new()
 $rsa.PersistKeyInCsp=$false
 try {
   $rsa.FromXmlString($xml)
   if($rsa.KeySize -lt 2048){throw 'Key below 2048 bits'}
   $issued=[DateTimeOffset]::UtcNow
   $nonceBytes=[byte[]]::new(24)
   [Security.Cryptography.RandomNumberGenerator]::Fill($nonceBytes)
   $requestId=[guid]::NewGuid().ToString('D')
   $nonce=([Convert]::ToBase64String($nonceBytes)).TrimEnd('=').Replace('+','-').Replace('/','_')
   $req=[ordered]@{
     protocol_version='6.0'; request_id=$requestId; command=$Command;
     issued_at=$issued.ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture);
     expires_at=$issued.AddMinutes(3).ToString('yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture);
     nonce=$nonce; signature=''
   }
   $payload=@('ROTA62-BRIDGE-V6',$req.protocol_version,$req.request_id,$req.command,$req.issued_at,$req.expires_at,$req.nonce) -join "`n"
   $sig=$rsa.SignData([Text.Encoding]::UTF8.GetBytes($payload),'SHA256')
   $req.signature=[Convert]::ToBase64String($sig)
   $dest=[IO.Path]::GetFullPath($OutputPath)
   $parent=[IO.Path]::GetDirectoryName($dest)
   if(-not [IO.Directory]::Exists($parent)){throw 'Output directory not found'}
   if([IO.File]::Exists($dest)){throw 'Refusing to overwrite existing request'}
   [IO.File]::WriteAllText($dest,($req|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
   Write-Output '[OK] SIGNED_REQUEST_CREATED_NO_NETWORK'
 } finally {$rsa.Dispose()}
} catch {
 Write-Output '[BLOQUEADO] SIGN_REQUEST_FAILED'
 exit 2
}
