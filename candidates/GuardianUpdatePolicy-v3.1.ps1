# ROTA62 Guardian Update Policy v3.1 CANDIDATE
# Fail-closed policy module: check-only integration; no update installation here.
Set-StrictMode -Version Latest
function ConvertTo-R62Version {
 param([Parameter(Mandatory=$true)][string]$Text)
 if($Text -cnotmatch '^3\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$') { throw 'VERSION_FORMAT_INVALID' }
 return [version]$Text
}
function Assert-R62Upgrade {
 param([string]$Current,[string]$Target)
 $installed=ConvertTo-R62Version $Current
 $incoming=ConvertTo-R62Version $Target
 if($incoming -le $installed){throw 'DOWNGRADE_OR_REPLAY_BLOCKED'}
}
function Assert-R62ReleaseUri {
 param([Parameter(Mandatory=$true)][string]$Uri,[string]$Kind='bundle')
 $u=$null
 if(-not [Uri]::TryCreate($Uri,[UriKind]::Absolute,[ref]$u)){throw 'INVALID_URL'}
 if($u.Scheme -cne 'https' -or $u.Host -cne 'github.com' -or $u.Port -ne 443){throw 'UNTRUSTED_ORIGIN'}
 if($u.UserInfo -or $u.Query -or $u.Fragment){throw 'UNTRUSTED_URL_COMPONENT'}
 if($u.AbsolutePath -cnotmatch '^/melucasariel/agent-updater/releases/download/v3\.[0-9]{1,4}\.[0-9]{1,4}/[A-Za-z0-9_.-]+$'){throw 'UNTRUSTED_RELEASE_PATH'}
}
function Assert-R62Manifest {
 param([Parameter(Mandatory=$true)]$Manifest,
       [Parameter(Mandatory=$true)][string]$PinnedPublicKeyXml,
       [Parameter(Mandatory=$true)][string]$CurrentVersion)
 $version=[string]$Manifest.version
 $bundle=[string]$Manifest.bundle_url
 $hash=[string]$Manifest.bundle_sha256
 $signature=[string]$Manifest.signature_base64
 Assert-R62Upgrade -Current $CurrentVersion -Target $version
 Assert-R62ReleaseUri -Uri $bundle
 if($hash -cnotmatch '^[a-f0-9]{64}$'){throw 'INVALID_HASH'}
 if($signature.Length -lt 80 -or $signature.Length -gt 1024){throw 'INVALID_SIGNATURE_SIZE'}
 if($bundle -cnotmatch ('/releases/download/v'+[regex]::Escape($version)+'/')){throw 'RELEASE_TAG_MISMATCH'}
 $rsa=New-Object System.Security.Cryptography.RSACryptoServiceProvider
 try {
  $rsa.PersistKeyInCsp=$false
  $rsa.FromXmlString($PinnedPublicKeyXml)
  if($rsa.KeySize -lt 3072){throw 'WEAK_SIGNING_KEY'}
  $payload=$version+"`n"+$bundle+"`n"+$hash
  $valid=$rsa.VerifyData([Text.Encoding]::UTF8.GetBytes($payload),'SHA256',[Convert]::FromBase64String($signature))
  if(-not $valid){throw 'BAD_SIGNATURE'}
 } finally {$rsa.Dispose()}
 return $true
}
# This candidate deliberately does NOT implement an installer.
# Rollback requires an agent health handshake and process supervisor before installation may be enabled.
