# ROTA62 Guardian v3.4.1 canary — read-only client verification.
# Never invokes the updater, stops an Agent, modifies the local feed or installs a candidate.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== GUARDIAN CANARY 3.4.1 READ ONLY ===')
$tempDir=$null
try {
 $root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
 $public=Join-Path $root 'signing-public.xml'
 $config=Join-Path $root 'update_source.json'
 $versionFile=Join-Path $root 'installed_version.txt'
 foreach($p in @($public,$config,$versionFile)){if(!(Test-Path -LiteralPath $p -PathType Leaf)){throw 'LOCAL_TRUST_FILE_MISSING'}}
 $installed=(Get-Content -LiteralPath $versionFile -Raw).Trim()
 if($installed -cne '3.4.0'){throw 'INSTALLED_VERSION_UNEXPECTED'}
 $cfg=Get-Content -LiteralPath $config -Raw|ConvertFrom-Json
 $feed='https://github.com/melucasariel/agent-updater/releases/latest/download/release.json'
 if([string]$cfg.manifest_url -cne $feed){throw 'INSTALLED_FEED_UNEXPECTED'}
 $pub=[IO.File]::ReadAllText($public,[Text.Encoding]::UTF8)
 if([string]$cfg.public_key_xml -cne $pub){throw 'PINNED_PUBLIC_KEY_MISMATCH'}
 $tag='v3.4.1'
 $base='https://github.com/melucasariel/agent-updater/releases/download/'+$tag+'/'
 $bundle=$base+'guardian-v3.4.1.zip'
 $tempDir=Join-Path ([IO.Path]::GetTempPath()) ('R62_CANARY_VERIFY_'+[guid]::NewGuid().ToString('N'))
 New-Item -Path $tempDir -ItemType Directory -Force|Out-Null
 $mf=Join-Path $tempDir 'release.json'
 $zip=Join-Path $tempDir 'guardian-v3.4.1.zip'
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 Invoke-WebRequest -Uri ($base+'release.json') -OutFile $mf -UseBasicParsing -TimeoutSec 30
 if((Get-Item -LiteralPath $mf).Length -gt 8192){throw 'MANIFEST_TOO_LARGE'}
 $m=Get-Content -LiteralPath $mf -Raw|ConvertFrom-Json
 if([string]$m.version -cne '3.4.1'){throw 'MANIFEST_VERSION_INVALID'}
 if([string]$m.bundle_url -cne $bundle){throw 'MANIFEST_BUNDLE_URL_INVALID'}
 $hash=[string]$m.bundle_sha256
 if($hash -cnotmatch '^[a-f0-9]{64}$'){throw 'MANIFEST_HASH_INVALID'}
 $sig=[string]$m.signature_base64
 if($sig.Length -lt 100 -or $sig.Length -gt 1024){throw 'MANIFEST_SIGNATURE_INVALID'}
 $data='3.4.1'+[char]10+$bundle+[char]10+$hash
 $rsa=New-Object Security.Cryptography.RSACryptoServiceProvider
 try{
  $rsa.PersistKeyInCsp=$false
  $rsa.FromXmlString($pub)
  if($rsa.KeySize -lt 3072){throw 'PUBLIC_KEY_TOO_WEAK'}
  if(-not $rsa.VerifyData([Text.Encoding]::UTF8.GetBytes($data),'SHA256',[Convert]::FromBase64String($sig))){throw 'SIGNATURE_REJECTED'}
 }finally{$rsa.Dispose()}
 $report.Add('[OK] PUBLISHED_MANIFEST_RSA_SHA256_VALID')
 Invoke-WebRequest -Uri $bundle -OutFile $zip -UseBasicParsing -TimeoutSec 60
 if((Get-Item -LiteralPath $zip).Length -gt 2000000){throw 'BUNDLE_TOO_LARGE'}
 if((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'DOWNLOADED_ZIP_HASH_INVALID'}
 Add-Type -AssemblyName System.IO.Compression
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $archive=[IO.Compression.ZipFile]::OpenRead($zip)
 try{
  $entries=@($archive.Entries)
  if($entries.Count -ne 1 -or $entries[0].FullName -cne 'GuardianAgent.ps1' -or $entries[0].Length -gt 100000){throw 'ZIP_ENTRIES_INVALID'}
  $reader=New-Object IO.StreamReader($entries[0].Open(),[Text.Encoding]::UTF8)
  try{$agentText=$reader.ReadToEnd()}finally{$reader.Dispose()}
  if($agentText -notmatch 'R62_HEALTH_V34_PROTOCOL' -or $agentText -notmatch "version='3[.]4[.]1'"){throw 'CANDIDATE_HEALTH_PROTOCOL_INVALID'}
  $tokens=$null;$errors=$null
  [void][Management.Automation.Language.Parser]::ParseInput($agentText,[ref]$tokens,[ref]$errors)
  if(@($errors).Count){throw 'CANDIDATE_SYNTAX_INVALID'}
 }finally{$archive.Dispose()}
 $report.Add('[OK] DOWNLOADED_ZIP_SHA256_MATCH')
 $report.Add('[OK] CANDIDATE_AGENT_SYNTAX_AND_HEALTH_PROTOCOL')
 # The pre-release must NOT be promoted. Check the visible GitHub latest RELEASE redirect,
 # without trying to interpret a 404 as a failure.
 $latestOk=$true
 try {
  $req=[Net.HttpWebRequest]::Create($feed)
  $req.AllowAutoRedirect=$false
  $req.Timeout=15000
  $response=$req.GetResponse()
  try {
   if([int]$response.StatusCode -eq 200){throw 'LATEST_ALREADY_PRESENT'}
  }finally{$response.Dispose()}
 } catch [Net.WebException] {
  if($_.Exception.Response){
   try{
    if([int]$_.Exception.Response.StatusCode -ne 404){$latestOk=$false}
   }finally{$_.Exception.Response.Dispose()}
  }else{$latestOk=$false}
 }
 if(-not $latestOk){$report.Add('[AVISO] LATEST_ENDPOINT_NOT_VERIFIED')}
 $report.Add('[OK] NO_LOCAL_AGENT_FILES_MODIFIED')
 $report.Add('[MODO] CANARY_PRE_RELEASE_READ_ONLY')
 $report.Add('[LIMITE] Stable promotion and real automatic rollout NOT tested')
}catch{
 $errorCode=[string]$_.Exception.Message
 if($errorCode -cnotmatch '^[A-Z0-9_]+$'){$errorCode='READ_ONLY_VERIFICATION_ERROR'}
 $report.Add('[BLOQUEADO] '+$errorCode)
}finally{
 if($tempDir){Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue}
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
