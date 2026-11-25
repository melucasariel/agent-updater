# Guardian 3.4.1 signed CANARY builder. PowerShell 5.1. Does not edit the installed Agent.
# -PublishCanary requires the user's authenticated GitHub CLI; default is offline-only.
[CmdletBinding()]
param([switch]$PublishCanary)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$repo='melucasariel/agent-updater'
$version='3.4.1'
$tag='v3.4.1'
$zipName='guardian-v3.4.1.zip'
$zipUrl='https://github.com/'+$repo+'/releases/download/'+$tag+'/'+$zipName
$root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$agent=Join-Path $root 'GuardianAgent_v3.ps1'
$versionFile=Join-Path $root 'installed_version.txt'
$public=Join-Path $root 'signing-public.xml'
$private=Join-Path $root 'signing-private.dpapi'
$feed=Join-Path $root 'update_source.json'
$work=$null
$privateBytes=$null
$report=New-Object System.Collections.Generic.List[string]
$report.Add('=== GUARDIAN CANARY 3.4.1 ===')
$success=$false
function RequireFile([string]$path){
 if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw 'MISSING_LOCAL_PREREQUISITE'}
}
function RunGh([string[]]$arguments){
 $exe=Get-Command gh -ErrorAction SilentlyContinue
 if(-not $exe){throw 'GITHUB_CLI_NOT_INSTALLED'}
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=$exe.Source
 $psi.Arguments=($arguments | ForEach-Object {
  if($_ -match '["\r\n]'){throw 'GH_ARGUMENT_REJECTED'}
  if($_ -match '\s'){'"'+$_+'"'}else{$_}
 }) -join ' '
 $psi.UseShellExecute=$false
 $psi.CreateNoWindow=$true
 $psi.RedirectStandardOutput=$true
 $psi.RedirectStandardError=$true
 $p=[Diagnostics.Process]::Start($psi)
 try{
  $stdout=$p.StandardOutput.ReadToEnd()
  $stderr=$p.StandardError.ReadToEnd()
  if(-not $p.WaitForExit(60000)){try{$p.Kill()}catch{};throw 'GITHUB_CLI_TIMEOUT'}
  if($p.ExitCode -ne 0){throw 'GITHUB_CLI_COMMAND_FAILED'}
  return $stdout.Trim()
 }finally{$p.Dispose()}
}
try{
 foreach($f in @($agent,$versionFile,$public,$private,$feed)){RequireFile $f}
 if((Get-Content -LiteralPath $versionFile -Raw).Trim() -cne '3.4.0'){throw 'INSTALLED_VERSION_NOT_3_4_0'}
 $cfg=Get-Content -LiteralPath $feed -Raw | ConvertFrom-Json
 if([string]$cfg.manifest_url -cne 'https://github.com/melucasariel/agent-updater/releases/latest/download/release.json'){throw 'FEED_URL_NOT_EXPECTED'}
 $publicXml=[IO.File]::ReadAllText($public,[Text.Encoding]::UTF8)
 if([string]$cfg.public_key_xml -cne $publicXml){throw 'LOCAL_PUBLIC_KEY_DIFFERS_FROM_PIN'}
 $old=[IO.File]::ReadAllText($agent,[Text.Encoding]::UTF8)
 if(-not $old.Contains('R62_HEALTH_V34_PROTOCOL') -or -not $old.Contains('GuardianChallenge')){throw 'HEALTH_PROTOCOL_NOT_PRESENT'}
 $token="version='3.4.0'"
 if(($old.Split([string[]]@($token),[StringSplitOptions]::None)).Length -ne 2){throw 'VERSION_STAMP_NOT_UNIQUE'}
 $patched=$old.Replace($token,"version='3.4.1'")
 $patched+=[Environment]::NewLine+'# R62 signed canary v3.4.1: heartbeat version only.'+[Environment]::NewLine
 if([Text.Encoding]::UTF8.GetByteCount($patched) -gt 100000){throw 'AGENT_TOO_LARGE'}
 $work=Join-Path ([IO.Path]::GetTempPath()) ('R62_CANARY_'+[guid]::NewGuid().ToString('N'))
 New-Item -Path $work -ItemType Directory -Force | Out-Null
 $candidate=Join-Path $work 'GuardianAgent.ps1'
 [IO.File]::WriteAllText($candidate,$patched,(New-Object Text.UTF8Encoding($false)))
 $tokens=$null;$errors=$null
 [void][Management.Automation.Language.Parser]::ParseFile($candidate,[ref]$tokens,[ref]$errors)
 if(@($errors).Count){throw 'CANDIDATE_PARSE_FAILED'}
 $zip=Join-Path $work $zipName
 $archive=[IO.Compression.ZipFile]::Open($zip,[IO.Compression.ZipArchiveMode]::Create)
 try{
  $entry=$archive.CreateEntry('GuardianAgent.ps1',[IO.Compression.CompressionLevel]::Optimal)
  $from=[IO.File]::OpenRead($candidate);$to=$entry.Open()
  try{$from.CopyTo($to)}finally{$to.Dispose();$from.Dispose()}
 }finally{$archive.Dispose()}
 if((Get-Item -LiteralPath $zip).Length -gt 2000000){throw 'ZIP_TOO_LARGE'}
 $check=[IO.Compression.ZipFile]::OpenRead($zip)
 try{
  $entries=@($check.Entries)
  if($entries.Count -ne 1 -or $entries[0].FullName -cne 'GuardianAgent.ps1'){throw 'ZIP_ENTRIES_INVALID'}
 }finally{$check.Dispose()}
 $hash=(Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
 $payload=$version+[char]10+$zipUrl+[char]10+$hash
 $privateBytes=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($private),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
 $rsa=New-Object Security.Cryptography.RSACryptoServiceProvider
 $pub=New-Object Security.Cryptography.RSACryptoServiceProvider
 try{
  $rsa.PersistKeyInCsp=$false;$pub.PersistKeyInCsp=$false
  $rsa.FromXmlString([Text.Encoding]::UTF8.GetString($privateBytes))
  $pub.FromXmlString($publicXml)
  if($pub.KeySize -lt 3072){throw 'PUBLIC_KEY_TOO_WEAK'}
  $signature=[Convert]::ToBase64String($rsa.SignData([Text.Encoding]::UTF8.GetBytes($payload),'SHA256'))
  if(-not $pub.VerifyData([Text.Encoding]::UTF8.GetBytes($payload),'SHA256',[Convert]::FromBase64String($signature))){throw 'LOCAL_RSA_VERIFY_FAILED'}
 }finally{$rsa.Dispose();$pub.Dispose()}
 $manifest=[ordered]@{version=$version;bundle_url=$zipUrl;bundle_sha256=$hash;signature_base64=$signature}
 $manifestFile=Join-Path $work 'release.json'
 [IO.File]::WriteAllText($manifestFile,($manifest|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
 $report.Add('[OK] CANARY_ZIP_SINGLE_ENTRY')
 $report.Add('[OK] LOCAL_RSA_SHA256_SIGN_AND_VERIFY')
 $report.Add('[OK] SIGNING_KEY_REMAINED_LOCAL_DPAPI')
 if($PublishCanary){
  [void](RunGh @('auth','status','--hostname','github.com'))
  $already=$false
  try{[void](RunGh @('release','view',$tag,'--repo',$repo,'--json','tagName'));$already=$true}catch{}
  if($already){throw 'RELEASE_TAG_ALREADY_EXISTS'}
  [void](RunGh @('release','create',$tag,$zip,$manifestFile,'--repo',$repo,'--target','main','--title','Guardian Canary v3.4.1','--notes','Signed canary prerelease; do not promote before separate validation.','--prerelease','--latest=false'))
  $report.Add('[OK] GITHUB_PRERELEASE_PUBLISHED')
  $verify=Join-Path $work 'downloaded'
  New-Item -Path $verify -ItemType Directory -Force|Out-Null
  [void](RunGh @('release','download',$tag,'--repo',$repo,'--dir',$verify))
  $remoteZip=Join-Path $verify $zipName;$remoteManifest=Join-Path $verify 'release.json'
  RequireFile $remoteZip;RequireFile $remoteManifest
  if((Get-FileHash -LiteralPath $remoteZip -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'PUBLISHED_ZIP_HASH_MISMATCH'}
  $m=Get-Content -LiteralPath $remoteManifest -Raw|ConvertFrom-Json
  if([string]$m.version -cne $version -or [string]$m.bundle_url -cne $zipUrl -or [string]$m.bundle_sha256 -cne $hash){throw 'PUBLISHED_MANIFEST_INVALID'}
  $v=New-Object Security.Cryptography.RSACryptoServiceProvider
  try{
   $v.PersistKeyInCsp=$false;$v.FromXmlString($publicXml)
   if(-not $v.VerifyData([Text.Encoding]::UTF8.GetBytes($payload),'SHA256',[Convert]::FromBase64String([string]$m.signature_base64))){throw 'PUBLISHED_SIGNATURE_INVALID'}
  }finally{$v.Dispose()}
  $report.Add('[OK] PRERELEASE_ASSETS_REDOWNLOADED_AND_VERIFIED')
  $report.Add('[SEGURO] PRERELEASE_NOT_LATEST; NO_AUTOMATIC_INSTALL')
 }else{
  $report.Add('[MODO] PREPARAR_APENAS; NAO_PUBLICADO')
  $report.Add('[PROXIMO] GITHUB_CLI_AUTENTICADO_NECESSARIO_PARA_PUBLICAR')
 }
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]+$'){$reason='LOCAL_ERROR_REDACTED'}
 $report.Add('[BLOQUEADO] '+$reason)
}finally{
 if($privateBytes){[Array]::Clear($privateBytes,0,$privateBytes.Length)}
 if($work){Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue}
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
