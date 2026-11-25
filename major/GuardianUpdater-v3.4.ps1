# ROTA62 Guardian 3.4 — signed feed, version guard and supervised rollback
# Windows PowerShell 5.1. Runs only when separately launched by Guardian.
[CmdletBinding()]
param([switch]$CheckOnly,[switch]$Install)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$cfgFile=Join-Path $root 'update_source.json'
$agent=Join-Path $root 'GuardianAgent_v3.ps1'
$versionFile=Join-Path $root 'installed_version.txt'
$stop=Join-Path $root 'stop_v3.flag'
function Reject([string]$message){throw $message}
function ParseVersion([string]$s){
 if($s -cnotmatch '^3\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$'){Reject 'VERSION_INVALID'}
 return [version]$s
}
function ManifestUrlAllowed([string]$raw){
 $u=$null
 if(-not [Uri]::TryCreate($raw,[UriKind]::Absolute,[ref]$u)){return $false}
 return ($u.Scheme -ceq 'https' -and $u.Host -ceq 'github.com' -and $u.Port -eq 443 -and !$u.UserInfo -and !$u.Query -and !$u.Fragment -and $u.AbsolutePath -ceq '/melucasariel/agent-updater/releases/latest/download/release.json')
}
function BundleUrlAllowed([string]$raw,[string]$version){
 $u=$null
 if(-not [Uri]::TryCreate($raw,[UriKind]::Absolute,[ref]$u)){return $false}
 return ($u.Scheme -ceq 'https' -and $u.Host -ceq 'github.com' -and $u.Port -eq 443 -and !$u.UserInfo -and !$u.Query -and !$u.Fragment -and $u.AbsolutePath -cmatch ('^/melucasariel/agent-updater/releases/download/v'+[regex]::Escape($version)+'/[A-Za-z0-9_.-]+\.zip$'))
}
function FetchLimited([string]$url,[string]$path,[long]$max){
 $req=[Net.HttpWebRequest]::Create($url)
 $req.Timeout=15000;$req.ReadWriteTimeout=15000;$req.MaximumAutomaticRedirections=5
 $resp=$null;$inputStream=$null;$out=$null
 try{
  $resp=$req.GetResponse()
  if($resp.ResponseUri.Scheme -cne 'https'){Reject 'NON_HTTPS_REDIRECT'}
  if($resp.ResponseUri.Host -cnotin @('github.com','objects.githubusercontent.com','release-assets.githubusercontent.com')){Reject 'UNTRUSTED_REDIRECT'}
  if($resp.ContentLength -gt $max){Reject 'RESPONSE_TOO_LARGE'}
  $inputStream=$resp.GetResponseStream()
  $out=[IO.File]::Create($path)
  $bytes=New-Object byte[] 8192;$total=0L
  while(($read=$inputStream.Read($bytes,0,$bytes.Length)) -gt 0){
   $total+=$read
   if($total -gt $max){Reject 'RESPONSE_TOO_LARGE'}
   $out.Write($bytes,0,$read)
  }
  if($total -eq 0){Reject 'EMPTY_RESPONSE'}
 }finally{
  if($out){$out.Dispose()}
  if($inputStream){$inputStream.Dispose()}
  if($resp){$resp.Dispose()}
 }
}
function IsAgentStopped {
 $m=New-Object System.Threading.Mutex($false,'Local\ROTA62_Guardian_V3_Instance')
 try{
  if($m.WaitOne(0)){$m.ReleaseMutex();return $true}
  return $false
 }catch [System.Threading.AbandonedMutexException] {
  try{$m.ReleaseMutex()}catch{}
  return $true
 }finally{$m.Dispose()}
}
function WaitOldAgent {
 $sw=[Diagnostics.Stopwatch]::StartNew()
 while($sw.ElapsedMilliseconds -lt 14000){
  if(IsAgentStopped){return}
  Start-Sleep -Milliseconds 175
 }
 Reject 'OLD_AGENT_STOP_TIMEOUT'
}
function StartAgent([string]$challenge,[string]$receipt) {
 $args='-NoProfile -NonInteractive -Sta -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$agent+'"'
 if($challenge){$args+=' -GuardianChallenge '+$challenge+' -GuardianReceipt "'+$receipt+'"'}
 return Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $args -WindowStyle Hidden -PassThru
}
function CheckHealth([Diagnostics.Process]$p,[string]$challenge,[string]$receipt,[string]$hash,[string]$version){
 $sw=[Diagnostics.Stopwatch]::StartNew()
 while($sw.ElapsedMilliseconds -lt 12000){
  if($p.HasExited){Reject 'NEW_AGENT_EXITED'}
  if(Test-Path -LiteralPath $receipt){break}
  Start-Sleep -Milliseconds 125
 }
 if(!(Test-Path -LiteralPath $receipt)){Reject 'HEALTH_TIMEOUT'}
 if((Get-Item -LiteralPath $receipt).Length -gt 2048){Reject 'HEALTH_TOO_LARGE'}
 $ack=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
 if([string]$ack.challenge -cne $challenge){Reject 'HEALTH_NONCE_INVALID'}
 if([int]$ack.pid -ne $p.Id){Reject 'HEALTH_PID_INVALID'}
 if([string]$ack.sha256 -cne $hash){Reject 'HEALTH_HASH_INVALID'}
 if([string]$ack.version -cne $version){Reject 'HEALTH_VERSION_INVALID'}
 Start-Sleep -Milliseconds 1200
 if($p.HasExited){Reject 'NEW_AGENT_DIED'}
}
$work=$null;$backup=$null;$replacementDone=$false;$child=$null;$receipt=$null;$stage=$null
try{
 if(!(Test-Path -LiteralPath $agent -PathType Leaf)){Reject 'AGENT_NOT_FOUND'}
 if(!(Test-Path -LiteralPath $cfgFile -PathType Leaf)){Write-Output '[OK] UPDATES_DISABLED';exit 0}
 $cfg=Get-Content -LiteralPath $cfgFile -Raw | ConvertFrom-Json
 if(!$cfg.manifest_url -or !$cfg.public_key_xml){Write-Output '[OK] UPDATES_DISABLED';exit 0}
 if(-not (ManifestUrlAllowed ([string]$cfg.manifest_url))){Reject 'FEED_URL_NOT_ALLOWED'}
 if(!(Test-Path -LiteralPath $versionFile -PathType Leaf)){Reject 'PINNED_VERSION_MISSING'}
 $current=(Get-Content -LiteralPath $versionFile -Raw).Trim()
 $old=ParseVersion $current
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $work=Join-Path $env:TEMP ('r62_update_'+[guid]::NewGuid().ToString('N'))
 New-Item -Path $work -ItemType Directory -Force|Out-Null
 $mf=Join-Path $work 'release.json'
 FetchLimited ([string]$cfg.manifest_url) $mf 8192
 $manifest=Get-Content -LiteralPath $mf -Raw | ConvertFrom-Json
 $target=[string]$manifest.version
 $new=ParseVersion $target
 if($new -le $old){Write-Output '[OK] NO_NEWER_VERSION';exit 0}
 $url=[string]$manifest.bundle_url;$hash=[string]$manifest.bundle_sha256;$sig=[string]$manifest.signature_base64
 if(-not (BundleUrlAllowed $url $target)){Reject 'BUNDLE_URL_NOT_ALLOWED'}
 if($hash -cnotmatch '^[a-f0-9]{64}$'){Reject 'SIGNED_HASH_INVALID'}
 if($sig.Length -lt 100 -or $sig.Length -gt 1024){Reject 'SIGNATURE_LENGTH_INVALID'}
 $rsa=New-Object Security.Cryptography.RSACryptoServiceProvider
 try{
  $rsa.PersistKeyInCsp=$false
  $rsa.FromXmlString([string]$cfg.public_key_xml)
  if($rsa.KeySize -lt 3072){Reject 'RSA_KEY_WEAK'}
  $payload=$target+[char]10+$url+[char]10+$hash
  $valid=$rsa.VerifyData([Text.Encoding]::UTF8.GetBytes($payload),'SHA256',[Convert]::FromBase64String($sig))
 }finally{$rsa.Dispose()}
 if(-not $valid){Reject 'RSA_SIGNATURE_INVALID'}
 Write-Output ('[OK] SIGNED_UPDATE_AVAILABLE='+$target)
 if($CheckOnly -or !$Install){Write-Output '[OK] CHECK_ONLY';exit 0}
 $zip=Join-Path $work 'release.zip'
 FetchLimited $url $zip 2000000
 if((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){Reject 'ZIP_HASH_MISMATCH'}
 Add-Type -AssemblyName System.IO.Compression
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $a=[IO.Compression.ZipFile]::OpenRead($zip)
 $candidate=Join-Path $work 'GuardianAgent.ps1'
 try{
  $entries=@($a.Entries)
  if($entries.Count -ne 1 -or $entries[0].FullName -cne 'GuardianAgent.ps1' -or $entries[0].Length -gt 100000){Reject 'ZIP_ENTRIES_INVALID'}
  $source=$entries[0].Open();$dest=[IO.File]::Create($candidate)
  try{$source.CopyTo($dest)}finally{$dest.Dispose();$source.Dispose()}
 }finally{$a.Dispose()}
 $tokens=$null;$errors=$null
 [void][Management.Automation.Language.Parser]::ParseFile($candidate,[ref]$tokens,[ref]$errors)
 if(@($errors).Count){Reject 'POWERSHELL_SYNTAX_INVALID'}
 $candidateText=[IO.File]::ReadAllText($candidate)
 if($candidateText -notmatch 'R62_HEALTH_V34_PROTOCOL' -or $candidateText -notmatch 'GuardianChallenge'){Reject 'HEALTH_PROTOCOL_NOT_FOUND'}
 $stage=Join-Path $root ('guardian_staged_'+[guid]::NewGuid().ToString('N')+'.ps1')
 Copy-Item -LiteralPath $candidate -Destination $stage
 $newHash=(Get-FileHash -LiteralPath $stage -Algorithm SHA256).Hash
 if($newHash -ne (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash){Reject 'STAGED_HASH_MISMATCH'}
 $backup=Join-Path $root ('guardian_backup_'+[guid]::NewGuid().ToString('N')+'.ps1')
 [IO.File]::WriteAllText($stop,'stop')
 WaitOldAgent
 [IO.File]::Replace($stage,$agent,$backup,$true)
 $replacementDone=$true
 if((Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash -ne $newHash){Reject 'LIVE_HASH_MISMATCH'}
 Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
 $challenge=[guid]::NewGuid().ToString('N')
 $receipt=Join-Path $root ('health_'+$challenge+'.json')
 $child=StartAgent $challenge $receipt
 CheckHealth $child $challenge $receipt $newHash $target
 $nextVersion=Join-Path $root ('next_version_'+[guid]::NewGuid().ToString('N')+'.txt')
 [IO.File]::WriteAllText($nextVersion,$target,(New-Object Text.UTF8Encoding($false)))
 Copy-Item -LiteralPath $nextVersion -Destination $versionFile -Force
 Remove-Item -LiteralPath $nextVersion -Force -ErrorAction SilentlyContinue
 $replacementDone=$false
 Write-Output ('[APROVADO] INSTALLED='+$target)
}catch{
 $message=[string]$_.Exception.Message
 if($message -notmatch '^[A-Z0-9_]+$'){$message='UNCLASSIFIED_FAILURE'}
 Write-Output ('[BLOQUEADO] '+$message)
 if($replacementDone -and $backup -and (Test-Path -LiteralPath $backup)){
  try{
   if($child -and !$child.HasExited){$child.Kill();$child.WaitForExit(4000)|Out-Null}
   [IO.File]::Copy($backup,$agent,$true)
   Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
   $null=StartAgent '' ''
   Write-Output '[RECUPERADO] PREVIOUS_AGENT_RESTORED'
  }catch{Write-Output '[CRITICO] MANUAL_ROLLBACK_REQUIRED'}
 }elseif(Test-Path -LiteralPath $stop){
  Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
  if(IsAgentStopped){try{$null=StartAgent '' ''}catch{}}
 }
 exit 1
}finally{
 if($receipt){Remove-Item -LiteralPath $receipt -Force -ErrorAction SilentlyContinue}
 if($work){Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue}
 if($stage){Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue}
}
