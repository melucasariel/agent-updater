# ROTA62 Guardian v3.4 one-time major migration. No ZIP, no database commands.
[CmdletBinding()]
param([switch]$DryRun)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$agent=Join-Path $root 'GuardianAgent_v3.ps1'
$updater=Join-Path $root 'GuardianUpdater.ps1'
$stop=Join-Path $root 'stop_v3.flag'
$version=Join-Path $root 'installed_version.txt'
$feed=Join-Path $root 'update_source.json'
$public=Join-Path $root 'signing-public.xml'
$private=Join-Path $root 'signing-private.dpapi'
$beforeAgent='84F9440890F1DBB550F0C57833ECD485E685839B8323B995147759A4090F9CE8'
$beforeUpdater='9BE00D02A49457AC3A05B732F6746174241B5C545B6131368DF436604A914E0E'
$newUpdater='7DAFA8779E0ABD3139934579033D27FD7BB71691C3A3178E8C224687A9FF20E2'
$url='https://raw.githubusercontent.com/melucasariel/agent-updater/90850cd6418df42fdb519e25c4c48dc74816e72f/major/GuardianUpdater-v3.4.ps1'
function CheckHash([string]$p,[string]$h){if(!(Test-Path -LiteralPath $p) -or (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -cne $h){throw 'AUDIT_HASH_MISMATCH'}}
function AgentFree{
 $mutex=New-Object Threading.Mutex($false,'Local\ROTA62_Guardian_V3_Instance')
 try{if($mutex.WaitOne(0)){$mutex.ReleaseMutex();return $true};return $false}
 catch [Threading.AbandonedMutexException]{try{$mutex.ReleaseMutex()}catch{};return $true}
 finally{$mutex.Dispose()}
}
function StartGuardian([string]$nonce,[string]$ack){
 $args='-NoProfile -NonInteractive -Sta -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$agent+'"'
 if($nonce){$args+=' -GuardianChallenge '+$nonce+' -GuardianReceipt "'+$ack+'"'}
 return Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $args -WindowStyle Hidden -PassThru
}
$work=$null;$savedAgent=$null;$savedUpdater=$null;$modifiedAgent=$false;$modifiedUpdater=$false;$child=$null;$ackFile=$null
try{
 CheckHash $agent $beforeAgent
 CheckHash $updater $beforeUpdater
 if(!(Test-Path -LiteralPath $public) -or !(Test-Path -LiteralPath $private)){throw 'LOCAL_SIGNING_KEYS_MISSING'}
 if(Test-Path -LiteralPath $version){if((Get-Content -LiteralPath $version -Raw).Trim() -ne '3.0.0'){throw 'VERSION_NOT_EXPECTED'}}
 if(Test-Path -LiteralPath $feed){
  $existing=Get-Content -LiteralPath $feed -Raw|ConvertFrom-Json
  if([string]$existing.manifest_url -or [string]$existing.public_key_xml){throw 'FEED_ALREADY_CONFIGURED'}
 }
 $work=Join-Path $root ('guardian_major_'+[guid]::NewGuid().ToString('N'))
 New-Item -ItemType Directory -Path $work -Force|Out-Null
 $download=Join-Path $work 'GuardianUpdater.ps1'
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $web=New-Object Net.WebClient
 try{$web.DownloadFile($url,$download)}finally{$web.Dispose()}
 CheckHash $download $newUpdater
 $original=[IO.File]::ReadAllText($agent)
 $marker=" Event 'agent_started'"
 if($original.Split(@($marker),[StringSplitOptions]::None).Length -ne 2){throw 'HEALTH_INSERT_MARKER_NOT_UNIQUE'}
 $hook=@'
 if($GuardianChallenge){
  if($GuardianChallenge -cnotmatch '^[a-f0-9]{32}$'){throw 'HEALTH_CHALLENGE_INVALID'}
  $expected=Join-Path $root ('health_'+$GuardianChallenge+'.json')
  if([IO.Path]::GetFullPath($GuardianReceipt) -cne [IO.Path]::GetFullPath($expected)){throw 'HEALTH_RECEIPT_PATH_INVALID'}
  $reply=[ordered]@{challenge=$GuardianChallenge;pid=$PID;sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash;version='3.4.0'}
  $tmp=$expected+'.temp'
  [IO.File]::WriteAllText($tmp,($reply|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
  [IO.File]::Move($tmp,$expected)
 }
'@
 $header='param([string]$GuardianChallenge="",[string]$GuardianReceipt="") # R62_HEALTH_V34_PROTOCOL'+[Environment]::NewLine
 $patched=$header+$original.Replace($marker,$marker+[Environment]::NewLine+$hook)
 $patched=$patched.Replace("INSTALADO=GUARDIAN_V3'","INSTALADO=GUARDIAN_V3.4'")
 $patchedFile=Join-Path $work 'GuardianAgent.ps1'
 [IO.File]::WriteAllText($patchedFile,$patched,(New-Object Text.UTF8Encoding($false)))
 $tok=$null;$errs=$null
 [void][Management.Automation.Language.Parser]::ParseFile($patchedFile,[ref]$tok,[ref]$errs)
 if(@($errs).Count -gt 0){throw 'AGENT_SYNTAX_FAILED'}
 [void][Management.Automation.Language.Parser]::ParseFile($download,[ref]$tok,[ref]$errs)
 if(@($errs).Count -gt 0){throw 'UPDATER_SYNTAX_FAILED'}
 if($DryRun){Write-Output '[APROVADO] MAJOR_DRY_RUN_PRECHECK';Write-Output '[NAO EXECUTADO] Instalacao, Docker, SQL';exit 0}
 $newHash=(Get-FileHash -LiteralPath $patchedFile -Algorithm SHA256).Hash
 $stageAgent=Join-Path $root ('new_agent_'+[guid]::NewGuid().ToString('N')+'.ps1')
 $stageUpdater=Join-Path $root ('new_updater_'+[guid]::NewGuid().ToString('N')+'.ps1')
 Copy-Item -LiteralPath $patchedFile -Destination $stageAgent
 Copy-Item -LiteralPath $download -Destination $stageUpdater
 $savedAgent=Join-Path $root ('backup_agent_'+[guid]::NewGuid().ToString('N')+'.ps1')
 $savedUpdater=Join-Path $root ('backup_updater_'+[guid]::NewGuid().ToString('N')+'.ps1')
 [IO.File]::WriteAllText($stop,'stop')
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while(-not (AgentFree) -and $watch.ElapsedMilliseconds -lt 15000){Start-Sleep -Milliseconds 150}
 if(-not (AgentFree)){throw 'AGENT_STOP_TIMEOUT'}
 [IO.File]::Replace($stageAgent,$agent,$savedAgent,$true);$modifiedAgent=$true
 [IO.File]::Replace($stageUpdater,$updater,$savedUpdater,$true);$modifiedUpdater=$true
 if((Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash -ne $newHash){throw 'LIVE_AGENT_HASH_FAILED'}
 CheckHash $updater $newUpdater
 Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
 $challenge=[guid]::NewGuid().ToString('N')
 $ackFile=Join-Path $root ('health_'+$challenge+'.json')
 $child=StartGuardian $challenge $ackFile
 $sw=[Diagnostics.Stopwatch]::StartNew()
 while($sw.ElapsedMilliseconds -lt 14000){
  if($child.HasExited){throw 'NEW_AGENT_EXITED'}
  if(Test-Path -LiteralPath $ackFile){break}
  Start-Sleep -Milliseconds 140
 }
 if(!(Test-Path -LiteralPath $ackFile)){throw 'HEALTH_TIMEOUT'}
 if((Get-Item -LiteralPath $ackFile).Length -gt 2048){throw 'HEALTH_FILE_TOO_BIG'}
 $receipt=Get-Content -LiteralPath $ackFile -Raw|ConvertFrom-Json
 if([string]$receipt.challenge -cne $challenge -or [int]$receipt.pid -ne $child.Id -or [string]$receipt.sha256 -cne $newHash -or [string]$receipt.version -cne '3.4.0'){throw 'HEALTH_VALIDATION_FAILED'}
 Start-Sleep -Milliseconds 1200
 if($child.HasExited){throw 'NEW_AGENT_EARLY_EXIT'}
 [IO.File]::WriteAllText($version,'3.4.0',(New-Object Text.UTF8Encoding($false)))
 $pub=[IO.File]::ReadAllText($public,[Text.Encoding]::UTF8)
 if($pub -notmatch '<RSAKeyValue>'){throw 'PUBLIC_KEY_INVALID'}
 $cfg=[ordered]@{manifest_url='https://github.com/melucasariel/agent-updater/releases/latest/download/release.json';public_key_xml=$pub}
 [IO.File]::WriteAllText($feed,($cfg|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
 Write-Output '[APROVADO] GUARDIAN_MAJOR_3_4_COM_HEALTH'
 Write-Output '[OK] FEED_ASSINADO_CONFIGURADO'
 Write-Output '[LIMITE] Releases assinadas ainda precisam de publicacao.'
 try{Set-Clipboard -Value 'GUARDIAN_MAJOR=3.4.0; STATUS=APROVADO; HEALTH=OK; FEED=CONFIGURADO' -ErrorAction Stop}catch{}
 $modifiedAgent=$false
} catch{
 $msg=[string]$_.Exception.Message
 if($msg -notmatch '^[A-Z0-9_]+$'){$msg='ERRO_NAO_CLASSIFICADO'}
 Write-Output ('[BLOQUEADO] '+$msg)
 try{Set-Clipboard -Value ('GUARDIAN_MAJOR=BLOQUEADO; CODIGO='+$msg) -ErrorAction Stop}catch{}
 if($modifiedAgent -and $savedAgent -and (Test-Path -LiteralPath $savedAgent)){
  try{
   if($child -and !$child.HasExited){$child.Kill();$child.WaitForExit(4000)|Out-Null}
   Copy-Item -LiteralPath $savedAgent -Destination $agent -Force
   if($modifiedUpdater -and $savedUpdater){Copy-Item -LiteralPath $savedUpdater -Destination $updater -Force}
   Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
   $restored=StartGuardian '' ''
   Start-Sleep -Milliseconds 1200
   if($restored.HasExited){throw 'RESTORED_AGENT_FAILED_TO_START'}
   Write-Output '[RECUPERADO] AGENT_V3_ANTERIOR_RESTAURADO'
  }catch{Write-Output '[CRITICO] ROLLBACK_MANUAL_NECESSARIO'}
 } elseif(Test-Path -LiteralPath $stop){
  Remove-Item -LiteralPath $stop -Force -ErrorAction SilentlyContinue
  if(AgentFree){try{$null=StartGuardian '' ''}catch{}}
 }
 exit 1
}finally{
 if($ackFile){Remove-Item -LiteralPath $ackFile -Force -ErrorAction SilentlyContinue}
 if($work){Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue}
}
