# ROTA62 Guardian CLEAN6 startup hooks audit v0.5.6
# READ ONLY: docker inspect and docker cp on stopped container only.
# No start/run/exec, SQL, network tests, decrypted content, or env values printed.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN6 STARTUP HOOK AUDIT v0.5.6 ===')
$report.Add('[MODO] READ_ONLY_STOPPED_IMAGE_SCAN_NO_START')
$stage='INIT'
$work=$null
$passed=$false
function DockerRead([string[]]$argsDocker) {
 $out=@(& docker @argsDocker 2>$null)
 if($LASTEXITCODE -ne 0){throw 'DOCKER_INSPECT_FAILED'}
 return (($out -join [Environment]::NewLine).Trim())
}
function CopyKnown([string]$src,[string]$dest) {
 $old=$ErrorActionPreference
 try {
  $ErrorActionPreference='Continue'
  $null=@(& docker cp ($cn+':'+$src) $dest 2>$null)
  return ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $dest))
 }catch{return $false}finally{$ErrorActionPreference=$old}
}
function FilesUnder([string]$path) {
 if(Test-Path -LiteralPath $path -PathType Leaf){return @(Get-Item -LiteralPath $path)}
 if(Test-Path -LiteralPath $path -PathType Container){return @(Get-ChildItem -LiteralPath $path -File -Recurse -ErrorAction Stop)}
 return @()
}
try {
 $stage='CONTAINER'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_NOT_FOUND'}
 $ins=DockerRead @('inspect',$cn)
 $objects=@(ConvertFrom-Json -InputObject $ins)
 if($objects.Count -ne 1){throw 'CONTAINER_INSPECT_INVALID'}
 $c=$objects[0]
 if([string]$c.State.Status -cne 'created' -or $c.State.Running -ne $false){throw 'CONTAINER_NOT_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'NETWORK_NOT_NONE'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'PORT_BINDINGS_PRESENT'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne 'rota62_guardian_clean6_data'){throw 'MOUNT_UNEXPECTED'}
 $report.Add('[OK] CLEAN6_STOPPED_NETWORK_NONE_SINGLE_VOLUME')
 $stage='IMAGE'
 $imageId=[string]$c.Image
 if($imageId -cnotmatch '^sha256:[0-9a-f]{64}$'){throw 'IMAGE_INVALID'}
 $imRaw=DockerRead @('image','inspect',$imageId)
 $images=@(ConvertFrom-Json -InputObject $imRaw)
 if($images.Count -ne 1 -or [string]$images[0].Id -cne $imageId){throw 'IMAGE_INSPECT_INVALID'}
 $report.Add('[OK] IMAGE_ID_PINNED')
 $report.Add('ENTRYPOINT_TOKEN_COUNT='+@($c.Config.Entrypoint|Where-Object {$_}).Count)
 $report.Add('IMAGE_CMD_TOKEN_COUNT='+@($c.Config.Cmd|Where-Object {$_}).Count)
 $stage='STATIC_COPY'
 $work=Join-Path $env:TEMP ('R62-clean6-scan-'+[guid]::NewGuid().ToString('N'))
 $null=New-Item -ItemType Directory -Path $work -Force
 $entryCandidates=@('/usr/local/bin/docker-entrypoint.sh','/usr/local/bin/docker-entrypoint','/docker-entrypoint.sh')
 $entry=@($c.Config.Entrypoint|Where-Object {$_})
 if($entry.Count -gt 0 -and [string]$entry[0] -cmatch '^/(usr/local/bin|usr/bin|bin)/[A-Za-z0-9_./-]+$' -and [string]$entry[0] -notmatch '\.\.'){
  $entryCandidates=@([string]$entry[0])+$entryCandidates
 }
 $paths=@($entryCandidates|Select-Object -Unique)
 $copied=0
 $copyFailed=0
 $all=New-Object 'System.Collections.Generic.List[object]'
 foreach($p in $paths) {
  $dest=Join-Path $work ('entry-'+$copied+'-'+$copyFailed)
  if(CopyKnown $p $dest){
   $copied++
   foreach($file in @(FilesUnder $dest)){[void]$all.Add($file)}
  }else{$copyFailed++}
 }
 $report.Add('ENTRYPOINT_CANDIDATES_COPIED='+$copied)
 foreach($dirname in @('/docker-entrypoint-initdb.d','/usr/local/share/postgresql/initdb.d')) {
  $dest=Join-Path $work ('hooks-'+$all.Count)
  if(CopyKnown $dirname $dest){
   $files=@(FilesUnder $dest)
   $report.Add(('INIT_HOOK_DIRECTORY_'+$(if($dirname -eq '/docker-entrypoint-initdb.d'){'STANDARD'}else{'ALTERNATE'}))+'=PRESENT')
   $report.Add('INIT_HOOK_FILE_COUNT='+$files.Count)
   foreach($file in $files){[void]$all.Add($file)}
  }else{
   $report.Add(('INIT_HOOK_DIRECTORY_'+$(if($dirname -eq '/docker-entrypoint-initdb.d'){'STANDARD'}else{'ALTERNATE'}))+'=NOT_COPIED')
  }
 }
 if($copied -eq 0){throw 'ENTRYPOINT_SCRIPT_NOT_COPIED'}
 $stage='CLASSIFY'
 $executables=0
 $comments=0
 $networkExec=0
 $networkComment=0
 $cron=0
 $pgnet=0
 $preload=0
 $totalFiles=0
 $totalBytes=0L
 foreach($file in $all) {
  if($file.Length -gt 1048576){throw 'SINGLE_SCRIPT_TOO_LARGE'}
  $totalBytes+=$file.Length
  if($totalBytes -gt 4194304){throw 'SCAN_SIZE_LIMIT'}
  if($file.Extension -notin @('.sh','.bash','.sql','.conf','.txt','.py','')){continue}
  $totalFiles++
  $lines=[IO.File]::ReadAllLines($file.FullName)
  foreach($line in $lines){
   $t=$line.Trim()
   if($t -eq ''){continue}
   $isComment=($t.StartsWith('#') -or $t.StartsWith('--'))
   $hasNetwork=($t -match '(?i)(^|[^\w])(curl|wget)([ \t]|$)|https?://')
   if($hasNetwork){
    if($isComment){$networkComment++}else{$networkExec++}
   }
   if($t -match '(?i)pg_cron|cron\.launch_active_jobs'){$cron++}
   if($t -match '(?i)pg_net|pg_net\.'){$pgnet++}
   if($t -match '(?i)shared_preload_libraries'){$preload++}
   if($isComment){$comments++}else{$executables++}
  }
 }
 $report.Add('TEXT_FILES_SCANNED='+$totalFiles)
 $report.Add('CODE_LINES='+$executables)
 $report.Add('COMMENT_LINES='+$comments)
 $report.Add('NETWORK_REFERENCE_ACTIVE_LINE_COUNT='+$networkExec)
 $report.Add('NETWORK_REFERENCE_COMMENT_LINE_COUNT='+$networkComment)
 $report.Add('PG_CRON_REFERENCE_LINES='+$cron)
 $report.Add('PG_NET_REFERENCE_LINES='+$pgnet)
 $report.Add('SHARED_PRELOAD_REFERENCE_LINES='+$preload)
 if($networkExec -gt 0){$report.Add('[AVISO] NETWORK_RELATED_CODE_PRESENT_DO_NOT_START')}
 else{$report.Add('[INFO] NO_ACTIVE_NETWORK_REFERENCE_OBSERVED_IN_SCANNED_FILES')}
 $report.Add('[LIMITE] Static scan cannot certify behavior of image hooks, binaries, or runtime')
 $report.Add('[LIMITE] No container start, writes, SQL, or remote traffic performed')
 $report.Add('[CONCLUIDO] STARTUP_HOOK_CLASSIFICATION_ONLY')
 $report.Add('[PROXIMO] SAFE_POSTGRES_START_DESIGN')
 $passed=$true
}catch{
 $code=[string]$_.Exception.Message
 if($code -cnotmatch '^[A-Z0-9_]{3,90}$'){$code='LOCAL_ERROR_REDACTED'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$code)
}finally{
 if($work -and (Test-Path -LiteralPath $work)){Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue}
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $passed){exit 1}
