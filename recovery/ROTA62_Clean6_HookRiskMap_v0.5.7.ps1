# ROTA62 CLEAN6: classify startup hook risk by file - v0.5.7
# READ ONLY container/image. Only docker inspect and docker cp; never execute, start or restore.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN6 HOOK RISK MAP v0.5.7 ===')
$report.Add('[MODO] READ_ONLY_NO_START_NO_SQL_NO_SECRET_VALUES')
$stage='INIT'; $ok=$false; $tmp=$null
function DockerRead([string[]]$arguments) {
  $data=@(& docker @arguments 2>$null)
  if($LASTEXITCODE -ne 0){throw 'DOCKER_INSPECT_FAILED'}
  return (($data -join [Environment]::NewLine).Trim())
}
function DockerCopy([string]$source,[string]$target) {
  $previous=$ErrorActionPreference
  try {
    $ErrorActionPreference='Continue'
    $null=@(& docker cp ($cn+':'+$source) $target 2>$null)
    return ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $target))
  } catch {return $false} finally {$ErrorActionPreference=$previous}
}
try {
  $stage='SAFETY'
  if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
  $raw=DockerRead @('inspect',$cn)
  $obj=@(ConvertFrom-Json -InputObject $raw)
  if($obj.Count -ne 1){throw 'CONTAINER_INSPECT_INVALID'}
  $c=$obj[0]
  if([string]$c.State.Status -cne 'created' -or $c.State.Running -ne $false){throw 'CONTAINER_MUST_REMAIN_STOPPED'}
  if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'NETWORK_NONE_REQUIRED'}
  if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'PUBLISHED_PORTS_BLOCKED'}
  if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn){throw 'VOLUME_MISMATCH'}
  $report.Add('[OK] CLEAN6_STOPPED_ISOLATION_REVALIDATED')
  $stage='FILE_COPY'
  $tmp=Join-Path $env:TEMP ('R62-CLEAN6-RISK-'+[guid]::NewGuid().ToString('N'))
  $null=New-Item -ItemType Directory -Path $tmp -Force
  $hooks=Join-Path $tmp 'hooks'
  if(-not (DockerCopy '/docker-entrypoint-initdb.d' $hooks)){throw 'INIT_HOOKS_NOT_READABLE'}
  $paths=@('/usr/local/bin/docker-entrypoint.sh','/usr/local/bin/docker-entrypoint','/docker-entrypoint.sh')
  $entry=@($c.Config.Entrypoint|Where-Object {$_})
  if($entry.Count -gt 0 -and [string]$entry[0] -cmatch '^/(usr/local/bin|usr/bin|bin)/[A-Za-z0-9_./-]+$' -and [string]$entry[0] -notmatch '\.\.'){
    $paths=@([string]$entry[0])+$paths
  }
  $entryCount=0; $items=New-Object 'System.Collections.Generic.List[object]'
  $seen=New-Object 'System.Collections.Generic.HashSet[string]'
  foreach($p in $paths){
    if(-not $seen.Add($p)){continue}
    $dest=Join-Path $tmp ('entry'+$entryCount+'.txt')
    if(DockerCopy $p $dest){
      $fi=Get-Item -LiteralPath $dest
      $items.Add([pscustomobject]@{File=$fi;Label='ENTRYPOINT_'+$entryCount})
      $entryCount++
    }
  }
  $files=@(Get-ChildItem -LiteralPath $hooks -File -Recurse -ErrorAction Stop)
  if($files.Count -gt 128){throw 'HOOK_FILE_COUNT_EXCEEDS_LIMIT'}
  foreach($file in $files){
    $name=$file.FullName.Substring($hooks.Length).TrimStart('\','/')
    $safeName=($name -replace '[^A-Za-z0-9._/-]','_')
    if($safeName.Length -gt 90){$safeName=$safeName.Substring(0,90)}
    $items.Add([pscustomobject]@{File=$file;Label=$safeName})
  }
  $report.Add('HOOK_FILES='+$files.Count)
  $report.Add('ENTRYPOINT_SCRIPTS='+$entryCount)
  $stage='CLASSIFICATION'
  $total=0L; $risk=New-Object 'System.Collections.Generic.List[object]'
  foreach($item in $items){
    $file=$item.File
    if($file.Length -gt 1048576){throw 'HOOK_FILE_TOO_LARGE'}
    $total+=$file.Length
    if($total -gt 6291456){throw 'HOOK_SCAN_TOTAL_LIMIT'}
    if($file.Extension -notin @('.sh','.bash','.sql','.conf','.txt','.py','')){continue}
    $stats=[ordered]@{direct=0;url=0;comment=0;cron=0;pgnet=0;preload=0;init=0;code=0}
    foreach($line in [IO.File]::ReadLines($file.FullName)){
      $t=$line.Trim(); if($t -eq ''){continue}
      $isComment=($t.StartsWith('#') -or $t.StartsWith('--'))
      if($isComment){if($t -match '(?i)(curl|wget|https?://)'){$stats.comment++};continue}
      $stats.code++
      if($t -match '(?i)(^|[;&|() \t])(curl|wget)[ \t]'){$stats.direct++}
      if($t -match '(?i)https?://'){$stats.url++}
      if($t -match '(?i)pg_cron|cron\.launch_active_jobs'){$stats.cron++}
      if($t -match '(?i)pg_net|pg_net\.'){$stats.pgnet++}
      if($t -match '(?i)shared_preload_libraries'){$stats.preload++}
      if($t -match '(?i)initdb|docker-entrypoint-initdb'){$stats.init++}
    }
    if($stats.direct+$stats.url+$stats.cron+$stats.pgnet+$stats.preload -gt 0){
      $score=10*$stats.direct+4*$stats.url+$stats.cron+$stats.pgnet+$stats.preload
      $risk.Add([pscustomobject]@{Label=$item.Label;S=$score;V=$stats})
    }
  }
  $report.Add('FILES_WITH_RELEVANT_SIGNALS='+$risk.Count)
  foreach($item in @($risk|Sort-Object -Property S -Descending|Select-Object -First 25)){
    $v=$item.V
    $report.Add(('FILE='+$item.Label+' CURL_WGET_CODE='+$v.direct+' URL_CODE='+$v.url+' NETWORK_COMMENT='+$v.comment+' CRON_CODE='+$v.cron+' PGNET_CODE='+$v.pgnet+' PRELOAD_CODE='+$v.preload))
  }
  if($risk.Count -gt 25){$report.Add('ADDITIONAL_SIGNAL_FILES_NOT_SHOWN='+($risk.Count-25))}
  $report.Add('[LIMITE] Counts are syntactic; indirect shell calls, binaries and SQL may behave differently')
  $report.Add('[LIMITE] No raw script content, URLs, environment values or secrets included')
  $report.Add('[CONCLUIDO] STARTUP_RISK_FILES_CLASSIFIED')
  $report.Add('[NEXT] REVIEW_INIT_HOOKS_AND_DESIGN_CONTROLLED_POSTGRES_BOOT')
  $ok=$true
}catch{
  $reason=[string]$_.Exception.Message
  if($reason -cnotmatch '^[A-Z0-9_]+$'){$reason='SAFE_LOCAL_AUDIT_FAILURE'}
  $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
  if($tmp -and (Test-Path -LiteralPath $tmp)){Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue}
  $out=$report -join [Environment]::NewLine
  Write-Output $out
  try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
