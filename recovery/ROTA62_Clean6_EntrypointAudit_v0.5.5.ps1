# ROTA62 Guardian CLEAN6 - offline entrypoint inspection v0.5.5
# Windows PowerShell 5.1. Read-only Docker inspect/cp. Does not start container or run SQL.
# Copies only allowlisted nonsecret startup shell scripts from stopped CLEAN6 container into TEMP.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$container='rota62_guardian_clean6_pg'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN6 ENTRYPOINT AUDIT v0.5.5 ===')
$report.Add('[MODO] READ_ONLY_DOCKER_CP_NO_START_NO_SQL')
$stage='INIT'
$success=$false
$work=$null
function D([string[]]$argsDocker){
 $output=@(& docker @argsDocker 2>$null)
 if($LASTEXITCODE -ne 0){throw 'DOCKER_INSPECT_FAILED'}
 return (($output -join [Environment]::NewLine).Trim())
}
function CopyStartup([string]$source,[string]$dest){
 $old=$ErrorActionPreference
 try {
  $ErrorActionPreference='Continue'
  $null=@(& docker cp ($container+':'+$source) $dest 2>$null)
  return ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $dest -PathType Leaf))
 } catch { return $false
 } finally { $ErrorActionPreference=$old }
}
try {
 $stage='CONTAINER'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_NOT_FOUND'}
 $raw=D @('inspect',$container)
 $c=@($raw|ConvertFrom-Json)[0]
 if(-not $c -or [string]$c.State.Status -cne 'created' -or $c.State.Running -ne $false){throw 'CONTAINER_NOT_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'NETWORK_NOT_NONE'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'PUBLISHED_PORTS_DETECTED'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne 'rota62_guardian_clean6_data'){throw 'VOLUME_UNEXPECTED'}
 $report.Add('[OK] CLEAN6_STOPPED_ISOLATED_AND_MOUNT_PINNED')
 $stage='ENTRYPOINT'
 $ep=@($c.Config.Entrypoint | Where-Object {$_})
 $cmd=@($c.Config.Cmd | Where-Object {$_})
 if($ep.Count -eq 0){$report.Add('ENTRYPOINT_TYPE=IMAGE_CMD_ONLY')}
 elseif([string]$ep[0] -match '^/'){ $report.Add('ENTRYPOINT_TYPE=ABSOLUTE_PATH') }
 else { $report.Add('ENTRYPOINT_TYPE=PATH_LOOKUP_OR_SHELL') }
 if($cmd.Count -gt 0){$report.Add('IMAGE_CMD_PRESENT=YES')}else{$report.Add('IMAGE_CMD_PRESENT=NO')}
 # Don't print the entrypoint or image environment to avoid accidental secrets.
 $stage='ENTRYPOINT_COPY'
 $work=Join-Path $env:TEMP ('R62-entry-audit-'+[guid]::NewGuid().ToString('N'))
 $null=New-Item -Path $work -ItemType Directory -Force
 $entry=[string]$(if($ep.Count -gt 0){$ep[0]}else{''})
 $allowed=$false
 if($entry -cmatch '^/(usr/local/bin|usr/bin|bin|opt/bitnami/scripts)/[A-Za-z0-9_./-]+(\.sh|\.bash|docker-entrypoint)$' -and $entry -notmatch '\.\.'){
  $allowed=$true
 }
 # Some images use the shell script without .sh suffix; inspect known candidate paths only.
 $candidates=New-Object 'System.Collections.Generic.List[string]'
 if($allowed){[void]$candidates.Add($entry)}
 foreach($known in @('/usr/local/bin/docker-entrypoint.sh','/usr/local/bin/docker-entrypoint','/docker-entrypoint.sh')){
  if(-not $candidates.Contains($known)){[void]$candidates.Add($known)}
 }
 $found=0
 $signalCron=0
 $signalNet=0
 $signalPreload=0
 $signalInit=0
 $signalExternal=0
 foreach($p in $candidates){
  $dest=Join-Path $work ('script_'+$found+'.txt')
  if(-not (CopyStartup $p $dest)){continue}
  $fi=Get-Item -LiteralPath $dest
  if($fi.Length -gt 1048576){throw 'STARTUP_SCRIPT_EXCEEDS_SAFE_INSPECTION_LIMIT'}
  $rawScript=[IO.File]::ReadAllText($dest)
  $found++
  if($rawScript -match 'pg_cron|cron\.launch_active_jobs'){$signalCron++}
  if($rawScript -match 'pg_net|pg_net\.'){$signalNet++}
  if($rawScript -match 'shared_preload_libraries'){$signalPreload++}
  if($rawScript -match '(docker-entrypoint-initdb\.d|initdb|postgresql\.conf)'){$signalInit++}
  if($rawScript -match '(curl[ \t]|wget[ \t]|https?://)'){$signalExternal++}
 }
 $report.Add('STARTUP_SCRIPTS_READ='+$found)
 $report.Add('SIGNAL_CRON='+$(if($signalCron){'PRESENT'}else{'NOT_OBSERVED'}))
 $report.Add('SIGNAL_PG_NET='+$(if($signalNet){'PRESENT'}else{'NOT_OBSERVED'}))
 $report.Add('SIGNAL_SHARED_PRELOAD='+$(if($signalPreload){'PRESENT'}else{'NOT_OBSERVED'}))
 $report.Add('SIGNAL_INITDB='+$(if($signalInit){'PRESENT'}else{'NOT_OBSERVED'}))
 $report.Add('SIGNAL_EXTERNAL_FETCH='+$(if($signalExternal){'PRESENT'}else{'NOT_OBSERVED'}))
 $stage='IMAGE_CONFIG'
 $imageId=[string]$c.Image
 if($imageId -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'IMAGE_ID_INVALID'}
 $imgRaw=D @('image','inspect',$imageId)
 $img=@($imgRaw|ConvertFrom-Json)[0]
 if(-not $img -or [string]$img.Id -cne $imageId){throw 'IMAGE_CONFIG_NOT_FOUND'}
 $envNames=@($img.Config.Env | ForEach-Object {($_ -split '=',2)[0]})
 foreach($name in @('PGDATA','POSTGRES_INITDB_ARGS','POSTGRES_PASSWORD','POSTGRES_HOST_AUTH_METHOD')){
  $report.Add(('IMAGE_ENV_NAME_'+$name)+'='+$(if($envNames -contains $name){'PRESENT'}else{'NOT_PRESENT'}))
 }
 $report.Add('[LIMITE] Shell static scan is not a proof of startup safety')
 $report.Add('[LIMITE] Image initialization directories/extensions may still activate hooks')
 $report.Add('[LIMITE] No actual container execution, DB, ports or network connection tested')
 if($found -eq 0){$report.Add('[AVISO] NO_STARTUP_SCRIPT_READ_DO_NOT_START')}
 $report.Add('[CONCLUIDO] STOPPED_IMAGE_ENTRYPOINT_STATIC_INSPECTION')
 $report.Add('[PROXIMO] CONTROLLED_INIT_DESIGN_BEFORE_START')
 $success=$true
}catch{
 $message=[string]$_.Exception.Message
 if($message -cnotmatch '^[A-Z0-9_]{3,90}$'){$message='LOCAL_STATIC_INSPECTION_ERROR'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$message)
}finally{
 if($work -and (Test-Path -LiteralPath $work -PathType Container)){Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue}
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop; Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
