# ROTA62 Guardian CLEAN6 v0.6.0 - initialize NEW disposable PostgreSQL data only.
# Runs initdb DIRECTLY in an ephemeral --network none container, bypassing the Supabase entrypoint.
# Never starts CLEAN6, never touches previous labs, remote services, SQL, backup, or secrets.
# Windows PowerShell 5.1. Outputs and clipboard contain safe status labels only.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 DIRECT INITDB v0.6.0 ===')
$r.Add('[MODO] ISOLATED_NEW_VOLUME_INIT_ONLY_NO_RESTORE')
$stage='PRECHECK';$success=$false;$temp=$null
function InspectOne([string]$name){
 $raw=@(& docker inspect $name 2>$null)
 if($LASTEXITCODE -ne 0){throw 'DOCKER_INSPECT_FAILED'}
 $items=@(ConvertFrom-Json -InputObject ($raw -join [Environment]::NewLine))
 if($items.Count -ne 1){throw 'DOCKER_INSPECT_COUNT_INVALID'}
 return $items[0]
}
function DockerQuiet([string[]]$argv){
 $previous=$ErrorActionPreference
 try{
   $ErrorActionPreference='Continue'
   $null=@(& docker @argv 2>$null)
   return ($LASTEXITCODE -eq 0)
 }catch{return $false}finally{$ErrorActionPreference=$previous}
}
function DockerGet([string[]]$argv){
 $previous=$ErrorActionPreference
 try{
  $ErrorActionPreference='Continue'
  $lines=@(& docker @argv 2>$null)
  $exit=$LASTEXITCODE
 }catch{throw 'DOCKER_QUERY_EXCEPTION'}finally{$ErrorActionPreference=$previous}
 if($exit -ne 0){throw 'DOCKER_QUERY_FAILED'}
 return (($lines -join [Environment]::NewLine).Trim())
}
try{
 $stage='LAB_IDENTITY'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_NOT_FOUND'}
 $c=InspectOne $cn
 $ref=InspectOne $reference
 if([string]$c.State.Status -cne 'created' -or $c.State.Running -ne $false){throw 'CLEAN6_MUST_BE_CREATED_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_UNEXPECTED'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CLEAN6_PUBLISHED_PORTS_PRESENT'}
 if([string]$c.HostConfig.RestartPolicy.Name -cne 'no'){throw 'CLEAN6_RESTART_POLICY_UNEXPECTED'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn -or [string]$c.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'CLEAN6_VOLUME_MISMATCH'}
 if([string]$ref.State.Status -cne 'running'){throw 'REFERENCE_NOT_RUNNING'}
 if([string]$ref.Image -cne [string]$c.Image){throw 'PINNED_IMAGE_MISMATCH'}
 $image=[string]$c.Image
 if($image -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'IMAGE_DIGEST_INVALID'}
 $r.Add('[OK] CLEAN6_STOPPED_AND_IMAGE_IDENTITY')
 $stage='VOLUME_EXCLUSIVITY'
 $volumeRaw=DockerGet @('volume','inspect',$vn)
 $v=@(ConvertFrom-Json -InputObject $volumeRaw)
 if($v.Count -ne 1 -or [string]$v[0].Name -cne $vn){throw 'VOLUME_MISSING'}
 $users=DockerGet @('ps','--filter',('volume='+$vn),'--format','{{.ID}}')
 if($users.Trim().Length -gt 0){throw 'VOLUME_IN_USE_BY_RUNNING_CONTAINER'}
 $r.Add('[OK] DISPOSABLE_VOLUME_NO_RUNNING_CONSUMER')
 $stage='PGDATA'
 $envvars=@($c.Config.Env|Where-Object {$_ -match '^PGDATA='})
 if($envvars.Count -ne 1){throw 'PGDATA_REQUIRED_UNIQUE'}
 $pgdata=([string]$envvars[0]).Substring(7)
 if($pgdata -notmatch '^/var/lib/postgresql/data(?:/[A-Za-z0-9._/-]+)?$' -or $pgdata -match '(^|/)\.\.(/|$)'){throw 'PGDATA_OUTSIDE_DISPOSABLE_VOLUME'}
 $r.Add('[OK] PGDATA_INSIDE_CLEAN6_VOLUME')
 $stage='INITDB_BINARY'
 # Extract only the binary location from the pinned local reference; never print it.
 $path=DockerGet @('exec','--user','postgres',$reference,'sh','-c','command -v initdb')
 if($path -notmatch '^/[a-zA-Z0-9._/-]{5,200}$' -or $path -match '(^|/)\.\.(/|$)'){throw 'INITDB_PATH_INVALID'}
 # Verify the SAME file exists in the stopped CLEAN6 image, not only reference writable layer.
 $temp=Join-Path $env:TEMP ('R62-initdb-bin-'+[guid]::NewGuid().ToString('N'))
 $null=New-Item -ItemType Directory -Path $temp -Force
 $copy=Join-Path $temp 'initdb'
 if(-not (DockerQuiet @('cp',($cn+':'+$path),$copy))){throw 'INITDB_NOT_PRESENT_IN_CLEAN6_IMAGE'}
 if(-not (Test-Path -LiteralPath $copy -PathType Leaf)){throw 'INITDB_COPY_NOT_REGULAR_FILE'}
 if((Get-Item -LiteralPath $copy).Length -lt 32768){throw 'INITDB_UNEXPECTED_SIZE'}
 $r.Add('[OK] INITDB_PATH_VERIFIED_IN_STOPPED_IMAGE')
 $stage='EMPTY_VOLUME_PREFLIGHT'
 # Explicit /bin/sh bypasses entrypoint and only inspects PGDATA/parent permissions.
 $check='set -eu; case "$PGDATA" in /var/lib/postgresql/data|/var/lib/postgresql/data/*) ;; *) exit 71;; esac; p="$PGDATA"; if [ ! -d "$p" ]; then p="$(dirname "$PGDATA")"; fi; test -d "$p" && test -w "$p" || exit 72; if [ -d "$PGDATA" ]; then test -z "$(find "$PGDATA" -mindepth 1 -maxdepth 1 -print -quit)" || exit 73; elif [ -e "$PGDATA" ]; then exit 74; fi'
 $base=@('run','--rm','--pull','never','--network','none','--user','postgres',
   '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128',
   '--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data'))
 if(-not (DockerQuiet ($base+@('--entrypoint','/bin/sh',$image,'-c',$check)))){throw 'PGDATA_NOT_EMPTY_OR_NOT_WRITABLE'}
 $r.Add('[OK] PGDATA_EMPTY_AND_WRITABLE_AS_POSTGRES')
 $stage='INITDB'
 # Performs an actual write ONLY inside the disposable CLEAN6 named volume.
 # Peer auth on local UNIX socket; all TCP host authentication rejected.
 $initArguments=@('--entrypoint',$path,$image,
   '-D',$pgdata,'--username=postgres','--auth-local=peer','--auth-host=reject','--no-instructions')
 if(-not (DockerQuiet ($base+$initArguments))){throw 'INITDB_FAILED_CHECK_DISPOSABLE_VOLUME_BEFORE_RETRY'}
 $r.Add('[OK] INITDB_COMPLETED_WITH_ENTRYPOINT_BYPASSED')
 $stage='VALIDATE'
 $verify='set -eu; test -f "$PGDATA/PG_VERSION"; grep -qx 17 "$PGDATA/PG_VERSION"; test -f "$PGDATA/pg_hba.conf"; grep -Eq "^local[[:space:]]+all[[:space:]]+all[[:space:]]+peer" "$PGDATA/pg_hba.conf"; grep -Eq "^host[[:space:]]+all[[:space:]]+all[[:space:]]+all[[:space:]]+reject" "$PGDATA/pg_hba.conf"'
 if(-not (DockerQuiet ($base+@('--entrypoint','/bin/sh',$image,'-c',$verify)))){throw 'POST_INITDB_VALIDATION_FAILED'}
 $r.Add('[OK] PG_VERSION_17_AND_LOCAL_PEER_HOST_REJECT')
 $r.Add('[OK] NO_DOCKER_START_OF_CLEAN6_OR_PREVIOUS_LABS')
 $r.Add('[LIMITE] PostgreSQL server not started and backup not restored')
 $r.Add('[NEXT] CREATE_DIRECT_POSTGRES_SERVER_CONTAINER_NO_ENTRYPOINT')
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]{3,100}$'){$reason='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
 if($stage -in @('INITDB','VALIDATE')){$r.Add('[AVISO] CLEAN6_VOLUME_MAY_BE_INITIALIZED_DO_NOT_RERUN_AUTOMATICALLY')}
}finally{
 if($temp -and (Test-Path -LiteralPath $temp)){Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
 $output=$r -join [Environment]::NewLine
 Write-Output $output
 try{Set-Clipboard -Value $output -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
