# ROTA62 Guardian CLEAN6 - isolated direct initdb v0.6.2
# Initializes ONLY the disposable CLEAN6 data volume via pinned local Docker image.
# Ephemeral Docker --network none, --entrypoint /bin/sh: never runs Supabase entrypoint or hooks.
# Does NOT start CLEAN6 / other labs, expose ports, access production, restore or decrypt backup.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN6 DIRECT INITDB v0.6.2 ===')
$report.Add('[MODO] ISOLATED_DISPOSABLE_VOLUME_ONLY_NO_ENTRYPOINT_NO_RESTORE')
$stage='PRECHECK';$success=$false
function DockerGet([string[]]$argv){
  $previous=$ErrorActionPreference
  try{
    $ErrorActionPreference='Continue'
    $lines=@(& docker @argv 2>$null)
    $code=$LASTEXITCODE
  }catch{throw 'DOCKER_QUERY_EXCEPTION'}finally{$ErrorActionPreference=$previous}
  if($code -ne 0){throw 'DOCKER_QUERY_FAILED'}
  return (($lines -join [Environment]::NewLine).Trim())
}
function DockerQuiet([string[]]$argv){
  $previous=$ErrorActionPreference
  try{
    $ErrorActionPreference='Continue'
    $null=@(& docker @argv 2>$null)
    return ($LASTEXITCODE -eq 0)
  }catch{return $false}finally{$ErrorActionPreference=$previous}
}
try {
 $stage='VERIFY_CLEAN6'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_NOT_FOUND'}
 $cs=@(ConvertFrom-Json -InputObject (DockerGet @('inspect',$cn)))
 $rs=@(ConvertFrom-Json -InputObject (DockerGet @('inspect',$reference)))
 if($cs.Count -ne 1 -or $rs.Count -ne 1){throw 'LAB_INSPECT_COUNT_INVALID'}
 $c=$cs[0];$ref=$rs[0]
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_MUST_REMAIN_CREATED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_NOT_NONE'}
 if([string]$c.HostConfig.RestartPolicy.Name -cne 'no'){throw 'CLEAN6_RESTART_POLICY_NOT_NO'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CLEAN6_PORT_BINDINGS_PRESENT'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn -or [string]$c.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'CLEAN6_VOLUME_NOT_EXCLUSIVE'}
 if([string]$ref.State.Status -cne 'running'){throw 'REFERENCE_NOT_RUNNING'}
 if([string]$c.Image -cne [string]$ref.Image){throw 'IMAGE_ID_MISMATCH'}
 $image=[string]$c.Image
 if($image -cnotmatch '^sha256:[0-9a-f]{64}$'){throw 'IMAGE_ID_INVALID'}
 $report.Add('[OK] CLEAN6_STOPPED_IMAGE_PINNED')
 $stage='VOLUME_CHECK'
 $vs=@(ConvertFrom-Json -InputObject (DockerGet @('volume','inspect',$vn)))
 if($vs.Count -ne 1 -or [string]$vs[0].Name -cne $vn){throw 'VOLUME_NOT_FOUND'}
 $users=DockerGet @('ps','--filter',('volume='+$vn),'--format','{{.ID}}')
 if($users.Trim().Length -gt 0){throw 'CLEAN6_VOLUME_IN_USE'}
 $report.Add('[OK] CLEAN6_VOLUME_NOT_IN_USE')
 $stage='PGDATA_PATH'
 $pgdataEnv=@($c.Config.Env|Where-Object {$_ -match '^PGDATA='})
 if($pgdataEnv.Count -ne 1){throw 'PGDATA_NOT_UNIQUE'}
 $pgdata=([string]$pgdataEnv[0]).Substring(7)
 if($pgdata -notmatch '^/var/lib/postgresql/data(?:/[a-zA-Z0-9._/-]+)?$' -or $pgdata -match '(^|/)\.\.(/|$)'){throw 'PGDATA_PATH_REJECTED'}
 $report.Add('[OK] PGDATA_INSIDE_DISPOSABLE_VOLUME')
 # This is a NEW test volume only. Do not mount production or older LAB volumes.
 $base=@('run','--rm','--pull','never','--network','none','--user','postgres',
   '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128',
   '--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data'),
   '--env',('PGDATA='+$pgdata),'--entrypoint','/bin/sh',$image,'-c')
 $stage='EMPTY_AND_WRITABLE'
 # Shell-only preflight. Never runs initdb until path is proven empty and writable.
 $probe='set -eu; case "$PGDATA" in /var/lib/postgresql/data|/var/lib/postgresql/data/*) ;; *) exit 71;; esac; p="$PGDATA"; if [ -d "$p" ]; then test -w "$p" || exit 72; test -z "$(find "$p" -mindepth 1 -maxdepth 1 -print -quit)" || exit 73; elif [ -e "$p" ]; then exit 74; else p="$(dirname "$p")"; test -d "$p" && test -w "$p" || exit 75; fi; command -v initdb >/dev/null; command -v postgres >/dev/null'
 if(-not (DockerQuiet ($base+@($probe)))){throw 'PGDATA_NOT_EMPTY_NOT_WRITABLE_OR_TOOLS_MISSING'}
 $report.Add('[OK] PGDATA_EMPTY_WRITABLE_BINARIES_AVAILABLE')
 $stage='EXECUTE_INITDB'
 # Explicitly bypass the image's default entrypoint and its 64 setup files.
 # Peer auth limits UNIX-socket access to the local postgres OS user.
 # All TCP host rules are reject, and network is none at Docker level.
 $init='set -eu; exec "$(command -v initdb)" -D "$PGDATA" --username=postgres --auth-local=peer --auth-host=reject --no-instructions'
 if(-not (DockerQuiet ($base+@($init)))){throw 'DIRECT_INITDB_FAILED_DO_NOT_RETRY'}
 $report.Add('[OK] DIRECT_INITDB_COMPLETED')
 $stage='VALIDATION'
 $check='set -eu; test -f "$PGDATA/PG_VERSION"; grep -qx 17 "$PGDATA/PG_VERSION"; test -f "$PGDATA/pg_hba.conf"; grep -Eq "^local[[:space:]]+all[[:space:]]+all[[:space:]]+peer([[:space:]]|$)" "$PGDATA/pg_hba.conf"; grep -Eq "^host[[:space:]]+all[[:space:]]+all[[:space:]]+[^[:space:]]+[[:space:]]+reject([[:space:]]|$)" "$PGDATA/pg_hba.conf"'
 if(-not (DockerQuiet ($base+@($check)))){throw 'INITDB_RESULT_NOT_VERIFIED_DO_NOT_RETRY'}
 $report.Add('[OK] PG_VERSION_17_LOCAL_PEER_TCP_REJECT')
 $report.Add('[OK] DEFAULT_SUPABASE_ENTRYPOINT_NOT_RUN')
 $report.Add('[OK] CLEAN6_AND_PREVIOUS_LABS_NOT_STARTED_OR_MODIFIED')
 $report.Add('[LIMITE] PostgreSQL server not started; no backup restore attempted')
 $report.Add('[NEXT] PREPARE_DIRECT_OFFLINE_POSTGRES_START_WITH_WORKERS_DISABLED')
 $success=$true
}catch{
 $msg=[string]$_.Exception.Message
 if($msg -cnotmatch '^[A-Z0-9_]{3,100}$'){$msg='LOCAL_ERROR_REDACTED'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$msg)
 if($stage -in @('EXECUTE_INITDB','VALIDATION')){$report.Add('[AVISO] VOLUME_MAY_CONTAIN_INITIALIZED_DATA_DO_NOT_RERUN')}
}finally{
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
