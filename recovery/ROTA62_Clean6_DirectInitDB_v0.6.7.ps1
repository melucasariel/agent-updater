# ROTA62 Guardian CLEAN6 direct initdb v0.6.7
# Initializes only disposable named volume rota62_guardian_clean6_data, via local pinned Docker image.
# Bypasses Supabase entrypoint and its migration hooks with --entrypoint /bin/sh.
# Never starts CLEAN6, connects to network, publishes ports, or touches the backup/older labs.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 DIRECT INITDB v0.6.7 ===')
$r.Add('[MODO] INIT_DISPOSABLE_VOLUME_ONLY_NETWORK_NONE_NO_RESTORE')
$stage='PRECHECK';$ok=$false
function DockerGet([string[]]$a){
 $old=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$out=@(& docker @a 2>$null);$exit=$LASTEXITCODE}
 catch{throw 'DOCKER_METADATA_EXCEPTION'}finally{$ErrorActionPreference=$old}
 if($exit -ne 0){throw 'DOCKER_METADATA_FAILED'}
 return ($out -join [Environment]::NewLine).Trim()
}
function DockerRunExit([string[]]$a){
 $old=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$null=@(& docker @a 2>$null);return $LASTEXITCODE}
 catch{return -1}finally{$ErrorActionPreference=$old}
}
try{
 $stage='IDENTITY'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $containers=@(ConvertFrom-Json -InputObject (DockerGet @('inspect',$cn)))
 $refs=@(ConvertFrom-Json -InputObject (DockerGet @('inspect',$reference)))
 if($containers.Count -ne 1 -or $refs.Count -ne 1){throw 'INSPECT_COUNT_INVALID'}
 $c=$containers[0];$ref=$refs[0]
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_MUST_BE_CREATED_NOT_RUNNING'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_NOT_NONE'}
 if([string]$c.HostConfig.RestartPolicy.Name -cne 'no'){throw 'CLEAN6_RESTART_UNEXPECTED'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CLEAN6_PORTS_PRESENT'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn -or [string]$c.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'CLEAN6_VOLUME_MISMATCH'}
 if([string]$ref.State.Status -cne 'running' -or [string]$ref.Image -cne [string]$c.Image){throw 'PINNED_REFERENCE_MISMATCH'}
 $image=[string]$c.Image
 if($image -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'IMAGE_ID_INVALID'}
 $volumes=@(ConvertFrom-Json -InputObject (DockerGet @('volume','inspect',$vn)))
 if($volumes.Count -ne 1 -or [string]$volumes[0].Name -cne $vn){throw 'VOLUME_MISSING'}
 $active=DockerGet @('ps','--filter',('volume='+$vn),'--format','{{.ID}}')
 if($active.Length -gt 0){throw 'VOLUME_ALREADY_IN_USE'}
 $pgdataVars=@($c.Config.Env | Where-Object {$_ -match '^PGDATA='})
 if($pgdataVars.Count -ne 1 -or [string]$pgdataVars[0] -cne 'PGDATA=/var/lib/postgresql/data'){throw 'PGDATA_MUST_BE_VOLUME_ROOT'}
 $r.Add('[OK] CLEAN6_STOPPED_EXCLUSIVE_VOLUME_AND_PINNED_IMAGE')
 $stage='RECHECK_EMPTY'
 # Single pure-shell predicate; no writes. Same root and user verified in v0.6.6.
 $base=@('run','--rm','--pull','never','--network','none','--user','postgres',
   '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128',
   '--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data'),
   '--env','PGDATA=/var/lib/postgresql/data',
   '--entrypoint','/bin/sh',$image,'-c')
 $check='set -eu; test -d "$PGDATA"; test -x "$PGDATA"; test -w "$PGDATA"; test -z "$(find "$PGDATA" -mindepth 1 -maxdepth 1 -print -quit)"; command -v initdb >/dev/null; command -v postgres >/dev/null'
 if((DockerRunExit ($base+@($check))) -ne 0){throw 'EMPTY_WRITABLE_BINARIES_RECHECK_FAILED'}
 $r.Add('[OK] PGDATA_EMPTY_AND_WRITABLE_RECHECK')
 $stage='INITDB'
 # Initdb is invoked directly, NOT the container image entrypoint.
 # Only unix peer authentication is accepted; host/TCP records reject connections.
 # Docker network is disabled. This is the first intentional volume write.
 $init='set -eu; exec "$(command -v initdb)" -D "$PGDATA" --username=postgres --auth-local=peer --auth-host=reject --no-instructions'
 if((DockerRunExit ($base+@($init))) -ne 0){throw 'INITDB_FAILED_PRESERVE_VOLUME_NO_RETRY'}
 $r.Add('[OK] DIRECT_INITDB_COMPLETED')
 $stage='VERIFY'
 $verify='set -eu; test -f "$PGDATA/PG_VERSION"; grep -qx 17 "$PGDATA/PG_VERSION"; test -f "$PGDATA/pg_hba.conf"; grep -Eq "^local[[:space:]]+all[[:space:]]+all[[:space:]]+peer([[:space:]]|$)" "$PGDATA/pg_hba.conf"; grep -Eq "^host[[:space:]]+all[[:space:]]+all[[:space:]]+[^[:space:]]+[[:space:]]+reject([[:space:]]|$)" "$PGDATA/pg_hba.conf"'
 if((DockerRunExit ($base+@($verify))) -ne 0){throw 'INITIALIZED_FILES_VERIFICATION_FAILED_NO_RETRY'}
 $r.Add('[OK] POSTGRESQL_17_PEER_LOCAL_REJECT_HOST')
 $r.Add('[OK] SUPABASE_ENTRYPOINT_AND_64_INIT_HOOKS_NOT_RUN')
 $r.Add('[OK] CLEAN6_CONTAINER_REMAINS_STOPPED')
 $r.Add('[LIMITE] No postgres server started, no SQL executed, no backup restored')
 $r.Add('[NEXT] START_NEW_SEPARATE_SERVER_WITH_DISABLED_BACKGROUND_WORKERS')
 $ok=$true
}catch{
 $msg=[string]$_.Exception.Message
 if($msg -cnotmatch '^[A-Z0-9_]{3,100}$'){$msg='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$msg)
 if($stage -eq 'INITDB' -or $stage -eq 'VERIFY'){$r.Add('[AVISO] VOLUME_MAY_HAVE_CHANGED_DO_NOT_REPEAT_OR_DELETE')}
}finally{
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
