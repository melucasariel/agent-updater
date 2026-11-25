# ROTA62 Guardian CLEAN6 v0.6.3 - diagnose blocked initdb preflight
# READ ONLY probes of a new disposable volume. Never runs initdb, SQL, or postgres.
# Uses pinned local image with --network none and --entrypoint /bin/sh.
# No production/other labs affected; prints only allowlisted status.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN6 PGDATA DIAGNOSTIC v0.6.3 ===')
$report.Add('[MODO] READ_ONLY_SHELL_PROBES_NO_INITDB_NO_SQL')
$stage='PRECHECK'; $success=$false
function DockerGet([string[]]$argsDocker){
 $old=$ErrorActionPreference
 try {
  $ErrorActionPreference='Continue'
  $rows=@(& docker @argsDocker 2>$null)
  $exit=$LASTEXITCODE
 }catch{throw 'DOCKER_READ_EXCEPTION'}finally{$ErrorActionPreference=$old}
 if($exit -ne 0){throw 'DOCKER_READ_FAILED'}
 return (($rows -join [Environment]::NewLine).Trim())
}
try {
 $stage='IDENTITY'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_NOT_FOUND'}
 $cl=@(ConvertFrom-Json -InputObject (DockerGet @('inspect',$cn)))
 $re=@(ConvertFrom-Json -InputObject (DockerGet @('inspect',$reference)))
 if($cl.Count -ne 1 -or $re.Count -ne 1){throw 'INSPECT_CARDINALITY_INVALID'}
 $c=$cl[0];$ref=$re[0]
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_NOT_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_MISMATCH'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn -or [string]$c.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'CLEAN6_MOUNT_MISMATCH'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CLEAN6_PORTS_PRESENT'}
 if([string]$ref.State.Status -cne 'running' -or [string]$ref.Image -cne [string]$c.Image){throw 'REFERENCE_MISMATCH'}
 $image=[string]$c.Image
 if($image -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'PINNED_IMAGE_ID_INVALID'}
 $v=@(ConvertFrom-Json -InputObject (DockerGet @('volume','inspect',$vn)))
 if($v.Count -ne 1 -or [string]$v[0].Name -cne $vn){throw 'CLEAN6_VOLUME_MISSING'}
 $running=DockerGet @('ps','--filter',('volume='+$vn),'--format','{{.ID}}')
 if($running.Length -gt 0){throw 'CLEAN6_VOLUME_IN_USE'}
 $envs=@($c.Config.Env|Where-Object {$_ -match '^PGDATA='})
 if($envs.Count -ne 1){throw 'PGDATA_ENV_NOT_UNIQUE'}
 $pgdata=([string]$envs[0]).Substring(7)
 if($pgdata -notmatch '^/var/lib/postgresql/data(?:/[a-zA-Z0-9._/-]+)?$' -or $pgdata -match '(^|/)\.\.(/|$)'){throw 'PGDATA_OUT_OF_VOLUME'}
 $report.Add('[OK] CLEAN6_STOPPED_IMAGE_AND_VOLUME_PINNED')
 $stage='SHELL_PROBES'
 # Root filesystem is read-only; named volume is mounted read-write only to
 # make test -w meaningful, but the shell commands perform NO writes.
 $shell='set -eu; if [ -d "$PGDATA" ]; then echo PGDATA_KIND=DIR; if [ -w "$PGDATA" ]; then echo PGDATA_WRITABLE=YES; else echo PGDATA_WRITABLE=NO; fi; if [ -n "$(find "$PGDATA" -mindepth 1 -maxdepth 1 -print -quit)" ]; then echo PGDATA_EMPTY=NO; else echo PGDATA_EMPTY=YES; fi; elif [ -e "$PGDATA" ]; then echo PGDATA_KIND=NON_DIRECTORY; echo PGDATA_WRITABLE=NO; echo PGDATA_EMPTY=UNKNOWN; else echo PGDATA_KIND=MISSING; p="$(dirname "$PGDATA")"; if [ -d "$p" ] && [ -w "$p" ]; then echo PGDATA_PARENT_WRITABLE=YES; else echo PGDATA_PARENT_WRITABLE=NO; fi; echo PGDATA_EMPTY=NOT_CREATED; fi; if [ -f "$PGDATA/PG_VERSION" ]; then echo PG_VERSION_FILE=PRESENT; else echo PG_VERSION_FILE=ABSENT; fi; if command -v initdb >/dev/null 2>&1; then echo INITDB_IN_PATH=YES; else echo INITDB_IN_PATH=NO; fi; if command -v postgres >/dev/null 2>&1; then echo POSTGRES_IN_PATH=YES; else echo POSTGRES_IN_PATH=NO; fi'
 $argv=@('run','--rm','--pull','never','--network','none','--read-only',
  '--user','postgres','--cap-drop','ALL','--security-opt','no-new-privileges',
  '--pids-limit','64','--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data'),
  '--env',('PGDATA='+$pgdata),'--entrypoint','/bin/sh',$image,'-c',$shell)
 $result=DockerGet $argv
 $lines=@($result -split '[\r\n]+'|Where-Object {$_ -ne ''})
 $rules=@{
 'PGDATA_KIND'=@('DIR','NON_DIRECTORY','MISSING')
 'PGDATA_WRITABLE'=@('YES','NO')
 'PGDATA_PARENT_WRITABLE'=@('YES','NO')
 'PGDATA_EMPTY'=@('YES','NO','UNKNOWN','NOT_CREATED')
 'PG_VERSION_FILE'=@('PRESENT','ABSENT')
 'INITDB_IN_PATH'=@('YES','NO')
 'POSTGRES_IN_PATH'=@('YES','NO')
 }
 $seen=@{}
 foreach($line in $lines) {
  if($line -notmatch '^([A-Z_]+)=([A-Z_]+)$'){throw 'PROBE_OUTPUT_NOT_ALLOWLISTED'}
  $key=$Matches[1];$value=$Matches[2]
  if(-not $rules.ContainsKey($key) -or $value -notin $rules[$key] -or $seen.ContainsKey($key)){throw 'PROBE_OUTPUT_UNEXPECTED'}
  $seen[$key]=$value
  $report.Add($line)
 }
 foreach($must in @('PGDATA_KIND','PGDATA_EMPTY','PG_VERSION_FILE','INITDB_IN_PATH','POSTGRES_IN_PATH')) {
  if(-not $seen.ContainsKey($must)){throw 'PROBE_OUTPUT_MISSING'}
 }
 if($seen['PGDATA_KIND'] -eq 'DIR' -and -not $seen.ContainsKey('PGDATA_WRITABLE')){throw 'WRITABILITY_MISSING'}
 if($seen['PGDATA_KIND'] -eq 'MISSING' -and -not $seen.ContainsKey('PGDATA_PARENT_WRITABLE')){throw 'PARENT_WRITABILITY_MISSING'}
 $report.Add('[OK] CAUSE_COMPONENTS_SEPARATELY_REPORTED')
 $report.Add('[LIMITE] Shell read-only probes; no initdb, restore, or cleanup')
 $report.Add('[NEXT] FIX_ONLY_CONFIRMED_CAUSE_WITHOUT_DELETING_DATA')
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]{3,100}$'){$reason='LOCAL_ERROR_REDACTED'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
