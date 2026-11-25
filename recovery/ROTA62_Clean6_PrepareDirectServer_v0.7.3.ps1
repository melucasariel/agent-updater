# ROTA62 Guardian CLEAN6 v0.7.3 - prepare stopped explicit PG17 server
# Creates ONLY a NEW stopped local server container using disposable CLEAN6 initialized volume.
# Never starts postgres, executes SQL, decrypts backup, or touches previous labs/production.
# No Supabase entrypoint or init scripts. Network none; no ports; shared_preload_libraries empty.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$clean='rota62_guardian_clean6_pg'
$server='rota62_guardian_clean6_direct_pg'
$volume='rota62_guardian_clean6_data'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 PREPARE DIRECT SERVER v0.7.3 ===')
$r.Add('[MODO] CREATE_STOPPED_ONLY_NO_SERVER_START_NO_RESTORE')
$stage='PRECHECK';$success=$false
function DockerGet([string[]]$a){
 $old=$ErrorActionPreference
 try{
  $ErrorActionPreference='Continue'
  $output=@(& docker @a 2>$null)
  $exit=$LASTEXITCODE
 }catch{throw 'DOCKER_QUERY_EXCEPTION'}finally{$ErrorActionPreference=$old}
 if($exit -ne 0){throw 'DOCKER_QUERY_FAILED'}
 return (($output -join [Environment]::NewLine).Trim())
}
function DockerProbe([string[]]$a){
 $old=$ErrorActionPreference
 try{
  $ErrorActionPreference='Continue'
  $output=@(& docker @a 2>$null)
  $exit=$LASTEXITCODE
 }catch{$output=@();$exit=-1}finally{$ErrorActionPreference=$old}
 return [pscustomobject]@{Exit=$exit;Value=(($output -join [Environment]::NewLine).Trim())}
}
function ReadOne([string]$name) {
 $items=@(ConvertFrom-Json -InputObject (DockerGet @('inspect',$name)))
 if($items.Count -ne 1){throw 'INSPECT_COUNT_INVALID'}
 return $items[0]
}
try{
 $stage='IDENTITY'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_NOT_FOUND'}
 $c=ReadOne $clean
 $ref=ReadOne $reference
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_NOT_CREATED_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_UNEXPECTED'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $volume -or [string]$c.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'CLEAN6_VOLUME_MISMATCH'}
 if([string]$ref.State.Status -cne 'running' -or [string]$ref.Image -cne [string]$c.Image){throw 'REFERENCE_MISMATCH'}
 $image=[string]$c.Image
 if($image -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'IMAGE_ID_INVALID'}
 $vol=@(ConvertFrom-Json -InputObject (DockerGet @('volume','inspect',$volume)))
 if($vol.Count -ne 1 -or [string]$vol[0].Name -cne $volume){throw 'VOLUME_MISSING'}
 if((DockerGet @('ps','--filter',('volume='+$volume),'--format','{{.ID}}')).Length -gt 0){throw 'VOLUME_IN_USE_BY_RUNNING_CONTAINER'}
 $pgdata=@($c.Config.Env|Where-Object {$_ -ceq 'PGDATA=/var/lib/postgresql/data'})
 if($pgdata.Count -ne 1){throw 'PGDATA_UNEXPECTED'}
 $r.Add('[OK] CLEAN6_DATA_VOLUME_INITIALIZED_ISOLATED_REFERENCE_PINNED')
 $stage='NO_NAME_COLLISION'
 $already=DockerProbe @('container','inspect',$server)
 if($already.Exit -eq 0){throw 'DIRECT_SERVER_CONTAINER_ALREADY_EXISTS'}
 $r.Add('[OK] DIRECT_SERVER_NAME_AVAILABLE')
 $stage='DATA_SAFETY'
 $root='/var/lib/postgresql/data'
 $common=@('run','--rm','--pull','never','--network','none','--read-only',
  '--user','postgres','--cap-drop','ALL','--security-opt','no-new-privileges',
  '--pids-limit','64')
 $ro=@('--mount',('type=volume,source='+$volume+',target='+$root+',readonly'))
 # Use the proven v0.7.0 /bin/sh -c grep check (no assumed grep binary path).
 $version=DockerProbe ($common+$ro+@('--entrypoint','/bin/sh',$image,'-c','grep -qx 17 /var/lib/postgresql/data/PG_VERSION'))
 if($version.Exit -ne 0){throw 'PG17_INITIALIZED_DATA_NOT_VERIFIED'}
 $control=DockerProbe ($common+$ro+@('--entrypoint','/bin/sh',$image,'-c','test -f /var/lib/postgresql/data/global/pg_control'))
 if($control.Exit -ne 0){throw 'PG_CONTROL_MISSING'}
 $r.Add('[OK] INITIALIZED_PG17_DATA_FILES_PRESENT')
 $stage='POSTGRES_BINARY'
 $path=DockerProbe ($common+@('--entrypoint','/bin/sh',$image,'-c','command -v postgres'))
 if($path.Exit -ne 0 -or $path.Value -cnotmatch '^/[a-zA-Z0-9_./-]{5,200}$' -or $path.Value -match '(^|/)\.\.(/|$)'){throw 'POSTGRES_PATH_NOT_VERIFIED'}
 $executable=DockerProbe ($common+@('--entrypoint','/bin/sh',$image,'-c',('test -x '+$path.Value)))
 if($executable.Exit -ne 0){throw 'POSTGRES_BINARY_NOT_EXECUTABLE'}
 $r.Add('[OK] PINNED_IMAGE_POSTGRES_BINARY_VERIFIED')
 $stage='CREATE_STOPPED'
 # Absolute executable entrypoint bypasses all Supabase init hooks.
 # Empty listen_addresses disables TCP. Empty shared_preload_libraries avoids pg_cron and pg_net.
 # max_worker_processes=0 blocks extension background workers during initial recovery.
 # /tmp isolated tmpfs supports local UNIX socket; image root stays read-only.
 $create=@('create','--name',$server,'--pull','never','--network','none','--restart','no',
  '--user','postgres','--read-only',
  '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128',
  '--tmpfs','/tmp:rw,nosuid,nodev,size=16777216,mode=1777',
  '--mount',('type=volume,source='+$volume+',target='+$root),
  '--entrypoint',$path.Value,$image,
  '-D',$root,
  '-c','listen_addresses=',
  '-c','unix_socket_directories=/tmp',
  '-c','shared_preload_libraries=',
  '-c','max_worker_processes=0')
 $result=DockerProbe $create
 if($result.Exit -ne 0 -or $result.Value -cnotmatch '^[a-f0-9]{64}$'){throw 'DIRECT_SERVER_CREATE_FAILED_RECHECK_NAME'}
 $r.Add('[OK] DIRECT_SERVER_CREATED_NOT_STARTED')
 $stage='VERIFY_CREATED'
 $s=ReadOne $server
 if([string]$s.State.Status -cne 'created' -or [bool]$s.State.Running){throw 'DIRECT_SERVER_STATE_UNEXPECTED'}
 if([string]$s.HostConfig.NetworkMode -cne 'none'){throw 'DIRECT_SERVER_NETWORK_MISMATCH'}
 if([string]$s.HostConfig.RestartPolicy.Name -cne 'no'){throw 'DIRECT_SERVER_RESTART_POLICY_UNEXPECTED'}
 if($s.HostConfig.PortBindings -and @($s.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'DIRECT_SERVER_PORTS_UNEXPECTED'}
 if([string]$s.Image -cne $image){throw 'DIRECT_SERVER_IMAGE_MISMATCH'}
 if(@($s.Mounts).Count -ne 1 -or [string]$s.Mounts[0].Name -cne $volume){throw 'DIRECT_SERVER_VOLUME_MISMATCH'}
 if(@($s.Config.Entrypoint).Count -ne 1 -or [string]$s.Config.Entrypoint[0] -cne $path.Value){throw 'DIRECT_SERVER_ENTRYPOINT_MISMATCH'}
 $commandParts=@($s.Config.Cmd)
 if(($commandParts -join '|') -cne ((@('-D',$root,'-c','listen_addresses=','-c','unix_socket_directories=/tmp','-c','shared_preload_libraries=','-c','max_worker_processes=0')) -join '|')){throw 'DIRECT_SERVER_COMMAND_MISMATCH'}
 if($s.HostConfig.Privileged -eq $true -or $s.HostConfig.ReadonlyRootfs -ne $true){throw 'DIRECT_SERVER_PRIVILEGE_MISMATCH'}
 $r.Add('[OK] DIRECT_SERVER_SECURITY_AND_EXPLICIT_COMMAND_VERIFIED')
 $r.Add('[OK] CLEAN6_ORIGINAL_CONTAINER_NOT_STARTED')
 $r.Add('[LIMITE] PostgreSQL server not started; restore not yet attempted')
 $r.Add('[NEXT] START_DIRECT_SERVER_AND_VALIDATE_LOCAL_SOCKET_ONLY')
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]{3,100}$'){$reason='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
 if($stage -in @('CREATE_STOPPED','VERIFY_CREATED')){$r.Add('[AVISO] DIRECT_SERVER_CONTAINER_MAY_EXIST_DO_NOT_RERUN_OR_DELETE')}
}finally{
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
