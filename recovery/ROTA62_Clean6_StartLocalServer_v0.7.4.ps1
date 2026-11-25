# ROTA62 Guardian CLEAN6 v0.7.4 - start only isolated direct PostgreSQL 17 test server
# Start after verifying exact created-container identity & isolation.
# Executes SELECT-only local socket query; no restore, no DB modifications.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$server='rota62_guardian_clean6_direct_pg'
$clean='rota62_guardian_clean6_pg'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$volume='rota62_guardian_clean6_data'
$root='/var/lib/postgresql/data'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 LOCAL SERVER START v0.7.4 ===')
$r.Add('[MODO] START_ISOLATED_SERVER_LOCAL_SOCKET_SELECT_ONLY')
$stage='PRECHECK';$success=$false;$started=$false;$preverified=$false
function RunDocker([string[]]$argv) {
 $old=$ErrorActionPreference
 try{
  $ErrorActionPreference='Continue'
  $lines=@(& docker @argv 2>$null)
  $code=$LASTEXITCODE
 }catch{$lines=@();$code=-1}finally{$ErrorActionPreference=$old}
 return [pscustomobject]@{Code=$code;Text=(($lines -join [Environment]::NewLine).Trim())}
}
function DockerGet([string[]]$argv){
 $out=RunDocker $argv
 if($out.Code -ne 0){throw 'DOCKER_METADATA_FAILED'}
 return $out.Text
}
function InspectOne([string]$name){
 $items=@(ConvertFrom-Json -InputObject (DockerGet @('inspect',$name)))
 if($items.Count -ne 1){throw 'INSPECT_COUNT_INVALID'}
 return $items[0]
}
try{
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $stage='VERIFY_CONTAINER'
 $s=InspectOne $server
 $c=InspectOne $clean
 $ref=InspectOne $reference
 if([string]$s.Name -cne ('/'+$server)){throw 'SERVER_NAME_MISMATCH'}
 if([string]$s.State.Status -cne 'created' -or [bool]$s.State.Running){throw 'SERVER_MUST_BE_CREATED_AND_STOPPED'}
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_ORIGINAL_UNEXPECTED'}
 if([string]$ref.State.Status -cne 'running'){throw 'REFERENCE_NOT_RUNNING'}
 $image=[string]$c.Image
 if($image -cnotmatch '^sha256:[a-f0-9]{64}$' -or [string]$s.Image -cne $image -or [string]$ref.Image -cne $image){throw 'PINNED_IMAGE_MISMATCH'}
 if([string]$s.HostConfig.NetworkMode -cne 'none'){throw 'SERVER_NETWORK_NOT_NONE'}
 if([string]$s.HostConfig.RestartPolicy.Name -cne 'no'){throw 'SERVER_RESTART_UNEXPECTED'}
 if($s.HostConfig.PortBindings -and @($s.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'SERVER_HAS_PORTS'}
 if($s.NetworkSettings.Ports -and @($s.NetworkSettings.Ports.PSObject.Properties|Where-Object {$null -ne $_.Value}).Count -gt 0){throw 'SERVER_PUBLISHED_PORTS'}
 if([bool]$s.HostConfig.Privileged -or -not [bool]$s.HostConfig.ReadonlyRootfs){throw 'SERVER_PRIVILEGE_UNEXPECTED'}
 if(@($s.Mounts).Count -ne 1 -or [string]$s.Mounts[0].Name -cne $volume -or [string]$s.Mounts[0].Destination -cne $root){throw 'SERVER_VOLUME_MISMATCH'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $volume){throw 'CLEAN6_VOLUME_MISMATCH'}
 if([string]$s.Config.User -cne 'postgres'){throw 'SERVER_USER_NOT_POSTGRES'}
 if([string]$s.HostConfig.SecurityOpt[0] -cne 'no-new-privileges'){throw 'SERVER_SECURITY_OPTION_UNEXPECTED'}
 if(@($s.Config.Entrypoint).Count -ne 1){throw 'SERVER_ENTRYPOINT_CARDINALITY'}
 $bin=[string]$s.Config.Entrypoint[0]
 if($bin -cnotmatch '^/[a-zA-Z0-9_./-]{5,200}$' -or $bin -match '(^|/)\.\.(/|$)' -or $bin -match 'docker-entrypoint|/sh$'){throw 'SERVER_ENTRYPOINT_UNSAFE'}
 $expected=@('-D',$root,'-c','listen_addresses=','-c','unix_socket_directories=/tmp','-c','shared_preload_libraries=','-c','max_worker_processes=0')
 if((@($s.Config.Cmd) -join '|') -cne ($expected -join '|')){throw 'SERVER_COMMAND_MISMATCH'}
 $vol=@(ConvertFrom-Json -InputObject (DockerGet @('volume','inspect',$volume)))
 if($vol.Count -ne 1 -or [string]$vol[0].Name -cne $volume){throw 'VOLUME_IDENTITY_INVALID'}
 $using= DockerGet @('ps','--filter',('volume='+$volume),'--format','{{.ID}}')
 if($using.Length -gt 0){throw 'VOLUME_HAS_RUNNING_CONSUMER'}
 $preverified=$true
 $r.Add('[OK] SERVER_IDENTITY_IMAGE_NETWORK_SECURITY_COMMAND_VALIDATED')
 $stage='START'
 $res=RunDocker @('start',$server)
 if($res.Code -ne 0 -or $res.Text -cne $server){throw 'DOCKER_START_FAILED_CHECK_STATE'}
 $started=$true
 $r.Add('[OK] DIRECT_SERVER_START_COMMAND_ACCEPTED')
 $stage='READINESS'
 # Local UNIX socket only, no password. Test server settings + PG17 in SELECT only.
 $sql="SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses') = '' AND current_setting('shared_preload_libraries') = '' AND current_setting('max_worker_processes') = '0' AND current_setting('unix_socket_directories') = '/tmp' THEN 'R62_PG17_LOCAL_ISOLATED_OK' ELSE 'R62_SERVER_SETTINGS_MISMATCH' END"
 $connected=$false
 for($i=0;$i -lt 8;$i++){
  $check=RunDocker @('exec','--user','postgres',$server,'psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-h','/tmp','-U','postgres','-d','postgres','-c',$sql)
  if($check.Code -eq 0 -and $check.Text -ceq 'R62_PG17_LOCAL_ISOLATED_OK'){$connected=$true;break}
  if($check.Code -eq 0 -and $check.Text -ceq 'R62_SERVER_SETTINGS_MISMATCH'){throw 'SERVER_RUNTIME_SETTINGS_MISMATCH'}
  if($i -lt 7){Start-Sleep -Seconds 2}
 }
 if(-not $connected){throw 'SERVER_NOT_READY_LOCAL_SOCKET_OR_PSQL_FAILED'}
 $r.Add('[OK] LOCAL_UNIX_SOCKET_POSTGRES_SELECT_SUCCEEDED')
 $r.Add('[OK] POSTGRESQL_17_TCP_DISABLED_PRELOAD_EMPTY_BG_WORKERS_ZERO')
 $stage='POSTCHECK'
 $after=InspectOne $server
 if(-not [bool]$after.State.Running -or [string]$after.State.Status -cne 'running'){throw 'SERVER_NOT_RUNNING_AFTER_QUERY'}
 if([string]$after.HostConfig.NetworkMode -cne 'none'){throw 'NETWORK_CHANGED_AFTER_START'}
 if([string]$after.Config.User -cne 'postgres'){throw 'SERVER_USER_CHANGED'}
 $orig=InspectOne $clean
 if([bool]$orig.State.Running -or [string]$orig.State.Status -cne 'created'){throw 'ORIGINAL_CLEAN6_STATE_CHANGED'}
 $r.Add('[OK] DIRECT_SERVER_RUNNING_ONLY_NEW_TEST_CONTAINER')
 $r.Add('[OK] ORIGINAL_CLEAN6_CONTAINER_REMAINS_STOPPED')
 $r.Add('[LIMITE] No backup restoration attempted; database currently empty')
 $r.Add('[NEXT] STAGE_DECRYPTED_PGDMP_AND_RESTORE_TO_ISOLATED_TEST_DB')
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]{3,100}$'){$reason='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
 if(-not $success -and $preverified -and $stage -in @('START','READINESS','POSTCHECK')){
  # Only stop the exact, previously verified new container if Docker reports it running.
  try{
   $current=InspectOne $server
   if([string]$current.Name -ceq ('/'+$server) -and [bool]$current.State.Running -and [string]$current.HostConfig.NetworkMode -ceq 'none' -and [string]$current.Image -ceq $image){
    $stop=RunDocker @('stop','--time','10',$server)
    if($stop.Code -eq 0){$r.Add('[OK] FAILED_VALIDATION_DIRECT_SERVER_STOPPED')}
    else{$r.Add('[AVISO] DIRECT_SERVER_STOP_FAILED_MANUAL_INSPECTION_REQUIRED')}
   }
  }catch{$r.Add('[AVISO] SERVER_STATE_UNVERIFIED_MANUAL_INSPECTION_REQUIRED')}
 }
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
