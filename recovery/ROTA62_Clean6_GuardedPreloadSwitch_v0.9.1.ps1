# ROTA62 CLEAN6 v0.9.1 - guarded single-server switchover to preload-compatible image
# Does not restore backup, install extensions, or touch legacy labs.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$old='rota62_guardian_clean6_direct_pg'
$new='rota62_guardian_clean6_restore_pg'
$original='rota62_guardian_clean6_pg'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$volume='rota62_guardian_clean6_data'
$root='/var/lib/postgresql/data'
$db='rota62_clean6_restore_v1'
$stage='PRECHECK';$success=$false;$oldStopped=$false;$newStartAttempted=$false;$isolationConfirmed=$false
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 GUARDED SERVER SWITCH v0.9.1 ===')
$r.Add('[MODO] STOP_OLD_START_PRELOAD_VERIFY_WITH_ROLLBACK_NO_RESTORE')
function D([string[]]$argslist){
 $prev=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$lines=@(& docker @argslist 2>$null);$rc=$LASTEXITCODE}
 catch{$lines=@();$rc=-1}finally{$ErrorActionPreference=$prev}
 return [pscustomobject]@{Code=$rc;Text=(($lines -join [Environment]::NewLine).Trim())}
}
function Need([string[]]$argslist,[string]$errorName){
 $res=D $argslist
 if($res.Code -ne 0){throw $errorName}
 return $res.Text
}
function Inspect([string]$name){
 $raw=Need @('inspect',$name) 'DOCKER_INSPECT_FAILED'
 $arr=@(ConvertFrom-Json -InputObject $raw)
 if($arr.Count -ne 1){throw 'DOCKER_INSPECT_CARDINALITY'}
 return $arr[0]
}
function Query([string]$server,[string]$database,[string]$sql){
 return D @('exec','--user','postgres',$server,'psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1',
 '-h','/tmp','-U','postgres','-d',$database,'-c',$sql)
}
function RunningConsumers(){
 return Need @('ps','--filter',('volume='+$volume),'--format','{{.Names}}') 'RUNNING_VOLUME_CONSUMERS_UNKNOWN'
}
function VerifyBase([object]$s,[string]$expectedName,[string]$image,[string[]]$command,[string]$entry){
 if([string]$s.Name -cne ('/'+$expectedName)){throw 'CONTAINER_NAME_MISMATCH'}
 if([string]$s.Image -cne $image){throw 'CONTAINER_IMAGE_CHANGED'}
 if([string]$s.HostConfig.NetworkMode -cne 'none' -or [string]$s.HostConfig.RestartPolicy.Name -cne 'no'){throw 'NETWORK_RESTART_UNSAFE'}
 if([string]$s.Config.User -cne 'postgres' -or [bool]$s.HostConfig.Privileged -or -not [bool]$s.HostConfig.ReadonlyRootfs){throw 'CONTAINER_PRIVILEGE_UNSAFE'}
 if($s.HostConfig.SecurityOpt -notcontains 'no-new-privileges'){throw 'NO_NEW_PRIVILEGES_MISSING'}
 if($s.HostConfig.CapDrop -notcontains 'ALL'){throw 'CAP_DROP_ALL_MISSING'}
 if(@($s.Mounts).Count -ne 1 -or [string]$s.Mounts[0].Type -cne 'volume' -or [string]$s.Mounts[0].Name -cne $volume -or [string]$s.Mounts[0].Destination -cne $root){throw 'VOLUME_MOUNT_UNEXPECTED'}
 if($s.HostConfig.PortBindings -and @($s.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'PORT_BINDINGS_UNSAFE'}
 if((@($s.Config.Entrypoint) -join '|') -cne $entry){throw 'ENTRYPOINT_UNEXPECTED'}
 if((@($s.Config.Cmd) -join '|') -cne ($command -join '|')){throw 'COMMAND_UNEXPECTED'}
}
try{
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $stage='CONTAINER_PRECHECK'
 $current=Inspect $old;$future=Inspect $new;$clean=Inspect $original;$ref=Inspect $reference
 if(-not [bool]$current.State.Running -or [string]$current.State.Status -cne 'running'){throw 'OLD_SERVER_MUST_BE_RUNNING'}
 if([bool]$future.State.Running -or [string]$future.State.Status -cne 'created'){throw 'NEW_SERVER_MUST_BE_CREATED_AND_STOPPED'}
 if([bool]$clean.State.Running -or [string]$clean.State.Status -cne 'created'){throw 'ORIGINAL_CLEAN6_STATE_UNEXPECTED'}
 if(-not [bool]$ref.State.Running){throw 'REFERENCE_SERVER_NOT_RUNNING'}
 $image=[string]$current.Image
 if($image -cnotmatch '^sha256:[a-f0-9]{64}$' -or [string]$future.Image -cne $image -or [string]$clean.Image -cne $image -or [string]$ref.Image -cne $image){throw 'PINNED_IMAGE_MISMATCH'}
 $oldEntry=[string]@($current.Config.Entrypoint)[0]
 if($oldEntry -cnotmatch '^/[a-zA-Z0-9_./-]{5,200}$' -or $oldEntry -match '(^|/)\.\.(/|$)|docker-entrypoint|/sh$'){throw 'SERVER_POSTGRES_BINARY_UNSAFE'}
 $oldCmd=@('-D',$root,'-c','listen_addresses=','-c','unix_socket_directories=/tmp','-c','shared_preload_libraries=','-c','max_worker_processes=0')
 $newCmd=@('-D',$root,'-c','listen_addresses=','-c','unix_socket_directories=/tmp','-c','shared_preload_libraries=pg_cron,pg_net,pg_stat_statements','-c','max_worker_processes=4','-c','cron.database_name=rota62_clean6_restore_v1','-c','cron.launch_active_jobs=off')
 VerifyBase $current $old $image $oldCmd $oldEntry
 VerifyBase $future $new $image $newCmd $oldEntry
 if((RunningConsumers) -cne $old){throw 'VOLUME_NOT_EXCLUSIVELY_OWNED_BY_OLD'}
 $isolationConfirmed=$true
 $r.Add('[OK] OLD_AND_NEW_IDENTITY_IMAGE_COMMAND_ISOLATION_VERIFIED')
 $stage='SQL_PRECHECK'
 $sql="SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses')='' AND current_setting('unix_socket_directories')='/tmp' AND current_setting('shared_preload_libraries')='' AND current_setting('max_worker_processes')='0' THEN 'R62_OK' ELSE 'R62_BAD' END"
 $check=Query $old 'postgres' $sql
 if($check.Code -ne 0 -or $check.Text -cne 'R62_OK'){throw 'OLD_SERVER_RUNTIME_UNEXPECTED'}
 $dbCheck=Query $old 'postgres' "SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_database WHERE datname='rota62_clean6_restore_v1') THEN 'R62_EXISTS' ELSE 'R62_MISSING' END"
 if($dbCheck.Code -ne 0 -or $dbCheck.Text -cne 'R62_EXISTS'){throw 'TEST_DATABASE_MISSING'}
 $dbObjects=Query $old $db "SELECT CASE WHEN (SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql')=0 AND (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S'))=0 THEN 'R62_EMPTY' ELSE 'R62_NOT_EMPTY' END"
 if($dbObjects.Code -ne 0 -or $dbObjects.Text -cne 'R62_EMPTY'){throw 'TEST_DATABASE_NOT_EMPTY'}
 $r.Add('[OK] CURRENT_PG17_RUNTIME_AND_TARGET_EMPTY_VERIFIED')
 $stage='STOP_OLD'
 $stop=D @('stop','--time','20',$old)
 # Docker CLI stdout/stderr/exit may be unreliable under PowerShell 5.1.
 # Verify the persisted engine state, not the printed container name.
 $oldStopped=$true
 $state=Inspect $old
 if([bool]$state.State.Running -or [string]$state.State.Status -cne 'exited'){throw 'OLD_NOT_FULLY_STOPPED_CHECK_STATE'}
 if((RunningConsumers).Length -ne 0){throw 'VOLUME_STILL_HAS_RUNNING_CONSUMER'}
 $r.Add('[OK] OLD_SERVER_FULLY_STOPPED_VOLUME_FREE')
 if($stop.Code -ne 0 -or $stop.Text -cne $old){$r.Add('[INFO] DOCKER_STOP_OUTPUT_NONCANONICAL_ENGINE_STATE_VERIFIED')}
 $stage='START_NEW'
 $newStartAttempted=$true
 $start=D @('start',$new)
 $newState=Inspect $new
 if(-not [bool]$newState.State.Running -or [string]$newState.State.Status -cne 'running'){throw 'NEW_DOCKER_START_NOT_RUNNING_CHECK_STATE'}
 if((RunningConsumers) -cne $new){throw 'NEW_DOCKER_START_VOLUME_CONSUMER_MISMATCH'}
 $r.Add('[OK] PRELOAD_SERVER_START_ENGINE_STATE_CONFIRMED')
 if($start.Code -ne 0 -or $start.Text -cne $new){$r.Add('[INFO] DOCKER_START_OUTPUT_NONCANONICAL_ENGINE_STATE_VERIFIED')}
 $stage='VERIFY_RUNTIME'
 $sql2="SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses')='' AND current_setting('unix_socket_directories')='/tmp' AND replace(current_setting('shared_preload_libraries'),' ','')='pg_cron,pg_net,pg_stat_statements' AND current_setting('max_worker_processes')='4' AND current_setting('cron.database_name')='rota62_clean6_restore_v1' AND current_setting('cron.launch_active_jobs')='off' THEN 'R62_PRELOAD_OK' ELSE 'R62_PRELOAD_BAD' END"
 $ready=$false
 for($i=0;$i -lt 10;$i++){
  $q=Query $new 'postgres' $sql2
  if($q.Code -eq 0 -and $q.Text -ceq 'R62_PRELOAD_OK'){$ready=$true;break}
  if($q.Code -eq 0 -and $q.Text -ceq 'R62_PRELOAD_BAD'){throw 'PRELOAD_RUNTIME_SETTINGS_INVALID'}
  if($i -lt 9){Start-Sleep -Seconds 2}
 }
 if(-not $ready){throw 'PRELOAD_SERVER_NOT_READY'}
 $r.Add('[OK] PG17_LOCAL_SOCKET_PRELOADS_ACTIVE_CRON_JOBS_DISABLED')
 $stage='FINAL_CHECK'
 $ns=Inspect $new;$os=Inspect $old
 if(-not [bool]$ns.State.Running -or [bool]$os.State.Running){throw 'RUNNING_SERVER_CARDINALITY_UNEXPECTED'}
 if((RunningConsumers) -cne $new){throw 'RUNNING_VOLUME_CONSUMER_UNEXPECTED'}
 $target=Query $new $db "SELECT CASE WHEN (SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql')=0 THEN 'R62_NOT_INSTALLED' ELSE 'R62_EXTENSIONS_PRESENT' END"
 if($target.Code -ne 0 -or $target.Text -cne 'R62_NOT_INSTALLED'){throw 'EXTENSIONS_PREINSTALLED_UNEXPECTED'}
 $r.Add('[OK] ONLY_NEW_PRELOAD_SERVER_RUNNING_ON_CLEAN6_VOLUME')
 $r.Add('[OK] NO_EXTENSION_INSTALLATION_NO_BACKUP_RESTORE')
 $r.Add('[APROVADO] CLEAN6_PRELOAD_SERVER_RUNNING_ISOLATED')
 $r.Add('[NEXT] CONTROLLED_EXTENSION_AND_SCHEMA_RESTORE_PLAN')
 $success=$true
}catch{
 $why=[string]$_.Exception.Message
 if($why -cnotmatch '^[A-Z0-9_]{3,100}$'){$why='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$why)
}finally{
 if(-not $success -and $isolationConfirmed -and $stage -in @('STOP_OLD','START_NEW','VERIFY_RUNTIME','FINAL_CHECK')){
  # Stop new if running; never start the old DB if any other container still uses volume.
  try{
   $n=Inspect $new
   if([bool]$n.State.Running -and [string]$n.Name -ceq ('/'+$new) -and [string]$n.Image -ceq $image){
    $stopNew=D @('stop','--time','20',$new)
    $afterStopNew=Inspect $new
    if(-not [bool]$afterStopNew.State.Running -and [string]$afterStopNew.State.Status -ceq 'exited'){$r.Add('[OK] ROLLBACK_NEW_SERVER_STOPPED')}
    else{$r.Add('[AVISO] ROLLBACK_NEW_STOP_FAILED_MANUAL_CHECK_REQUIRED')}
   }
   $currentUse=RunningConsumers
   $o=Inspect $old
   if(-not [bool]$o.State.Running -and $currentUse.Length -eq 0 -and [string]$o.Image -ceq $image){
    $back=D @('start',$old)
    $oldAfterRestart=Inspect $old
    if([bool]$oldAfterRestart.State.Running -and (RunningConsumers) -ceq $old){
     $r.Add('[OK] ROLLBACK_OLD_SERVER_RUNNING_EXCLUSIVELY')
     $probe=Query $old 'postgres' "SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses')='' THEN 'R62_PG17_READY' ELSE 'R62_NOT_READY' END"
     if($probe.Code -eq 0 -and $probe.Text -ceq 'R62_PG17_READY'){$r.Add('[OK] ROLLBACK_OLD_POSTGRES_RESPONDS')}
     else{$r.Add('[AVISO] ROLLBACK_OLD_POSTGRES_NOT_READY_INSPECT_FIRST')}
    }else{$r.Add('[AVISO] ROLLBACK_OLD_SERVER_START_FAILED_MANUAL_CHECK_REQUIRED')}
   }elseif([bool]$o.State.Running){$r.Add('[OK] OLD_SERVER_REMAINS_RUNNING')}
   else{$r.Add('[AVISO] OLD_SERVER_NOT_RESTARTED_VOLUME_OR_STATE_UNSAFE')}
  }catch{$r.Add('[AVISO] ROLLBACK_STATE_UNKNOWN_DO_NOT_RETRY_MANUALLY')}
 }
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
