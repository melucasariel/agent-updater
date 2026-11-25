# ROTA62 CLEAN6 v0.8.6 - prepare stopped preload-aware restore server (no start/stop)
# Safe separate container, same volume; only one server ever starts at a time.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$existing='rota62_guardian_clean6_direct_pg'
$new='rota62_guardian_clean6_restore_pg'
$clean='rota62_guardian_clean6_pg'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$volume='rota62_guardian_clean6_data'
$root='/var/lib/postgresql/data'
$database='rota62_clean6_restore_v1'
$stage='PRECHECK';$ok=$false;$created=$false
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 PREPARE PRELOAD RESTORE SERVER v0.8.6 ===')
$r.Add('[MODO] CREATE_STOPPED_ONLY_DO_NOT_STOP_RUNNING_DB_NO_RESTORE')
function D([string[]]$a){
 $old=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$o=@(& docker @a 2>$null);$rc=$LASTEXITCODE}
 catch{$o=@();$rc=-1}finally{$ErrorActionPreference=$old}
 return [pscustomobject]@{Code=$rc;Value=(($o -join [Environment]::NewLine).Trim())}
}
function Must([string[]]$a,[string]$fail){
 $x=D $a;if($x.Code -ne 0){throw $fail};return $x.Value
}
function Inspect([string]$name){
 $raw=Must @('inspect',$name) 'INSPECT_FAILED'
 $arr=@(ConvertFrom-Json -InputObject $raw)
 if($arr.Count -ne 1){throw 'INSPECT_COUNT_UNEXPECTED'}
 return $arr[0]
}
function Sql([string]$db,[string]$q){
 return Must @('exec','--user','postgres',$existing,
 'psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-h','/tmp','-U','postgres','-d',$db,'-c',$q) 'PG_QUERY_FAILED'
}
try{
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $stage='CURRENT_STATES'
 $e=Inspect $existing;$c=Inspect $clean;$p=Inspect $reference
 if([string]$e.Name -cne ('/'+$existing) -or -not [bool]$e.State.Running){throw 'CURRENT_DIRECT_SERVER_NOT_RUNNING'}
 if([string]$c.Name -cne ('/'+$clean) -or [bool]$c.State.Running -or [string]$c.State.Status -cne 'created'){throw 'ORIGINAL_CLEAN6_STATE_UNEXPECTED'}
 if([string]$p.Name -cne ('/'+$reference) -or -not [bool]$p.State.Running){throw 'REFERENCE_CONTAINER_STATE_UNEXPECTED'}
 if([string]$e.Image -cnotmatch '^sha256:[a-f0-9]{64}$' -or [string]$e.Image -cne [string]$c.Image -or [string]$e.Image -cne [string]$p.Image){throw 'PINNED_IMAGE_MISMATCH'}
 $image=[string]$e.Image
 if([string]$e.HostConfig.NetworkMode -cne 'none' -or [string]$e.HostConfig.RestartPolicy.Name -cne 'no'){throw 'CURRENT_SERVER_NETWORK_UNSAFE'}
 if([bool]$e.HostConfig.Privileged -or -not [bool]$e.HostConfig.ReadonlyRootfs -or [string]$e.Config.User -cne 'postgres'){throw 'CURRENT_SERVER_PRIVILEGE_UNSAFE'}
 if(@($e.Mounts).Count -ne 1 -or [string]$e.Mounts[0].Name -cne $volume -or [string]$e.Mounts[0].Destination -cne $root){throw 'CURRENT_SERVER_VOLUME_UNEXPECTED'}
 if($e.HostConfig.SecurityOpt -notcontains 'no-new-privileges'){throw 'CURRENT_SERVER_SECURITY_OPT_MISSING'}
 if($e.HostConfig.PortBindings -and @($e.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CURRENT_SERVER_PORTS_UNSAFE'}
 $users=Must @('ps','--filter',('volume='+$volume),'--format','{{.Names}}') 'VOLUME_CONSUMERS_QUERY_FAILED'
 if($users -cne $existing){throw 'OTHER_RUNNING_VOLUME_CONSUMER_DETECTED'}
 $r.Add('[OK] CURRENT_DIRECT_PG17_EXCLUSIVE_RUNNING_VOLUME_ISOLATED')
 $stage='DATABASE'
 $q="SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses')='' AND current_setting('shared_preload_libraries')='' AND current_setting('max_worker_processes')='0' AND current_setting('unix_socket_directories')='/tmp' THEN 'R62_OK' ELSE 'R62_BAD' END"
 if((Sql 'postgres' $q) -cne 'R62_OK'){throw 'CURRENT_PG17_RUNTIME_MISMATCH'}
 $qdb="SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_database WHERE datname='rota62_clean6_restore_v1' AND pg_get_userbyid(datdba)='postgres') THEN 'EXISTS' ELSE 'ABSENT' END"
 if((Sql 'postgres' $qdb) -cne 'EXISTS'){throw 'RESTORE_TEST_DATABASE_MISSING'}
 $qext="SELECT count(*)::text FROM pg_extension WHERE extname<>'plpgsql'"
 if((Sql $database $qext) -cne '0'){throw 'RESTORE_TARGET_EXTENSIONS_NOT_EMPTY'}
 $r.Add('[OK] EMPTY_RESTORE_DB_AND_SAFE_CURRENT_POSTGRESQL_SETTINGS')
 $stage='NEW_NAME'
 $qnew=D @('container','inspect',$new)
 if($qnew.Code -eq 0){throw 'NEW_CONTAINER_ALREADY_EXISTS_DO_NOT_REPEAT'}
 $bin=@($e.Config.Entrypoint)
 if($bin.Count -ne 1){throw 'CURRENT_ENTRYPOINT_UNEXPECTED'}
 $entry=[string]$bin[0]
 if($entry -cnotmatch '^/[A-Za-z0-9_./-]{5,200}$' -or $entry -match '(^|/)\.\.(/|$)' -or $entry -match 'docker-entrypoint|/sh$'){throw 'POSTGRES_EXECUTABLE_UNSAFE'}
 $expect=@('-D',$root,'-c','listen_addresses=','-c','unix_socket_directories=/tmp','-c','shared_preload_libraries=','-c','max_worker_processes=0')
 if((@($e.Config.Cmd) -join '|') -cne ($expect -join '|')){throw 'DIRECT_COMMAND_NOT_BASELINE'}
 $r.Add('[OK] NEW_CONTAINER_NAME_AVAILABLE_BINARY_PINNED')
 $stage='CREATE_STOPPED'
 $cmd=@('-D',$root,
 '-c','listen_addresses=',
 '-c','unix_socket_directories=/tmp',
 '-c','shared_preload_libraries=pg_cron,pg_net,pg_stat_statements',
 '-c','max_worker_processes=4',
 '-c','cron.database_name=rota62_clean6_restore_v1',
 '-c','cron.launch_active_jobs=off')
 $argslist=@('create','--name',$new,'--pull','never',
 '--network','none','--restart','no','--user','postgres','--read-only',
 '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128',
 '--tmpfs','/tmp:rw,nosuid,nodev,size=16777216,mode=1777',
 '--mount',('type=volume,source='+$volume+',target='+$root),
 '--entrypoint',$entry,$image)+$cmd
 $a=D $argslist
 if($a.Code -ne 0){throw 'DOCKER_CREATE_FAILED_CHECK_STATE'}
 $created=$true
 $r.Add('[OK] PRELOAD_RESTORE_CONTAINER_CREATED_STOPPED')
 $stage='VERIFY_NEW'
 $n=Inspect $new
 if([string]$n.Name -cne ('/'+$new) -or [string]$n.State.Status -cne 'created' -or [bool]$n.State.Running){throw 'NEW_CONTAINER_NOT_STOPPED'}
 if([string]$n.Image -cne $image -or [string]$n.HostConfig.NetworkMode -cne 'none' -or [string]$n.HostConfig.RestartPolicy.Name -cne 'no'){throw 'NEW_CONTAINER_ISOLATION_FAILED'}
 if([string]$n.Config.User -cne 'postgres' -or -not [bool]$n.HostConfig.ReadonlyRootfs -or [bool]$n.HostConfig.Privileged){throw 'NEW_CONTAINER_PRIVILEGE_FAILED'}
 if($n.HostConfig.SecurityOpt -notcontains 'no-new-privileges'){throw 'NEW_CONTAINER_SECURITY_OPT_FAILED'}
 if($n.HostConfig.PortBindings -and @($n.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'NEW_CONTAINER_PORTS_UNSAFE'}
 if(@($n.Mounts).Count -ne 1 -or [string]$n.Mounts[0].Name -cne $volume -or [string]$n.Mounts[0].Destination -cne $root){throw 'NEW_CONTAINER_VOLUME_MISMATCH'}
 if((@($n.Config.Entrypoint) -join '|') -cne $entry){throw 'NEW_CONTAINER_ENTRYPOINT_MISMATCH'}
 if((@($n.Config.Cmd) -join '|') -cne ($cmd -join '|')){throw 'NEW_CONTAINER_OPTIONS_MISMATCH'}
 $now=Inspect $existing
 if(-not [bool]$now.State.Running){throw 'CURRENT_DIRECT_SERVER_WAS_STOPPED'}
 if((Must @('ps','--filter',('volume='+$volume),'--format','{{.Names}}') 'VOLUME_RECHECK_FAILED') -cne $existing){throw 'NEW_CONTAINER_STARTED_UNEXPECTEDLY'}
 $r.Add('[OK] PRELOAD_OPTIONS_CRON_JOBS_DISABLED_NO_TCP_NETWORK_NONE')
 $r.Add('[OK] CURRENT_DIRECT_SERVER_STILL_RUNNING_EXCLUSIVELY')
 $r.Add('[APROVADO] CLEAN6_STOPPED_PRELOAD_RESTORE_SERVER_PREPARED')
 $r.Add('[LIMITE] No switch, no startup, no extension installed, no restore')
 $r.Add('[NEXT] GUARDED_STOP_OLD_THEN_START_PRELOAD_SERVER_WITH_RUNTIME_CHECK')
 $ok=$true
}catch{
 $why=[string]$_.Exception.Message
 if($why -cnotmatch '^[A-Z0-9_]{3,100}$'){$why='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$why)
 if($created){$r.Add('[AVISO] NEW_CONTAINER_MAY_EXIST_DO_NOT_RERUN')}
}finally{
 $o=$r -join [Environment]::NewLine
 Write-Output $o
 try{Set-Clipboard -Value $o -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
