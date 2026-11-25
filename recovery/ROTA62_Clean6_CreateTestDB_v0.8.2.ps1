# ROTA62 CLEAN6 v0.8.2 — create one dedicated test database, no restore
# Run only after successful v0.8.1 dependency inventory.
# Does NOT create roles, extensions, schemas, objects or touch old labs.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$server='rota62_guardian_clean6_direct_pg'
$original='rota62_guardian_clean6_pg'
$ref='supabase_db_ROTA62_TESTE_SUPABASE'
$volume='rota62_guardian_clean6_data'
$db='rota62_clean6_restore_v1'
$root='/var/lib/postgresql/data'
$stage='PRECHECK'
$ok=$false
$created=$false
$lines=New-Object 'System.Collections.Generic.List[string]'
$lines.Add('=== ROTA62 CLEAN6 CREATE ISOLATED TEST DATABASE v0.8.2 ===')
$lines.Add('[MODO] CREATE_NEW_DB_ONLY_NO_RESTORE_NO_ROLES_NO_EXTENSIONS')
function D([string[]]$argslist){
 $prior=$ErrorActionPreference
 try{
  $ErrorActionPreference='Continue'
  $res=@(& docker @argslist 2>$null)
  $rc=$LASTEXITCODE
 }catch{$res=@();$rc=-1}finally{$ErrorActionPreference=$prior}
 return [pscustomobject]@{Code=$rc;Value=(($res -join [Environment]::NewLine).Trim())}
}
function Need([string[]]$argslist,[string]$errorName){
 $x=D $argslist
 if($x.Code -ne 0){throw $errorName}
 return $x.Value
}
function Inspect([string]$name){
 $r=Need @('inspect',$name) 'DOCKER_INSPECT_FAILED'
 $arr=@(ConvertFrom-Json -InputObject $r)
 if($arr.Count -ne 1){throw 'DOCKER_INSPECT_INVALID'}
 return $arr[0]
}
function Query([string]$database,[string]$sql){
 return Need @('exec','--user','postgres',$server,
  'psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1',
  '-h','/tmp','-U','postgres','-d',$database,'-c',$sql) 'PSQL_QUERY_FAILED'
}
try{
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_MISSING'}
 $stage='CONTAINER_ISOLATION'
 $s=Inspect $server
 $c=Inspect $original
 $rr=Inspect $ref
 if([string]$s.Name -cne ('/'+$server) -or [string]$c.Name -cne ('/'+$original)){throw 'CONTAINER_NAME_MISMATCH'}
 if(-not [bool]$s.State.Running -or [string]$s.State.Status -cne 'running'){throw 'DIRECT_SERVER_NOT_RUNNING'}
 if([bool]$c.State.Running -or [string]$c.State.Status -cne 'created'){throw 'ORIGINAL_CLEAN6_STATE_UNEXPECTED'}
 if(-not [bool]$rr.State.Running){throw 'REFERENCE_NOT_RUNNING'}
 if([string]$s.Image -cnotmatch '^sha256:[a-f0-9]{64}$' -or [string]$s.Image -cne [string]$c.Image -or [string]$s.Image -cne [string]$rr.Image){throw 'IMAGE_PIN_MISMATCH'}
 if([string]$s.HostConfig.NetworkMode -cne 'none'){throw 'NETWORK_UNEXPECTED'}
 if([string]$s.HostConfig.RestartPolicy.Name -cne 'no'){throw 'RESTART_POLICY_UNEXPECTED'}
 if(-not [bool]$s.HostConfig.ReadonlyRootfs -or [bool]$s.HostConfig.Privileged){throw 'PRIVILEGE_MISMATCH'}
 if([string]$s.Config.User -cne 'postgres'){throw 'SERVER_USER_UNEXPECTED'}
 if(@($s.Mounts).Count -ne 1 -or [string]$s.Mounts[0].Name -cne $volume -or [string]$s.Mounts[0].Destination -cne $root){throw 'VOLUME_MISMATCH'}
 if($s.HostConfig.PortBindings -and @($s.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'PUBLISHED_PORTS_UNEXPECTED'}
 if($s.HostConfig.SecurityOpt -notcontains 'no-new-privileges'){throw 'SECURITY_OPT_MISSING'}
 $users=Need @('ps','--filter',('volume='+$volume),'--format','{{.Names}}') 'RUNNING_VOLUME_QUERY_FAILED'
 if($users -cne $server){throw 'VOLUME_SHARED_WITH_RUNNING_CONTAINER'}
 $lines.Add('[OK] CLEAN6_EXCLUSIVE_VOLUME_AND_SERVER_ISOLATION_VERIFIED')
 $stage='RUNTIME_PG17'
 $query="SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses')='' AND current_setting('shared_preload_libraries')='' AND current_setting('max_worker_processes')='0' AND current_setting('unix_socket_directories')='/tmp' THEN 'R62_ISOLATED_PG17_OK' ELSE 'R62_RUNTIME_UNSAFE' END"
 if((Query 'postgres' $query) -cne 'R62_ISOLATED_PG17_OK'){throw 'RUNTIME_SETTINGS_UNSAFE'}
 $lines.Add('[OK] PG17_TCP_DISABLED_LOCAL_SOCKET_ONLY')
 $stage='DATABASE_COLLISION_CHECK'
 $dbNameSql="SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_database WHERE datname='rota62_clean6_restore_v1') THEN 'EXISTS' ELSE 'ABSENT' END"
 if((Query 'postgres' $dbNameSql) -cne 'ABSENT'){throw 'TARGET_DATABASE_ALREADY_EXISTS_NO_ACTION'}
 $other=Query 'postgres' "SELECT CASE WHEN (SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1'))=0 THEN 'ONLY_SYSTEM_DATABASES' ELSE 'OTHER_DATABASE_PRESENT' END"
 if($other -cne 'ONLY_SYSTEM_DATABASES'){throw 'OTHER_DATABASE_ALREADY_PRESENT_NO_ACTION'}
 $lines.Add('[OK] TARGET_DATABASE_ABSENT_AND_CLUSTER_FRESH')
 $stage='CREATE_DATABASE'
 $create=D @('exec','--user','postgres',$server,'createdb','-h','/tmp','-U','postgres','-O','postgres','-T','template0',$db)
 if($create.Code -ne 0){throw 'CREATEDB_FAILED_INSPECT_BEFORE_RETRY'}
 $created=$true
 $lines.Add('[OK] DEDICATED_RESTORE_TEST_DATABASE_CREATED')
 $stage='VERIFY_DATABASE'
 $verify="SELECT CASE WHEN datname='rota62_clean6_restore_v1' AND pg_get_userbyid(datdba)='postgres' AND datallowconn THEN 'R62_DB_CREATED_OK' ELSE 'R62_DB_INVALID' END FROM pg_database WHERE datname='rota62_clean6_restore_v1'"
 if((Query 'postgres' $verify) -cne 'R62_DB_CREATED_OK'){throw 'DATABASE_POSTCREATE_VERIFY_FAILED'}
 $objects=Query $db "SELECT CASE WHEN (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f'))=0 THEN 'EMPTY' ELSE 'NOT_EMPTY' END"
 if($objects -cne 'EMPTY'){throw 'DATABASE_UNEXPECTED_USER_OBJECTS'}
 $again=Inspect $server
 if(-not [bool]$again.State.Running -or [string]$again.HostConfig.NetworkMode -cne 'none'){throw 'POSTCREATE_SERVER_STATE_UNEXPECTED'}
 $lines.Add('[OK] TEST_DATABASE_EXISTS_EMPTY_OWNED_BY_POSTGRES')
 $lines.Add('[OK] OTHER_LABS_UNTOUCHED_BY_THIS_SCRIPT')
 $lines.Add('[APROVADO] CLEAN6_SEPARATE_RESTORE_DATABASE_READY')
 $lines.Add('[LIMITE] No extensions, roles or backup data restored')
 $lines.Add('[NEXT] PLAN_SUPABASE_ROLE_EXTENSION_BOOTSTRAP_IN_TEST_DB')
 $ok=$true
}catch{
 $message=[string]$_.Exception.Message
 if($message -cnotmatch '^[A-Z0-9_]{3,100}$'){$message='LOCAL_ERROR_REDACTED'}
 $lines.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$message)
 if($created){$lines.Add('[AVISO] DATABASE_MAY_EXIST_DO_NOT_RERUN_USE_INSPECTION')}
}finally{
 $out=$lines -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
