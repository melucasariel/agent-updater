# ROTA62 CLEAN6 v0.8.3 - bootstrap only five isolated non-login service roles
# No grants, no login, no extensions, no restore, no changes to old labs.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$server='rota62_guardian_clean6_direct_pg'
$original='rota62_guardian_clean6_pg'
$ref='supabase_db_ROTA62_TESTE_SUPABASE'
$volume='rota62_guardian_clean6_data'
$db='rota62_clean6_restore_v1'
$roles=@('pgbouncer','supabase_admin','supabase_auth_admin','supabase_realtime_admin','supabase_storage_admin')
$stage='PRECHECK';$ok=$false;$changed=$false
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 SAFE ROLE BOOTSTRAP v0.8.3 ===')
$r.Add('[MODO] CREATE_ONLY_FIVE_NOLOGIN_ROLES_NO_GRANTS_NO_RESTORE')
function D([string[]]$a){
 $p=$ErrorActionPreference
 try{ $ErrorActionPreference='Continue'; $v=@(& docker @a 2>$null);$rc=$LASTEXITCODE }
 catch{ $v=@();$rc=-1 }
 finally{ $ErrorActionPreference=$p }
 return [pscustomobject]@{Code=$rc;Value=(($v -join [Environment]::NewLine).Trim())}
}
function Must([string[]]$a,[string]$fail){
 $v=D $a
 if($v.Code -ne 0){throw $fail}
 return $v.Value
}
function Inspect([string]$name){
 $raw=Must @('inspect',$name) 'DOCKER_INSPECT_FAILED'
 $items=@(ConvertFrom-Json -InputObject $raw)
 if($items.Count -ne 1){throw 'DOCKER_INSPECT_UNEXPECTED'}
 return $items[0]
}
function SQL([string]$dbname,[string]$sql,[bool]$readonly){
 $argslist=@('exec','--user','postgres',$server,'psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-h','/tmp','-U','postgres','-d',$dbname)
 if($readonly){ $argslist+=@('-c',$sql) }else{ $argslist+=@('-c',$sql) }
 return D $argslist
}
function ReadSQL([string]$dbname,[string]$sql){
 $q=SQL $dbname $sql $true
 if($q.Code -ne 0){throw 'READ_ONLY_SQL_FAILED'}
 return $q.Value
}
try{
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $stage='ISOLATION'
 $s=Inspect $server;$c=Inspect $original;$rf=Inspect $ref
 if([string]$s.Name -cne ('/'+$server) -or -not [bool]$s.State.Running){throw 'DIRECT_SERVER_STATE_UNEXPECTED'}
 if([string]$c.Name -cne ('/'+$original) -or [bool]$c.State.Running -or [string]$c.State.Status -cne 'created'){throw 'ORIGINAL_CLEAN6_STATE_UNEXPECTED'}
 if(-not [bool]$rf.State.Running){throw 'REFERENCE_NOT_RUNNING'}
 if([string]$s.Image -cne [string]$c.Image -or [string]$s.Image -cne [string]$rf.Image -or [string]$s.Image -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'PINNED_IMAGE_UNEXPECTED'}
 if([string]$s.HostConfig.NetworkMode -cne 'none' -or [string]$s.HostConfig.RestartPolicy.Name -cne 'no'){throw 'NETWORK_OR_RESTART_UNSAFE'}
 if([string]$s.Config.User -cne 'postgres' -or [bool]$s.HostConfig.Privileged -or -not [bool]$s.HostConfig.ReadonlyRootfs){throw 'PRIVILEGE_UNSAFE'}
 if($s.HostConfig.SecurityOpt -notcontains 'no-new-privileges'){throw 'NO_NEW_PRIVILEGES_MISSING'}
 if(@($s.Mounts).Count -ne 1 -or [string]$s.Mounts[0].Name -cne $volume -or [string]$s.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'VOLUME_UNEXPECTED'}
 if($s.HostConfig.PortBindings -and @($s.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'PORTS_PUBLISHED'}
 $consumers=Must @('ps','--filter',('volume='+$volume),'--format','{{.Names}}') 'VOLUME_CONSUMER_CHECK_FAILED'
 if($consumers -cne $server){throw 'VOLUME_SHARED_WITH_RUNNING_CONTAINER'}
 $r.Add('[OK] SERVER_ISOLATION_AND_EXCLUSIVE_VOLUME_VERIFIED')
 $stage='PG_SETTINGS'
 $settings="SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses')='' AND current_setting('shared_preload_libraries')='' AND current_setting('max_worker_processes')='0' AND current_setting('unix_socket_directories')='/tmp' THEN 'R62_OK' ELSE 'R62_UNSAFE' END"
 if((ReadSQL 'postgres' $settings) -cne 'R62_OK'){throw 'PG_SETTINGS_UNEXPECTED'}
 $r.Add('[OK] POSTGRESQL17_LOCAL_SOCKET_ONLY')
 $stage='DATABASE'
 $count=ReadSQL 'postgres' "SELECT CASE WHEN (SELECT count(*) FROM pg_database WHERE datname='rota62_clean6_restore_v1' AND pg_get_userbyid(datdba)='postgres')=1 AND (SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1','rota62_clean6_restore_v1'))=0 THEN 'R62_DB_OK' ELSE 'R62_DB_UNEXPECTED' END"
 if($count -cne 'R62_DB_OK'){throw 'TARGET_DATABASE_NOT_EXCLUSIVE'}
 $empty=ReadSQL $db "SELECT CASE WHEN (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f'))=0 AND (SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql')=0 THEN 'R62_EMPTY' ELSE 'R62_NOT_EMPTY' END"
 if($empty -cne 'R62_EMPTY'){throw 'TARGET_NOT_EMPTY_OR_EXTENSIONS_EXIST'}
 $r.Add('[OK] TARGET_RESTORE_DB_EXISTS_AND_IS_EMPTY')
 $stage='ROLE_PRECHECK'
 $names="'"+($roles -join "','")+"'"
 $found=ReadSQL 'postgres' ("SELECT rolname FROM pg_roles WHERE rolname IN ("+$names+") ORDER BY rolname")
 if($found.Length -ne 0){throw 'ONE_OR_MORE_BOOTSTRAP_ROLES_ALREADY_EXIST_NO_RETRY'}
 $r.Add('[OK] FIVE_SERVICE_ROLE_NAMES_AVAILABLE')
 $stage='CREATE_ROLES'
 foreach($role in $roles){
  if($role -cnotmatch '^[a-z_]{3,40}$'){throw 'UNSAFE_ROLE_NAME'}
  $create=SQL 'postgres' ('CREATE ROLE '+$role+' NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION INHERIT') $false
  if($create.Code -ne 0){throw 'ROLE_CREATE_FAILED_INSPECT_STATE'}
  $changed=$true
  $r.Add('[OK] CREATED_NOLOGIN_ROLE_'+$role.ToUpperInvariant())
 }
 $stage='VERIFY_ROLES'
 $verified=ReadSQL 'postgres' ("SELECT count(*)::text FROM pg_roles WHERE rolname IN ("+$names+") AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication")
 if($verified -cne '5'){throw 'POSTCREATE_ROLE_FLAGS_NOT_VERIFIED'}
 $after=Inspect $server
 if(-not [bool]$after.State.Running -or [string]$after.HostConfig.NetworkMode -cne 'none'){throw 'SERVER_STATE_CHANGED'}
 $r.Add('[OK] ALL_FIVE_ROLES_VERIFIED_NOLOGIN_NO_ADMIN_PRIVILEGES')
 $r.Add('[OK] OLD_REFERENCE_CONTAINERS_NOT_MODIFIED_BY_SCRIPT')
 $r.Add('[APROVADO] CLEAN6_SERVICE_ROLES_BOOTSTRAPPED')
 $r.Add('[LIMITE] Roles are restricted placeholders; no grants, extensions, schemas or restore yet')
 $r.Add('[NEXT] SAFE_EXTENSION_AND_SCHEMA_DEPENDENCY_PREP')
 $ok=$true
}catch{
 $msg=[string]$_.Exception.Message
 if($msg -cnotmatch '^[A-Z0-9_]{3,100}$'){$msg='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$msg)
 if($changed){$r.Add('[AVISO] SOME_ROLES_MAY_EXIST_DO_NOT_RERUN_INSPECT_FIRST')}
}finally{
 $output=$r -join [Environment]::NewLine
 Write-Output $output
 try{Set-Clipboard -Value $output -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
