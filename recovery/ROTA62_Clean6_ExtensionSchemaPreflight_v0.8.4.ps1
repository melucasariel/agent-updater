# ROTA62 CLEAN6 extension/schema preflight v0.8.4 (SELECT-only)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$server='rota62_guardian_clean6_direct_pg'
$volume='rota62_guardian_clean6_data'
$db='rota62_clean6_restore_v1'
$extensions=@('pg_cron','pg_net','pg_stat_statements','pgcrypto','supabase_vault','uuid-ossp')
$roles=@('pgbouncer','supabase_admin','supabase_auth_admin','supabase_realtime_admin','supabase_storage_admin')
$schemas=@('auth','extensions','graphql','graphql_public','pgbouncer','realtime','storage','vault')
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN6 EXTENSION SCHEMA PREFLIGHT v0.8.4 ===')
$report.Add('[MODO] READ_ONLY_NO_DDL_NO_RESTORE')
$stage='PRECHECK';$ok=$false
function D([string[]]$a){
 $prev=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$out=@(& docker @a 2>$null);$rc=$LASTEXITCODE}
 catch{$out=@();$rc=-1}
 finally{$ErrorActionPreference=$prev}
 return [pscustomobject]@{Code=$rc;Value=(($out -join [Environment]::NewLine).Trim())}
}
function Need([string[]]$a,[string]$fail){
 $q=D $a
 if($q.Code -ne 0){throw $fail}
 return $q.Value
}
function GetContainer([string]$name){
 $items=@(ConvertFrom-Json -InputObject (Need @('inspect',$name) 'DOCKER_INSPECT_FAILED'))
 if($items.Count -ne 1){throw 'DOCKER_INSPECT_COUNT_INVALID'}
 return $items[0]
}
function Q([string]$database,[string]$sql){
 $raw=Need @('exec','--user','postgres',$server,'psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-h','/tmp','-U','postgres','-d',$database,'-c',$sql) 'READ_ONLY_SQL_FAILED'
 if($raw.Length -gt 6000){throw 'METADATA_OUTPUT_TOO_LARGE'}
 return $raw
}
try{
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_MISSING'}
 $stage='ISOLATION'
 $s=GetContainer $server;$c=GetContainer 'rota62_guardian_clean6_pg';$reference=GetContainer 'supabase_db_ROTA62_TESTE_SUPABASE'
 if([string]$s.Name -cne ('/'+$server) -or -not [bool]$s.State.Running){throw 'SERVER_NOT_RUNNING'}
 if([bool]$c.State.Running -or [string]$c.State.Status -cne 'created'){throw 'ORIGINAL_CLEAN6_CHANGED'}
 if(-not [bool]$reference.State.Running){throw 'REFERENCE_NOT_RUNNING'}
 if([string]$s.Image -cnotmatch '^sha256:[a-f0-9]{64}$' -or [string]$s.Image -cne [string]$c.Image -or [string]$s.Image -cne [string]$reference.Image){throw 'IMAGE_PIN_MISMATCH'}
 if([string]$s.HostConfig.NetworkMode -cne 'none' -or [string]$s.HostConfig.RestartPolicy.Name -cne 'no' -or [string]$s.Config.User -cne 'postgres'){throw 'SERVER_CONFIG_UNSAFE'}
 if([bool]$s.HostConfig.Privileged -or -not [bool]$s.HostConfig.ReadonlyRootfs -or $s.HostConfig.SecurityOpt -notcontains 'no-new-privileges'){throw 'SERVER_SECURITY_UNSAFE'}
 if(@($s.Mounts).Count -ne 1 -or [string]$s.Mounts[0].Name -cne $volume -or [string]$s.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'VOLUME_MISMATCH'}
 if($s.HostConfig.PortBindings -and @($s.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'PORTS_UNSAFE'}
 if((Need @('ps','--filter',('volume='+$volume),'--format','{{.Names}}') 'VOLUME_CHECK_FAILED') -cne $server){throw 'SHARED_VOLUME_UNSAFE'}
 $report.Add('[OK] SERVER_ISOLATED_EXCLUSIVE_VOLUME')
 $stage='RUNTIME'
 $sql="SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses')='' AND current_setting('shared_preload_libraries')='' AND current_setting('max_worker_processes')='0' AND current_setting('unix_socket_directories')='/tmp' THEN 'OK' ELSE 'BAD' END"
 if((Q 'postgres' $sql) -cne 'OK'){throw 'SERVER_RUNTIME_UNSAFE'}
 $report.Add('[OK] PG17_NO_TCP_NO_PRELOAD_NO_WORKERS')
 $stage='DATABASE'
 $check="SELECT CASE WHEN (SELECT count(*) FROM pg_database WHERE datname='rota62_clean6_restore_v1' AND pg_get_userbyid(datdba)='postgres')=1 AND (SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1','rota62_clean6_restore_v1'))=0 THEN 'OK' ELSE 'BAD' END"
 if((Q 'postgres' $check) -cne 'OK'){throw 'TARGET_DATABASE_STATE_UNEXPECTED'}
 $obj="SELECT CASE WHEN (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','S','f'))=0 AND (SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql')=0 THEN 'OK' ELSE 'BAD' END"
 if((Q $db $obj) -cne 'OK'){throw 'TARGET_NOT_EMPTY'}
 $report.Add('[OK] TEST_DATABASE_EMPTY')
 $stage='ROLES'
 $roleList="'"+($roles -join "','")+"'"
 $roleSql="SELECT count(*)::text FROM pg_roles WHERE rolname IN ("+$roleList+") AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication"
 if((Q 'postgres' $roleSql) -cne '5'){throw 'RESTRICTED_ROLES_NOT_VERIFIED'}
 $report.Add('[OK] FIVE_NOLOGIN_SERVICE_ROLES_VERIFIED')
 $stage='EXTENSIONS'
 $extList="'"+($extensions -join "','")+"'"
 $available=Q $db ("SELECT name || '|' || default_version || '|' || coalesce(installed_version,'NONE') FROM pg_available_extensions WHERE name IN ("+$extList+") ORDER BY name")
 $rows=@($available -split '\r?\n' | Where-Object {$_})
 if($rows.Count -ne 6){throw 'REQUIRED_EXTENSIONS_NOT_ALL_AVAILABLE'}
 foreach($line in $rows){
  $v=$line -split '\|',3
  if($v.Count -ne 3 -or $extensions -cnotcontains $v[0] -or $v[1] -cnotmatch '^[A-Za-z0-9_.-]{1,35}$' -or $v[2] -cne 'NONE'){throw 'EXTENSION_ROW_UNEXPECTED'}
  $report.Add('EXTENSION='+$v[0]+' VERSION='+$v[1]+' STATUS=AVAILABLE_NOT_INSTALLED')
 }
 $report.Add('[OK] SIX_REQUIRED_EXTENSIONS_AVAILABLE_NO_CONFLICT')
 $stage='SCHEMAS'
 $schemaList="'"+($schemas -join "','")+"'"
 if((Q $db ("SELECT count(*)::text FROM pg_namespace WHERE nspname IN ("+$schemaList+")")) -cne '0'){throw 'RESTORE_SCHEMAS_ALREADY_PRESENT'}
 $report.Add('[OK] EIGHT_ARCHIVE_SCHEMAS_NOT_PRECREATED')
 $report.Add('[AVISO] PG_CRON_AND_PG_NET_MAY_REQUIRE_SPECIAL_RESTORE_HANDLING')
 $report.Add('[APROVADO] CLEAN6_DEPENDENCIES_READY_FOR_ORDERED_RESTORE_PLAN')
 $report.Add('[LIMITE] No writes, no ACL grantee reconciliation, no restore')
 $report.Add('[NEXT] DESIGN_ORDERED_RESTORE_WITH_EXTENSION_HANDLING')
 $ok=$true
}catch{
 $err=[string]$_.Exception.Message
 if($err -cnotmatch '^[A-Z0-9_]{3,100}$'){$err='LOCAL_ERROR_REDACTED'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$err)
}finally{
 $txt=$report -join [Environment]::NewLine
 Write-Output $txt
 try{Set-Clipboard -Value $txt -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
