# ROTA62 CLEAN6 v0.8.8 - read-only state verification after failed guarded switch
# Never starts/stops containers, modifies volumes or runs write SQL.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$names=@('rota62_guardian_clean6_direct_pg','rota62_guardian_clean6_restore_pg','rota62_guardian_clean6_pg')
$volume='rota62_guardian_clean6_data'
$db='rota62_clean6_restore_v1'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 POST-SWITCH READ-ONLY DIAGNOSTIC v0.8.8 ===')
$r.Add('[MODO] READ_ONLY_NO_START_NO_STOP_NO_SQL_WRITES')
$stage='START';$success=$false
function D([string[]]$a){
 $prior=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$result=@(& docker @a 2>$null);$exit=$LASTEXITCODE}
 catch{$result=@();$exit=-1}
 finally{$ErrorActionPreference=$prior}
 return [pscustomobject]@{Exit=$exit;Text=(($result -join [Environment]::NewLine).Trim())}
}
function Need([string[]]$a,[string]$fail){
 $value=D $a
 if($value.Exit -ne 0){throw $fail}
 return $value.Text
}
function ReadContainer([string]$n){
 $raw=Need @('container','inspect',$n) 'DOCKER_INSPECT_FAILED'
 $items=@(ConvertFrom-Json -InputObject $raw)
 if($items.Count -ne 1){throw 'DOCKER_INSPECT_CARDINALITY'}
 return $items[0]
}
function Sql([string]$name,[string]$database,[string]$query){
 return D @('exec','--user','postgres',$name,'psql','-X','-A','-t','-q',
 '-v','ON_ERROR_STOP=1','-h','/tmp','-U','postgres','-d',$database,'-c',$query)
}
try{
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_MISSING'}
 $stage='DOCKER_INSPECT'
 $inspected=@{}
 foreach($name in $names){$inspected[$name]=ReadContainer $name}
 $a=$inspected[$names[0]];$b=$inspected[$names[1]];$c=$inspected[$names[2]]
 $image=[string]$a.Image
 if($image -cnotmatch '^sha256:[a-f0-9]{64}$' -or [string]$b.Image -cne $image -or [string]$c.Image -cne $image){throw 'IMAGE_IDENTITY_MISMATCH'}
 foreach($name in $names){
  $o=$inspected[$name]
  if([string]$o.Name -cne ('/'+$name)){throw 'CONTAINER_NAME_MISMATCH'}
  if([string]$o.HostConfig.NetworkMode -cne 'none' -or [string]$o.HostConfig.RestartPolicy.Name -cne 'no'){throw 'NETWORK_OR_RESTART_UNSAFE'}
  if([string]$o.Config.User -cne 'postgres' -or -not [bool]$o.HostConfig.ReadonlyRootfs -or [bool]$o.HostConfig.Privileged){throw 'PRIVILEGE_MISMATCH'}
  if($o.HostConfig.SecurityOpt -notcontains 'no-new-privileges'){throw 'SECURITY_OPTION_UNEXPECTED'}
  if(@($o.Mounts).Count -ne 1 -or [string]$o.Mounts[0].Name -cne $volume -or [string]$o.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'VOLUME_MISMATCH'}
  if($o.HostConfig.PortBindings -and @($o.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'PORTS_EXPOSED'}
  $state=[string]$o.State.Status
  if($state -cnotin @('running','exited','created')){throw 'UNKNOWN_CONTAINER_STATE'}
  $r.Add('CONTAINER_'+$name.ToUpperInvariant()+'='+$state.ToUpperInvariant())
 }
 $r.Add('[OK] ALL_THREE_CLEAN6_CONTAINERS_ISOLATED_PINNED')
 $stage='RUNNING_VOLUME_CONSUMERS'
 $namesRaw=Need @('ps','--filter',('volume='+$volume),'--format','{{.Names}}') 'DOCKER_PS_FAILED'
 $consumers=@($namesRaw -split '\r?\n' | Where-Object {$_})
 $r.Add('RUNNING_VOLUME_CONSUMER_COUNT='+$consumers.Count)
 if($consumers.Count -gt 1){throw 'MORE_THAN_ONE_RUNNING_VOLUME_CONSUMER'}
 if($consumers.Count -eq 1 -and $consumers[0] -cnotin @($names[0],$names[1])){throw 'UNEXPECTED_RUNNING_VOLUME_CONSUMER'}
 $r.Add('[OK] NO_CONCURRENT_POSTGRES_ON_CLEAN6_VOLUME')
 $stage='POSTGRES_READ_ONLY'
 $running=@($names | Where-Object {[bool]$inspected[$_].State.Running})
 if($running.Count -gt 1){throw 'TWO_CLEAN6_DATABASE_SERVERS_RUNNING'}
 if($running.Count -eq 0){
  $r.Add('[AVISO] NO_CLEAN6_DATABASE_SERVER_RUNNING')
  $r.Add('[NEXT] REQUIRE_GUARDED_RECOVERY_AFTER_INSPECTION')
 }else{
  $active=$running[0]
  $r.Add('ACTIVE_SERVER='+$active)
  if($consumers.Count -ne 1 -or $consumers[0] -cne $active){throw 'VOLUME_RUNNING_CONSUMER_MISMATCH'}
  $settings="SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses')='' AND current_setting('unix_socket_directories')='/tmp' THEN 'R62_READY' ELSE 'R62_UNSAFE' END"
  $q=Sql $active 'postgres' $settings
  if($q.Exit -ne 0 -or $q.Text -cne 'R62_READY'){throw 'PG17_LOCAL_SOCKET_NOT_READY'}
  $r.Add('[OK] ACTIVE_PG17_LOCAL_SOCKET_RESPONDS')
  $dbstate="SELECT CASE WHEN (SELECT count(*) FROM pg_database WHERE datname='rota62_clean6_restore_v1')=1 THEN 'DATABASE_PRESENT' ELSE 'DATABASE_MISSING' END"
  $dbq=Sql $active 'postgres' $dbstate
  if($dbq.Exit -ne 0 -or $dbq.Text -cne 'DATABASE_PRESENT'){throw 'TARGET_DATABASE_MISSING'}
  $r.Add('[OK] RESTORE_TEST_DATABASE_EXISTS')
  $x=Sql $active $db "SELECT CASE WHEN (SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql')=0 AND (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S'))=0 THEN 'DATABASE_EMPTY' ELSE 'DATABASE_HAS_OBJECTS' END"
  if($x.Exit -ne 0){throw 'RESTORE_DB_READ_ONLY_QUERY_FAILED'}
  $r.Add('RESTORE_TARGET_STATE='+$x.Text)
  if($x.Text -cne 'DATABASE_EMPTY'){throw 'RESTORE_TARGET_NOT_EMPTY'}
  $p=Sql $active 'postgres' "SELECT replace(current_setting('shared_preload_libraries'),' ','') || '|' || current_setting('max_worker_processes')"
  if($p.Exit -ne 0){throw 'PG_PRELOAD_QUERY_FAILED'}
  if($p.Text -ceq '|0'){$r.Add('PRELOAD_PROFILE=DIRECT_NO_WORKERS')}
  elseif($p.Text -ceq 'pg_cron,pg_net,pg_stat_statements|4'){$r.Add('PRELOAD_PROFILE=RESTORE_PRELOAD')}
  else{throw 'PRELOAD_RUNTIME_UNEXPECTED'}
  if($active -cne $names[0]){$r.Add('[AVISO] RESTORE_SERVER_ALREADY_ACTIVE_DO_NOT_REPEAT_SWITCH')}
  else{$r.Add('[OK] ORIGINAL_DIRECT_SERVER_RUNNING_AFTER_ROLLBACK')}
  $r.Add('[APROVADO] CLEAN6_POST_SWITCH_STATE_VERIFIED')
  $r.Add('[NEXT] FIX_STOP_OUTPUT_HANDLING_BEFORE_RETRYING_SWITCH')
 }
 $success=$true
}catch{
 $why=[string]$_.Exception.Message
 if($why -cnotmatch '^[A-Z0-9_]{3,100}$'){$why='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$why)
}finally{
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
