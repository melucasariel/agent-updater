# ROTA62 Guardian CLEAN6 v0.6.9 - direct PostgreSQL initdb (fix Windows shell substitution)
# ONLY modifies disposable volume rota62_guardian_clean6_data after independent empty/permission checks.
# Network none, no ports, bypasses Supabase entrypoint and all init hooks.
# Does NOT start existing CLEAN6 container, touch previous labs, secrets, backups or remote services.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$ref='supabase_db_ROTA62_TESTE_SUPABASE'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 DIRECT INITDB v0.6.9 ===')
$r.Add('[MODO] DISPOSABLE_VOLUME_INIT_NO_SUPABASE_HOOKS_NETWORK_NONE')
$stage='PRECHECK';$success=$false
function DockerQuery([string[]]$argv){
 $old=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$rows=@(& docker @argv 2>$null);$rc=$LASTEXITCODE}
 catch{throw 'DOCKER_METADATA_EXCEPTION'}finally{$ErrorActionPreference=$old}
 if($rc -ne 0){throw 'DOCKER_METADATA_FAILED'}
 return (($rows -join [Environment]::NewLine).Trim())
}
function DockerProbe([string[]]$argv){
 $old=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$rows=@(& docker @argv 2>$null);$rc=$LASTEXITCODE}
 catch{$rows=@();$rc=-1}finally{$ErrorActionPreference=$old}
 return [pscustomobject]@{Code=$rc;Text=(($rows -join [Environment]::NewLine).Trim())}
}
try{
 $stage='IDENTITY'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $cArr=@(ConvertFrom-Json -InputObject (DockerQuery @('inspect',$cn)))
 $refArr=@(ConvertFrom-Json -InputObject (DockerQuery @('inspect',$ref)))
 if($cArr.Count -ne 1 -or $refArr.Count -ne 1){throw 'LAB_INSPECT_INVALID'}
 $c=$cArr[0];$reference=$refArr[0]
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_NOT_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_MISMATCH'}
 if([string]$c.HostConfig.RestartPolicy.Name -cne 'no'){throw 'CLEAN6_RESTART_POLICY_MISMATCH'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CLEAN6_PORTS_PRESENT'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn -or [string]$c.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'CLEAN6_VOLUME_MISMATCH'}
 if([string]$reference.State.Status -cne 'running' -or [string]$reference.Image -cne [string]$c.Image){throw 'REFERENCE_IMAGE_MISMATCH'}
 $image=[string]$c.Image
 if($image -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'IMAGE_ID_INVALID'}
 $volArr=@(ConvertFrom-Json -InputObject (DockerQuery @('volume','inspect',$vn)))
 if($volArr.Count -ne 1 -or [string]$volArr[0].Name -cne $vn){throw 'VOLUME_NOT_FOUND'}
 if((DockerQuery @('ps','--filter',('volume='+$vn),'--format','{{.ID}}')).Length -gt 0){throw 'VOLUME_HAS_RUNNING_CONSUMER'}
 $pgdataVars=@($c.Config.Env | Where-Object {$_ -match '^PGDATA='})
 if($pgdataVars.Count -ne 1 -or [string]$pgdataVars[0] -cne 'PGDATA=/var/lib/postgresql/data'){throw 'PGDATA_VOLUME_ROOT_REQUIRED'}
 $r.Add('[OK] CLEAN6_STOPPED_PINNED_IMAGE_EXCLUSIVE_VOLUME')
 $stage='EMPTY'
 $dataPath='/var/lib/postgresql/data'
 $common=@('run','--rm','--pull','never','--network','none','--read-only',
    '--user','postgres','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128')
 $ro=@('--mount',('type=volume,source='+$vn+',target='+$dataPath+',readonly'))
 $rw=@('--mount',('type=volume,source='+$vn+',target='+$dataPath))
 # IMPORTANT: no shell command substitution; stdout only counted, never reported.
 $find=DockerProbe ($common+$ro+@('--entrypoint','/usr/bin/find',$image,$dataPath,'-mindepth','1','-maxdepth','1','-print','-quit'))
 if($find.Code -ne 0){throw 'DIRECT_FIND_FAILED_NO_INITDB'}
 if($find.Text.Length -ne 0){throw 'PGDATA_NOT_EMPTY_NO_INITDB'}
 $r.Add('[OK] PGDATA_EMPTY_DIRECT_FIND')
 $stage='WRITABLE'
 $w=DockerProbe ($common+$rw+@('--entrypoint','/usr/bin/test',$image,'-w',$dataPath))
 if($w.Code -ne 0){throw 'PGDATA_NOT_WRITABLE_NO_INITDB'}
 $r.Add('[OK] PGDATA_WRITABLE_AS_POSTGRES')
 $stage='INITDB_EXECUTABLE'
 $bin=DockerProbe ($common+@('--entrypoint','/bin/sh',$image,'-c','command -v initdb'))
 $binPath=$bin.Text
 if($bin.Code -ne 0 -or $binPath -cnotmatch '^/[A-Za-z0-9._/-]{5,200}$' -or $binPath -match '(^|/)\.\.(/|$)'){throw 'INITDB_IMAGE_PATH_UNVERIFIED'}
 $testBin=DockerProbe ($common+@('--entrypoint','/usr/bin/test',$image,'-x',$binPath))
 if($testBin.Code -ne 0){throw 'INITDB_NOT_EXECUTABLE'}
 $r.Add('[OK] INITDB_EXECUTABLE_PATH_VERIFIED')
 $stage='INITDB'
 # FIRST INTENTIONAL WRITE. Entry point is the verified initdb executable itself.
 # Host/TCP authentication uses reject; local UNIX sockets peer auth only.
 $init=DockerProbe (@('run','--rm','--pull','never','--network','none',
   '--user','postgres','--cap-drop','ALL','--security-opt','no-new-privileges',
   '--pids-limit','128','--mount',('type=volume,source='+$vn+',target='+$dataPath),
   '--entrypoint',$binPath,$image,
   '-D',$dataPath,'--username=postgres','--auth-local=peer','--auth-host=reject','--no-instructions'))
 if($init.Code -ne 0){throw 'INITDB_FAILED_PRESERVE_VOLUME_NO_RETRY'}
 $r.Add('[OK] DIRECT_INITDB_COMPLETED')
 $stage='VERIFY'
 # Shell not required for checks: verify PG_VERSION with stat and use grep without pipes/subshell.
 $pgversion=DockerProbe ($common+$ro+@('--entrypoint','/bin/cat',$image,$dataPath+'/PG_VERSION'))
 if($pgversion.Code -ne 0 -or $pgversion.Text -cne '17'){throw 'PG_VERSION_17_NOT_VERIFIED'}
 $hba=DockerProbe ($common+$ro+@('--entrypoint','/usr/bin/grep',$image,'-E','^local[[:space:]]+all[[:space:]]+all[[:space:]]+peer([[:space:]]|$)',$dataPath+'/pg_hba.conf'))
 if($hba.Code -ne 0){throw 'LOCAL_PEER_RULE_NOT_VERIFIED'}
 $reject=DockerProbe ($common+$ro+@('--entrypoint','/usr/bin/grep',$image,'-E','^host[[:space:]]+all[[:space:]]+all[[:space:]]+[^[:space:]]+[[:space:]]+reject([[:space:]]|$)',$dataPath+'/pg_hba.conf'))
 if($reject.Code -ne 0){throw 'TCP_REJECT_RULE_NOT_VERIFIED'}
 $r.Add('[OK] PG17_LOCAL_PEER_TCP_REJECT_VERIFIED')
 $r.Add('[OK] CLEAN6_CONTAINER_LEFT_STOPPED')
 $r.Add('[OK] DEFAULT_SUPABASE_ENTRYPOINT_BYPASSED')
 $r.Add('[LIMITE] No PostgreSQL server running or backup restoration attempted')
 $r.Add('[NEXT] BUILD_EXPLICIT_OFFLINE_POSTGRES_SERVER_AND_RESTORE')
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]{3,100}$'){$reason='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
 if($stage -in @('INITDB','VERIFY')){$r.Add('[AVISO] CLEAN6_VOLUME_MAY_CONTAIN_INITIALIZED_DB_DO_NOT_REPEAT')}
}finally{
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
