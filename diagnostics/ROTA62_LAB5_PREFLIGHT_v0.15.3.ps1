# ROTA62 Guardian LAB5 v0.15.3 PRE-FLIGHT diagnostic — strictly read-only.
# DO NOT call an API, write SQL, start Docker containers, or touch production.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$pg='rota62_guardian_fifth_pg'
$net='rota62_guardian_fifth_internal'
$edge='rota62_guardian_lab5_dispatch_v012'
$db='rota62_guardian_fifth_restore'
$expected='13|25|93|2|2|0|0|off'
$source='D:\ROTA62_GUARDIAN\LAB5_DISPATCH_ORIGINAL_v0.12'
$indexSha='ACFEB7E6F708DF3A932DD47A64DB70A937B1343D0EE26E069041729936C16CF8'
$adapterSha='42FB1E25CB3B6243D37308726C3BA91C3ADEDF86A7A908659AE54ED9ABFFB3D6'
$stage='START'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 LAB5 v0.15.3 PREFLIGHT ===')
$report.Add('[MODO] READ_ONLY_NO_HTTP_NO_SQL_WRITES_NO_START')
$ok=$false
function RunDocker {
 [CmdletBinding()]
 param([Parameter(Mandatory=$true)][string[]]$Arguments)
 $lines=@(& docker @Arguments 2>$null)
 if($LASTEXITCODE -ne 0){throw 'DOCKER_NONZERO'}
 return (($lines -join [Environment]::NewLine).Trim())
}
try {
 $stage='DOCKER_CLI'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $report.Add('[OK] DOCKER_CLI_PRESENT')
 $stage='DOCKER_ENGINE'
 $v=RunDocker -Arguments @('info','--format','{{.ServerVersion}}')
 if([string]::IsNullOrWhiteSpace($v)){throw 'DOCKER_ENGINE_NO_RESPONSE'}
 $report.Add('[OK] DOCKER_ENGINE_REACHABLE')
 $stage='NETWORK'
 $internal=RunDocker -Arguments @('network','inspect',$net,'--format','{{.Internal}}')
 if($internal -cne 'true'){throw 'LAB_NETWORK_NOT_INTERNAL'}
 $report.Add('[OK] NETWORK_INTERNAL')
 $stage='PG_CONTAINER'
 $pgState=RunDocker -Arguments @('inspect',$pg,'--format','{{.State.Status}}')
 $pgNet=RunDocker -Arguments @('inspect',$pg,'--format','{{.HostConfig.NetworkMode}}')
 $pgPorts=RunDocker -Arguments @('inspect',$pg,'--format','{{json .HostConfig.PortBindings}}')
 if($pgState -cne 'running'){throw 'LAB_PG_NOT_RUNNING'}
 if($pgNet -cne $net){throw 'LAB_PG_WRONG_NETWORK'}
 if($pgPorts -cne '{}' -and $pgPorts -cne 'null'){throw 'LAB_PG_PORT_EXPOSED'}
 $report.Add('[OK] PG_RUNNING_INTERNAL_NO_PORTS')
 $stage='EDGE_CONTAINER'
 $edgeState=RunDocker -Arguments @('inspect',$edge,'--format','{{.State.Status}}')
 $edgeNet=RunDocker -Arguments @('inspect',$edge,'--format','{{.HostConfig.NetworkMode}}')
 $edgePorts=RunDocker -Arguments @('inspect',$edge,'--format','{{json .HostConfig.PortBindings}}')
 $edgeReadOnly=RunDocker -Arguments @('inspect',$edge,'--format','{{.HostConfig.ReadonlyRootfs}}')
 $edgeRestart=RunDocker -Arguments @('inspect',$edge,'--format','{{.HostConfig.RestartPolicy.Name}}')
 if($edgeState -cne 'running'){throw 'LAB_EDGE_NOT_RUNNING'}
 if($edgeNet -cne $net){throw 'LAB_EDGE_WRONG_NETWORK'}
 if($edgePorts -cne '{}' -and $edgePorts -cne 'null'){throw 'LAB_EDGE_PORT_EXPOSED'}
 if($edgeReadOnly -cne 'true'){throw 'LAB_EDGE_WRITABLE_ROOT'}
 if($edgeRestart -cne 'no'){throw 'LAB_EDGE_RESTART_ENABLED'}
 $report.Add('[OK] EDGE_RUNNING_INTERNAL_READONLY_NO_PORTS')
 $stage='MOUNT'
 $mountText=RunDocker -Arguments @('inspect',$edge,'--format','{{json .Mounts}}')
 $mounts=@(ConvertFrom-Json -InputObject $mountText)
 $correct=$false
 foreach($m in $mounts){
  if($m.Destination -ceq '/guardian-dispatch' -and $m.RW -eq $false -and ([string]$m.Source).TrimEnd('\','/') -ieq $source.TrimEnd('\','/')){$correct=$true}
 }
 if(-not $correct){throw 'LAB_MOUNT_MISMATCH'}
 $report.Add('[OK] SOURCE_MOUNT_READONLY')
 $stage='HASH'
 foreach($file in @(@('index.ts',$indexSha),@('guardian_adapter.ts',$adapterSha))){
  $path=Join-Path $source $file[0]
  if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw 'LAB_SOURCE_FILE_MISSING'}
  if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $file[1]){throw 'LAB_SOURCE_HASH_MISMATCH'}
 }
 $report.Add('[OK] SOURCE_SHA256')
 $stage='DB_READ_ONLY'
 $query="BEGIN READ ONLY; SELECT (SELECT count(*) FROM public.tr_users)::text||'|'||(SELECT count(*) FROM public.tr_sessions)||'|'||(SELECT count(*) FROM public.tr_rides)||'|'||(SELECT count(*) FROM public.tr_priority_drivers)||'|'||(SELECT count(*) FROM public.tr_driver_presence_v019)||'|'||(SELECT count(*) FROM public.tr_driver_declines_v019)||'|'||(SELECT count(*) FROM public.tr_users WHERE name LIKE 'GUARDIAN V014 %')||'|'||current_setting('cron.launch_active_jobs',true); ROLLBACK;"
 $response=RunDocker -Arguments @('exec',$pg,'psql','-U','supabase_admin','-d',$db,'-X','-A','-t','-v','ON_ERROR_STOP=1','-c',$query)
 $line=@($response -split '[\r\n]+' | Where-Object {$_ -match '^[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|[0-9]+\|(off|on)$'})
 if($line.Count -ne 1){throw 'LAB_SQL_RESULT_FORMAT'}
 if($line[0] -cne $expected){throw 'LAB_BASELINE_MISMATCH'}
 $report.Add('[OK] SQL_READ_ONLY_BASELINE')
 $report.Add('[APROVADO] LAB5_PREFLIGHT_READ_ONLY')
 $ok=$true
}catch{
 $category=[string]$_.Exception.Message
 if($category -cnotmatch '^[A-Z0-9_]+$'){$category='POWERSHELL_OR_DOCKER_UNCLASSIFIED'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$category)
 $report.Add('[RECHECK] NOT_RUN_SAFETY_STOP')
}finally{
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] REPORT_COPIED'}catch{}
}
if(-not $ok){exit 1}
