# ROTA62 Guardian - Clean Restore Stage 2 (v0.5.1)
# Create a fresh STOPPED disposable lab container and named volume, never start or restore.
# No production endpoints, secrets, plaintext or port bindings. Windows PowerShell 5.1.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$container='rota62_guardian_clean6_pg'
$volume='rota62_guardian_clean6_data'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN RESTORE STAGE 2 v0.5.1 ===')
$report.Add('[MODO] CREATE_STOPPED_ONLY_NETWORK_NONE_NO_RESTORE')
$stage='PRECHECK'
$success=$false
function D([string[]]$a) {
  $r=@(& docker @a 2>$null)
  if($LASTEXITCODE -ne 0){throw 'DOCKER_COMMAND_FAILED'}
  return (($r -join [Environment]::NewLine).Trim())
}
function Exists([string[]]$a) {
  $null=@(& docker @a 2>$null)
  return ($LASTEXITCODE -eq 0)
}
try {
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_NOT_FOUND'}
 $ver=D @('info','--format','{{.ServerVersion}}')
 if(-not $ver){throw 'DOCKER_ENGINE_UNAVAILABLE'}
 if(Exists @('container','inspect',$container)){throw 'TARGET_CONTAINER_ALREADY_EXISTS'}
 if(Exists @('volume','inspect',$volume)){throw 'TARGET_VOLUME_ALREADY_EXISTS'}
 $image=D @('inspect',$reference,'--format','{{.Image}}')
 if($image -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'REFERENCE_IMAGE_INVALID'}
 if((D @('image','inspect',$image,'--format','{{.Id}}')) -cne $image){throw 'IMAGE_NOT_AVAILABLE'}
 $refStatus=D @('inspect',$reference,'--format','{{.State.Status}}')
 if($refStatus -cne 'running'){throw 'REFERENCE_LAB_NOT_RUNNING'}
 $report.Add('[OK] NEW_NAMES_UNUSED')
 $report.Add('[OK] REFERENCE_IMAGE_PINNED_LOCALLY')
 # This volume will contain only disposable local test data.
 $stage='CREATE_VOLUME'
 $created=D @('volume','create','--name',$volume)
 if($created -cne $volume){throw 'VOLUME_CREATE_UNEXPECTED_RESULT'}
 $report.Add('[OK] NEW_DISPOSABLE_VOLUME_CREATED')
 # No docker start/run, never make the container reachable on any network.
 $stage='CREATE_STOPPED'
 # Use fixed known non-production placeholder because the container will NEVER be started by this script.
 $args=@('create','--name',$container,'--network','none','--restart','no',
   '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256',
   '--mount',('type=volume,source='+$volume+',target=/var/lib/postgresql/data'),
   '--env','POSTGRES_PASSWORD=R62_TEST_CONTAINER_STOPPED_NO_REAL_SECRET',
   $image)
 $cid=D $args
 if($cid -cnotmatch '^[a-f0-9]{64}$'){throw 'CONTAINER_CREATE_RESULT_INVALID'}
 $stage='VERIFY_STOPPED'
 $status=D @('inspect',$container,'--format','{{.State.Status}}')
 $mode=D @('inspect',$container,'--format','{{.HostConfig.NetworkMode}}')
 $ports=D @('inspect',$container,'--format','{{json .HostConfig.PortBindings}}')
 $restart=D @('inspect',$container,'--format','{{.HostConfig.RestartPolicy.Name}}')
 if($status -cne 'created' -or $mode -cne 'none' -or ($ports -cne '{}' -and $ports -cne 'null') -or $restart -cne 'no'){throw 'CREATED_CONTAINER_SAFETY_MISMATCH'}
 $report.Add('[OK] NEW_CONTAINER_CREATED_NOT_STARTED')
 $report.Add('[OK] NETWORK_NONE_NO_PUBLISHED_PORTS_NO_RESTART')
 $report.Add('[OK] PRIOR_LAB_CONTAINERS_UNCHANGED_BY_SCRIPT')
 $report.Add('[LIMITE] PostgreSQL initialization and restoration not executed')
 $report.Add('[NEXT] AUDIT_IMAGE_ENTRYPOINT_AND_PREPARE_SAFE_START')
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]{3,90}$'){$reason='LOCAL_DOCKER_ERROR_REDACTED'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
 $report.Add('[AVISO] If volume was created, it was intentionally preserved for investigation')
}finally{
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
