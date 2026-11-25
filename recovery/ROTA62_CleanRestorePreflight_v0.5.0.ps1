# ROTA62 Guardian - Clean Restore PRE-FLIGHT v0.5.0
# Read-only check for a NEW disposable Docker DB. No docker create/run, no DB writes.
# Windows PowerShell 5.1 compatible. Clipboard report contains no passwords or paths.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$pointer=Join-Path $root 'backup_selection.dpapi'
$expectedHash='35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 GUARDIAN CLEAN RESTORE PREFLIGHT v0.5.0 ===')
$report.Add('[MODO] READ_ONLY_NO_CREATE_NO_RESTORE_NO_PRODUCTION')
$stage='START'
$ready=$false
$bytes=$null
function Check([string]$k,[string]$v){$report.Add($k+'='+$v)}
function DockerRead([string[]]$a){
 $result=@(& docker @a 2>$null)
 if($LASTEXITCODE -ne 0){throw 'DOCKER_READ_FAILED'}
 return (($result -join [Environment]::NewLine).Trim())
}
try{
 $stage='TOOLS'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 if(-not (Get-Command node -ErrorAction SilentlyContinue)){throw 'NODE_MISSING'}
 if(-not (Get-Command pg_restore -ErrorAction SilentlyContinue)){throw 'PG_RESTORE_MISSING'}
 $nv=(& node --version 2>$null)
 if($LASTEXITCODE -ne 0 -or [string]$nv -notmatch '^v(\d+)\.'){throw 'NODE_VERSION_UNAVAILABLE'}
 if([int]$Matches[1] -lt 20){throw 'NODE_20_REQUIRED'}
 Check 'NODE_MAJOR' ([string]$Matches[1])
 $dockerVersion=DockerRead @('info','--format','{{.ServerVersion}}')
 if([string]::IsNullOrWhiteSpace($dockerVersion)){throw 'DOCKER_ENGINE_UNAVAILABLE'}
 Check 'DOCKER_ENGINE' 'READY'
 $stage='BACKUP_POINTER'
 Add-Type -AssemblyName System.Security
 if(-not (Test-Path -LiteralPath $pointer -PathType Leaf)){throw 'BACKUP_DPAPI_POINTER_MISSING'}
 $bytes=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($pointer),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
 $path=[Text.Encoding]::UTF8.GetString($bytes)
 [Array]::Clear($bytes,0,$bytes.Length);$bytes=$null
 if([IO.Path]::GetExtension($path) -cne '.r62db' -or -not (Test-Path -LiteralPath $path -PathType Leaf)){throw 'BACKUP_NOT_ACCESSIBLE'}
 if((Get-Item -LiteralPath $path).Length -ne 5287976){throw 'BACKUP_SIZE_MISMATCH'}
 if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $expectedHash){throw 'BACKUP_HASH_MISMATCH'}
 Check 'BACKUP' 'SHA256_VERIFIED'
 $stage='DOCKER_ORIGINAL_LAB'
 $original='supabase_db_ROTA62_TESTE_SUPABASE'
 $state=DockerRead @('inspect',$original,'--format','{{.State.Status}}')
 if($state -cne 'running'){throw 'REFERENCE_LAB_NOT_RUNNING'}
 $imageId=DockerRead @('inspect',$original,'--format','{{.Image}}')
 if($imageId -cnotmatch '^sha256:[0-9a-f]{64}$'){throw 'REFERENCE_IMAGE_ID_INVALID'}
 $imageDigest=DockerRead @('image','inspect',$imageId,'--format','{{.Id}}')
 if($imageDigest -cne $imageId){throw 'REFERENCE_IMAGE_NOT_PRESENT'}
 Check 'REFERENCE_SUPABASE_IMAGE' 'LOCAL_VERIFIED'
 $stage='EXISTING_TEST_RESOURCES'
 # The final restore runner must use new unique names, never these existing containers.
 $safeNames=@('rota62_guardian_fifth_pg','rota62_guardian_lab5_dispatch_v012','supabase_db_ROTA62_TESTE_SUPABASE')
 foreach($name in $safeNames){
  $x=@(& docker inspect $name --format '{{.State.Status}}' 2>$null)
  if($LASTEXITCODE -eq 0){Check ('EXISTING_'+$name) 'PRESERVE'}
 }
 $stage='DOCKER_STORAGE'
 # Disk free space at Docker data-root may differ from local drive.
 # Only inspect size availability: do not depend on a specific disk path.
 $df=DockerRead @('system','df','--format','{{.Type}}:{{.Size}}')
 if([string]::IsNullOrWhiteSpace($df)){throw 'DOCKER_DISK_INFO_UNAVAILABLE'}
 Check 'DOCKER_DISK_INSPECTION' 'RESPONDED_NOT_CAPACITY_CERTIFIED'
 $stage='SAFETY'
 # Future restore runner must create dedicated Docker named volume + internal network;
 # no current or remote DB connection strings permitted.
 Check 'RESTORE_DESTINATION' 'NEW_LOCAL_CONTAINER_REQUIRED'
 Check 'NETWORK_POLICY' 'INTERNAL_ONLY_REQUIRED'
 Check 'PG_CRON_PG_NET' 'MUST_BE_DISABLED_BEFORE_START'
 Check 'PLATFORM_SECRETS' 'NOT_READ'
 Check 'DRY_RUN' 'NO_NEW_RESOURCES_CREATED'
 Check 'NEXT' 'PREPARE_FRESH_ISOLATED_RESTORE_RUNNER'
 $report.Add('[APROVADO] PREFLIGHT_BASIC_DEPENDENCIES')
 $ready=$true
}catch{
 $code=[string]$_.Exception.Message
 if($code -cnotmatch '^[A-Z0-9_]{3,80}$'){$code='LOCAL_ERROR_REDACTED'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$code)
}finally{
 if($bytes){[Array]::Clear($bytes,0,$bytes.Length)}
 $textOutput=$report -join [Environment]::NewLine
 Write-Output $textOutput
 try{Set-Clipboard -Value $textOutput -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ready){exit 1}
