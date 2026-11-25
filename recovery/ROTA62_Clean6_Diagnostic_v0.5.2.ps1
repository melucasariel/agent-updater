# ROTA62 CLEAN6 v0.5.2 - read-only diagnosis of failed Stage 2
# No Docker mutations, no database reads, no secrets, no raw error output.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$container='rota62_guardian_clean6_pg'
$volume='rota62_guardian_clean6_data'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN6 DIAGNOSTIC v0.5.2 ===')
$report.Add('[MODO] READ_ONLY_DOCKER_INSPECT_NO_MUTATIONS')
function Probe([string]$Name,[string[]]$Arguments) {
  $output=@()
  $exitCode=-1
  try {
    $old=$ErrorActionPreference
    $ErrorActionPreference='Continue'
    try {
      $output=@(& docker @Arguments 2>$null)
      $exitCode=$LASTEXITCODE
    } finally {$ErrorActionPreference=$old}
  } catch {
    $report.Add($Name+'=COMMAND_EXCEPTION_REDACTED')
    return $null
  }
  if($exitCode -ne 0){
    $report.Add($Name+'=NOT_FOUND_OR_COMMAND_FAILED')
    return $null
  }
  $report.Add($Name+'=OK')
  return (($output -join [Environment]::NewLine).Trim())
}
try {
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_NOT_FOUND'}
 $engine=Probe 'DOCKER_ENGINE' @('info','--format','{{.ServerVersion}}')
 if(-not $engine){throw 'DOCKER_ENGINE_UNAVAILABLE'}
 $report.Add('ENGINE_ACCESS=YES')
 $containerId=Probe 'CLEAN6_CONTAINER' @('container','inspect',$container,'--format','{{.Id}}')
 if($containerId) {
   $state=Probe 'CLEAN6_STATE_QUERY' @('inspect',$container,'--format','{{.State.Status}}')
   if($state -in @('created','running','exited','paused')){$report.Add('CLEAN6_STATE='+$state)}
   $net=Probe 'CLEAN6_NETWORK_QUERY' @('inspect',$container,'--format','{{.HostConfig.NetworkMode}}')
   if($net -eq 'none'){$report.Add('CLEAN6_NETWORK=NONE')}
   elseif($net){$report.Add('CLEAN6_NETWORK=OTHER_BLOCK')}
   $port=Probe 'CLEAN6_PORTS_QUERY' @('inspect',$container,'--format','{{json .HostConfig.PortBindings}}')
   if($port -eq '{}' -or $port -eq 'null'){$report.Add('CLEAN6_PUBLISHED_PORTS=NONE')}
   elseif($port){$report.Add('CLEAN6_PUBLISHED_PORTS=CHECK_REQUIRED')}
 }
 $volumeResult=Probe 'CLEAN6_VOLUME' @('volume','inspect',$volume,'--format','{{.Name}}')
 if($volumeResult -ceq $volume){$report.Add('CLEAN6_VOLUME_ID_MATCH=YES')}
 $refState=Probe 'REFERENCE_STATE_QUERY' @('inspect',$reference,'--format','{{.State.Status}}')
 if($refState -eq 'running'){$report.Add('REFERENCE_RUNNING=YES')}
 elseif($refState){$report.Add('REFERENCE_RUNNING=NO')}
 $image=Probe 'REFERENCE_IMAGE_QUERY' @('inspect',$reference,'--format','{{.Image}}')
 if($image -match '^sha256:[a-f0-9]{64}$') {
   $report.Add('REFERENCE_IMAGE_FORMAT=VALID')
   $installed=Probe 'REFERENCE_IMAGE_LOCAL' @('image','inspect',$image,'--format','{{.Id}}')
   if($installed -eq $image){$report.Add('REFERENCE_IMAGE_LOCAL_MATCH=YES')}
 } else {$report.Add('REFERENCE_IMAGE_FORMAT=UNKNOWN')}
 $report.Add('[LIMITE] Only reads Docker metadata; no start/create/delete/SQL')
 $report.Add('[PROXIMO] Resolve failure and preserve any existing CLEAN6 resources')
} catch {
 $msg=[string]$_.Exception.Message
 if($msg -cnotmatch '^[A-Z0-9_]+$'){$msg='REDACTED_DIAGNOSTIC_ERROR'}
 $report.Add('[BLOQUEADO] '+$msg)
} finally {
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
