# ROTA62 Bridge V6 — local operator commands (only after trusted install).
# Never fetches executable files. Does not create a persistent service.
[CmdletBinding()]
param(
 [ValidateSet('STATUS','SELFTEST_ONCE','STOP_INSTRUCTIONS','CLEAN6_READINESS','CLEAN6_LOCATE_ERROR','CLEAN6_TRIAGE')][string]$Mode='STATUS',
 [string]$InstallDirectory=(Join-Path $env:LOCALAPPDATA 'ROTA62_BridgeV6')
)
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($InstallDirectory)
$agent=Join-Path $root 'scripts\Receive-BridgeV6.ps1'
$key=Join-Path $root 'bridge-public.xml'
switch($Mode){
 'STATUS' {
   Write-Output '=== ROTA62 V6 LOCAL STATUS ==='
   Write-Output ('STAGED='+(Test-Path -LiteralPath (Join-Path $root 'installed.version')))
   Write-Output ('PINNED_KEY_PRESENT='+(Test-Path -LiteralPath $key))
   Write-Output ('RECEIVER_SCRIPT_PRESENT='+(Test-Path -LiteralPath $agent))
   Write-Output 'AUTOSTART_CONFIGURED_BY_THIS_INSTALLER=NO'
 }
 'SELFTEST_ONCE' {
   if(-not(Test-Path -LiteralPath $agent) -or -not(Test-Path -LiteralPath $key)){Write-Output '[BLOQUEADO] AGENT_NOT_STAGED'; exit 2}
   & $agent -PublicKeyPath $key -StateDirectory (Join-Path $root 'state') -Once
 }
 'CLEAN6_READINESS' {
   $check=Join-Path $root 'scripts\Test-Clean6ReadinessV2.ps1'
   if(-not (Test-Path -LiteralPath $check -PathType Leaf)){Write-Output '[BLOQUEADO] CLEAN6_DIAGNOSTIC_NOT_STAGED'; exit 2}
   & $check
 }
 'CLEAN6_LOCATE_ERROR' {
   $loc=Join-Path $root 'scripts\Locate-Clean6ErrorMarkers.ps1'
   if(-not(Test-Path -LiteralPath $loc -PathType Leaf)){Write-Output '[BLOQUEADO] CLEAN6_LOCATOR_NOT_STAGED'; exit 2}
   & $loc
 }
 'CLEAN6_TRIAGE' {
   $triage=Join-Path $root 'scripts\Invoke-Clean6Triage.ps1'
   if(-not(Test-Path -LiteralPath $triage -PathType Leaf)){Write-Output '[BLOQUEADO] CLEAN6_TRIAGE_NOT_STAGED'; exit 2}
   & $triage
 }
 'STOP_INSTRUCTIONS' {
   Write-Output '[INFO] INSTALLER_DID_NOT_CREATE_BACKGROUND_SERVICE'
   Write-Output '[INFO] RECEIVER_RUNS_ONLY_WHEN_EXPLICITLY_STARTED'
 }
}
