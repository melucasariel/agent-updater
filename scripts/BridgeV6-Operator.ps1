# ROTA62 Bridge V6 — local operator commands (only after trusted install).
# Never fetches executable files. Does not create a persistent service.
[CmdletBinding()]
param(
 [ValidateSet('STATUS','SELFTEST_ONCE','STOP_INSTRUCTIONS')][string]$Mode='STATUS',
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
 'STOP_INSTRUCTIONS' {
   Write-Output '[INFO] INSTALLER_DID_NOT_CREATE_BACKGROUND_SERVICE'
   Write-Output '[INFO] RECEIVER_RUNS_ONLY_WHEN_EXPLICITLY_STARTED'
 }
}
