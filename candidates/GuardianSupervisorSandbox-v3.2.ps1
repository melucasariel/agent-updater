# ROTA62 Guardian v3.2 — transaction primitive for disposable laboratory ONLY.
# This module is not the live updater. A caller must explicitly supply a sandbox path.
Set-StrictMode -Version Latest

function Invoke-R62SandboxSwap {
 [CmdletBinding()]
 param(
  [Parameter(Mandatory=$true)][string]$LabRoot,
  [Parameter(Mandatory=$true)][string]$StagedFile,
  [Parameter(Mandatory=$true)][scriptblock]$HealthProbe,
  [switch]$SimulateCrash
 )
 $ErrorActionPreference='Stop'
 $resolvedRoot=[IO.Path]::GetFullPath($LabRoot).TrimEnd('\')
 $tempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
 if(-not $resolvedRoot.StartsWith(($tempRoot+'\'),[StringComparison]::OrdinalIgnoreCase)) {
   throw 'LAB_MUST_BE_UNDER_TEMP'
 }
 if(-not $resolvedRoot.Contains('R62_Supervisor_Test_')) {
   throw 'LAB_MARKER_MISSING'
 }
 if(!(Test-Path -LiteralPath $resolvedRoot -PathType Container)){throw 'LAB_MISSING'}
 $live=Join-Path $resolvedRoot 'GuardianAgent.ps1'
 $previous=Join-Path $resolvedRoot 'GuardianAgent.previous.ps1'
 $stage=Join-Path $resolvedRoot 'GuardianAgent.candidate.ps1'
 if(!(Test-Path -LiteralPath $live -PathType Leaf)){throw 'LAB_AGENT_MISSING'}
 if(!(Test-Path -LiteralPath $StagedFile -PathType Leaf)){throw 'STAGE_MISSING'}
 if((Get-Item -LiteralPath $StagedFile).Length -gt 100000){throw 'STAGE_TOO_LARGE'}
 $original=(Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash
 $new=(Get-FileHash -LiteralPath $StagedFile -Algorithm SHA256).Hash
 if($original -eq $new){throw 'REPLAY_SAME_BYTES'}
 $tokens=$null;$errors=$null
 [void][Management.Automation.Language.Parser]::ParseFile($StagedFile,[ref]$tokens,[ref]$errors)
 if(@($errors).Count -gt 0){throw 'STAGE_SYNTAX_ERROR'}
 Copy-Item -LiteralPath $StagedFile -Destination $stage -Force
 if((Get-FileHash -LiteralPath $stage -Algorithm SHA256).Hash -ne $new){throw 'STAGE_HASH_CHANGED'}
 if(Test-Path -LiteralPath $previous){throw 'PREVIOUS_BACKUP_EXISTS'}
 Copy-Item -LiteralPath $live -Destination $previous
 if((Get-FileHash -LiteralPath $previous -Algorithm SHA256).Hash -ne $original){throw 'BACKUP_VERIFY_FAILED'}
 $swapped=$false
 try {
   Copy-Item -LiteralPath $stage -Destination $live -Force
   $swapped=$true
   if((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -ne $new){throw 'LIVE_HASH_INVALID'}
   if($SimulateCrash){throw 'SIMULATED_STARTUP_FAILURE'}
   $healthy=$false
   # A real implementation must replace this callback with a challenge-response
   # from the newly running Agent process; a PID alone is not sufficient.
   $healthy=[bool](& $HealthProbe $live $new)
   if(-not $healthy){throw 'HEALTH_HANDSHAKE_FAILED'}
   return '[OK] SANDBOX_SWAPPED_AND_HEALTHY'
 } catch {
   if($swapped){
     Copy-Item -LiteralPath $previous -Destination $live -Force
     if((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -ne $original){
       throw 'CRITICAL_SANDBOX_ROLLBACK_FAILED'
     }
   }
   throw
 } finally {
   Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue
 }
}
