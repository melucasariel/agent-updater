# ROTA62 Guardian - OFFLINE regression tests for proposed updater safety rules.
# This file does not contact the network, invoke Docker/SQL, or touch the installed Agent.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$sb=Join-Path ([IO.Path]::GetTempPath()) ('R62_update_test_'+[guid]::NewGuid().ToString('N'))
$passed=0
function Assert([bool]$ok,[string]$name) {
 if(-not $ok){throw ('TEST_FAILED:'+ $name)}
 $script:passed++
 Write-Output ('PASS='+$name)
}
function StrictVersion([string]$v) {
 if($v -cnotmatch '^3\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$'){throw 'INVALID_VERSION'}
 return [version]$v
}
function ValidateTarget([string]$current,[string]$target) {
 $a=StrictVersion $current
 $b=StrictVersion $target
 if($b -le $a){throw 'DOWNGRADE_OR_REPLAY'}
}
function SimulateCommit([string]$source,[string]$live,[string]$backup,[switch]$FailAfterWrite) {
 if(!(Test-Path -LiteralPath $source -PathType Leaf)){throw 'STAGED_MISSING'}
 $originalHash=(Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash
 Copy-Item -LiteralPath $live -Destination $backup -ErrorAction Stop
 $swapped=$false
 try {
  Copy-Item -LiteralPath $source -Destination $live -Force -ErrorAction Stop
  $swapped=$true
  if($FailAfterWrite){throw 'SIMULATED_STARTUP_FAILURE'}
  if((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash){throw 'VERIFY_FAILED'}
 }catch{
  if($swapped -or (Test-Path -LiteralPath $backup)) {
   Copy-Item -LiteralPath $backup -Destination $live -Force -ErrorAction Stop
  }
  if((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -ne $originalHash){throw 'ROLLBACK_FAILED'}
  throw
 }
}
try {
 New-Item -ItemType Directory -Path $sb -Force | Out-Null
 Assert ((StrictVersion '3.0.1').ToString() -eq '3.0.1') 'VERSION_PARSE'
 Assert ((StrictVersion '3.12.34').ToString() -eq '3.12.34') 'VERSION_NUMERIC'
 $blocked=$false;try{ValidateTarget '3.0.2' '3.0.1'}catch{if($_.Exception.Message -eq 'DOWNGRADE_OR_REPLAY'){$blocked=$true}}
 Assert $blocked 'DOWNGRADE_BLOCKED'
 $blocked=$false;try{ValidateTarget '3.0.2' '3.0.2'}catch{if($_.Exception.Message -eq 'DOWNGRADE_OR_REPLAY'){$blocked=$true}}
 Assert $blocked 'REPLAY_BLOCKED'
 ValidateTarget '3.0.9' '3.0.10'; Assert $true 'SEMVER_NOT_LEXICAL'
 $blocked=$false;try{StrictVersion '3.01.2'|Out-Null}catch{if($_.Exception.Message -eq 'INVALID_VERSION'){$blocked=$true}}
 Assert $blocked 'NONCANONICAL_VERSION_BLOCKED'
 $live=Join-Path $sb 'GuardianAgent.ps1'
 $stage=Join-Path $sb 'stage.ps1'
 $backup=Join-Path $sb 'previous.ps1'
 [IO.File]::WriteAllText($live,'old validated agent')
 [IO.File]::WriteAllText($stage,'new test agent')
 $blocked=$false
 try{SimulateCommit -source $stage -live $live -backup $backup -FailAfterWrite}catch{if($_.Exception.Message -eq 'SIMULATED_STARTUP_FAILURE'){$blocked=$true}}
 Assert $blocked 'SIMULATED_FAILURE_OBSERVED'
 Assert ([IO.File]::ReadAllText($live) -ceq 'old validated agent') 'ROLLBACK_RESTORED_OLD_AGENT'
 SimulateCommit -source $stage -live $live -backup $backup
 Assert ([IO.File]::ReadAllText($live) -ceq 'new test agent') 'SUCCESSFUL_STAGED_REPLACEMENT'
 Write-Output ('TESTS_PASSED='+$passed+'/9')
 Write-Output '[LIMIT] Mock tests only; no real Guardian restart or install validation.'
 Write-Output '[NAO_EXECUTADO] Docker, PostgreSQL, rede, update real'
} catch {
 Write-Output ('[BLOQUEADO] '+($_.Exception.Message -replace '[^A-Za-z0-9_:]','?'))
 exit 1
} finally {
 Remove-Item -LiteralPath $sb -Recurse -Force -ErrorAction SilentlyContinue
}
