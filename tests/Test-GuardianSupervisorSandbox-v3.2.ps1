# Offline only. Creates and removes a disposable test directory under TEMP.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\candidates\GuardianSupervisorSandbox-v3.2.ps1')
$lab=Join-Path ([IO.Path]::GetTempPath()) ('R62_Supervisor_Test_'+[guid]::NewGuid().ToString('N'))
$good=Join-Path $lab 'good.ps1'
$bad=Join-Path $lab 'bad.ps1'
$live=Join-Path $lab 'GuardianAgent.ps1'
$prev=Join-Path $lab 'GuardianAgent.previous.ps1'
function WriteUtf8([string]$p,[string]$v){[IO.File]::WriteAllText($p,$v,(New-Object Text.UTF8Encoding($false)))}
function Assert([bool]$v,[string]$n){if(-not $v){throw ('TEST_FAILED_'+$n)};Write-Output ('PASS='+$n)}
try{
 New-Item -Path $lab -ItemType Directory -Force|Out-Null
 WriteUtf8 $live 'Write-Output "OLD"'
 WriteUtf8 $good 'Write-Output "NEW"'
 WriteUtf8 $bad 'if('
 $oldHash=(Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash
 $result=Invoke-R62SandboxSwap -LabRoot $lab -StagedFile $good -HealthProbe {param($p,$h) ((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -eq $h)}
 Assert ($result -eq '[OK] SANDBOX_SWAPPED_AND_HEALTHY') 'GOOD_CANDIDATE'
 Assert ([IO.File]::ReadAllText($live) -like '*NEW*') 'NEW_BYTES_COMMITTED'
 Assert ((Get-FileHash -LiteralPath $prev -Algorithm SHA256).Hash -eq $oldHash) 'BACKUP_VERIFIED'
 Remove-Item $prev -Force
 $newHash=(Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash
 $threw=$false
 try{Invoke-R62SandboxSwap -LabRoot $lab -StagedFile $good -HealthProbe {$true}|Out-Null}catch{$threw=($_.Exception.Message -eq 'REPLAY_SAME_BYTES')}
 Assert $threw 'REPLAY_BLOCKED'
 WriteUtf8 $live 'Write-Output "OLD"'
 $threw=$false
 try{Invoke-R62SandboxSwap -LabRoot $lab -StagedFile $bad -HealthProbe {$true}|Out-Null}catch{$threw=($_.Exception.Message -eq 'STAGE_SYNTAX_ERROR')}
 Assert $threw 'BAD_POWERSHELL_BLOCKED'
 WriteUtf8 $live 'Write-Output "OLD"'
 Remove-Item $prev -Force -ErrorAction SilentlyContinue
 $threw=$false
 try{Invoke-R62SandboxSwap -LabRoot $lab -StagedFile $good -HealthProbe {$false}|Out-Null}catch{$threw=($_.Exception.Message -eq 'HEALTH_HANDSHAKE_FAILED')}
 Assert $threw 'HEALTH_FAILURE_DETECTED'
 Assert ((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -eq $oldHash) 'HEALTH_FAILURE_ROLLBACK'
 Remove-Item $prev -Force -ErrorAction SilentlyContinue
 $threw=$false
 try{Invoke-R62SandboxSwap -LabRoot $lab -StagedFile $good -HealthProbe {$true} -SimulateCrash|Out-Null}catch{$threw=($_.Exception.Message -eq 'SIMULATED_STARTUP_FAILURE')}
 Assert $threw 'CRASH_DETECTED'
 Assert ((Get-FileHash -LiteralPath $live -Algorithm SHA256).Hash -eq $oldHash) 'CRASH_ROLLBACK'
 $threw=$false
 try{Invoke-R62SandboxSwap -LabRoot $env:LOCALAPPDATA -StagedFile $good -HealthProbe {$true}|Out-Null}catch{$threw=$true}
 Assert $threw 'LIVE_DIRECTORY_BLOCKED'
 Write-Output 'TESTS_DESIGNED=10'
 Write-Output '[LIMIT] In-memory health callback, not yet a real Agent heartbeat.'
 Write-Output '[NAO_EXECUTADO] Installed Guardian, Docker, PostgreSQL, HTTP, remote update'
$global:LASTEXITCODE=0
}catch{
 $safe=[string]$_.Exception.Message -replace '[^A-Z0-9_]','?'
 Write-Output ('[BLOQUEADO] '+$safe);exit 1
}finally{
 Remove-Item -LiteralPath $lab -Force -Recurse -ErrorAction SilentlyContinue
}
