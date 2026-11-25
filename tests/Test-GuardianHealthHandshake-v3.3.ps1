# Self-contained disposable Windows PowerShell lab for v3.3 heartbeat.
# Runs only its own temporary fixture, not the installed Guardian.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\candidates\GuardianHealthHandshake-v3.3.ps1')
$lab=Join-Path ([IO.Path]::GetTempPath()) ('R62_Health_Test_'+[guid]::NewGuid().ToString('N'))
$fixture=Join-Path $lab 'HealthFixture.ps1'
$passed=0
function Pass([bool]$v,[string]$name){if(-not $v){throw ('TEST_FAILED_'+$name)};$script:passed++;Write-Output ('PASS='+$name)}
function ExpectFailure([string]$reason,[scriptblock]$test){
 $observed=$false
 try { & $test | Out-Null } catch { $observed=($_.Exception.Message -ceq $reason) }
 Pass $observed $reason
}
$child=@'
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$Challenge,
 [Parameter(Mandatory=$true)][string]$ReceiptFile,
 [ValidateSet('Good','Wrong','Silent')][string]$Mode='Good'
)
$ErrorActionPreference='Stop'
if($Mode -eq 'Silent') { Start-Sleep -Seconds 15; exit }
$answer=if($Mode -eq 'Wrong'){'incorrect-challenge'}else{$Challenge}
$ack=[ordered]@{
 challenge=$answer
 process_id=$PID
 script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
}
$tmp=$ReceiptFile+'.tmp'
[IO.File]::WriteAllText($tmp,($ack|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
[IO.File]::Move($tmp,$ReceiptFile)
Start-Sleep -Seconds 15
'@
try {
 New-Item -Path $lab -ItemType Directory -Force | Out-Null
 [IO.File]::WriteAllText($fixture,$child,(New-Object Text.UTF8Encoding($false)))
 $result=Test-R62SandboxChildHealth -LabRoot $lab -ChildFile $fixture -Mode Good -TimeoutMs 5000
 Pass ($result -ceq '[OK] CHILD_HEALTH_VERIFIED') 'REAL_PROCESS_HEALTHY'
 ExpectFailure 'HEALTH_CHALLENGE_MISMATCH' {Test-R62SandboxChildHealth -LabRoot $lab -ChildFile $fixture -Mode Wrong -TimeoutMs 5000}
 ExpectFailure 'HEALTH_TIMEOUT' {Test-R62SandboxChildHealth -LabRoot $lab -ChildFile $fixture -Mode Silent -TimeoutMs 900}
 ExpectFailure 'LAB_ROOT_NOT_ALLOWED' {Test-R62SandboxChildHealth -LabRoot $env:LOCALAPPDATA -ChildFile $fixture -Mode Good}
 ExpectFailure 'CHILD_OUTSIDE_LAB' {Test-R62SandboxChildHealth -LabRoot $lab -ChildFile $PSCommandPath -Mode Good}
 Pass ($passed -eq 5) 'EXPECTED_TEST_COUNT'
 Write-Output ('TESTS_PASSED='+$passed+'/6')
 Write-Output '[LIMIT] Fixture subprocess, NOT installed Guardian; no real supervisor rollback or installation.'
 Write-Output '[NAO_EXECUTADO] Guardian ativo, Docker, SQL, rede, update remoto'
$global:LASTEXITCODE=0
} catch {
 $safe=([string]$_.Exception.Message -replace '[^A-Z0-9_]','?')
 Write-Output ('[BLOQUEADO] '+$safe)
 exit 1
} finally {
 Remove-Item -LiteralPath $lab -Force -Recurse -ErrorAction SilentlyContinue
}
