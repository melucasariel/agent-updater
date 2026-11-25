# Guardian v3.3: disposable end-to-end lab combining sandbox swap + real child heartbeat.
# Does not install or restart the real Guardian, and does not touch the database or Docker.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\candidates\GuardianSupervisorSandbox-v3.2.ps1')
. (Join-Path $PSScriptRoot '..\candidates\GuardianHealthHandshake-v3.3.ps1')
$lab=Join-Path ([IO.Path]::GetTempPath()) ('R62_Health_Test_'+[guid]::NewGuid().ToString('N'))
$swapLab=Join-Path ([IO.Path]::GetTempPath()) ('R62_Supervisor_Test_'+[guid]::NewGuid().ToString('N'))
$old=Join-Path $swapLab 'GuardianAgent.ps1'
$candidate=Join-Path $swapLab 'candidate.ps1'
$backup=Join-Path $swapLab 'GuardianAgent.previous.ps1'
function WriteUtf8([string]$path,[string]$value){[IO.File]::WriteAllText($path,$value,(New-Object Text.UTF8Encoding($false)))}
function Check([bool]$ok,[string]$name){if(-not $ok){throw ('TEST_FAILED_'+$name)};Write-Output ('PASS='+$name)}
$child=@'
[CmdletBinding()]
param([string]$Challenge,[string]$ReceiptFile,[string]$Mode='Good')
$ErrorActionPreference='Stop'
if($Mode -eq 'Silent'){Start-Sleep -Seconds 15;exit}
$response=if($Mode -eq 'Wrong'){'invalid'}else{$Challenge}
$receipt=[ordered]@{challenge=$response;process_id=$PID;script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash}
[IO.File]::WriteAllText(($ReceiptFile+'.tmp'),($receipt|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
[IO.File]::Move(($ReceiptFile+'.tmp'),$ReceiptFile)
Start-Sleep -Seconds 15
'@
try{
 New-Item -Path $lab -ItemType Directory -Force|Out-Null
 New-Item -Path $swapLab -ItemType Directory -Force|Out-Null
 WriteUtf8 $old 'Write-Output "previous agent"'
 WriteUtf8 $candidate $child
 $oldHash=(Get-FileHash -LiteralPath $old -Algorithm SHA256).Hash
 $healthProbe={
  param($updatedFile,$expectedHash)
  $childInLab=Join-Path $lab 'HealthFixture.ps1'
  Copy-Item -LiteralPath $updatedFile -Destination $childInLab -Force
  if((Get-FileHash -LiteralPath $childInLab -Algorithm SHA256).Hash -ne $expectedHash){throw 'HEALTH_STAGE_MISMATCH'}
  $response=Test-R62SandboxChildHealth -LabRoot $lab -ChildFile $childInLab -Mode Good -TimeoutMs 5000
  return ($response -eq '[OK] CHILD_HEALTH_VERIFIED')
 }.GetNewClosure()
 $result=Invoke-R62SandboxSwap -LabRoot $swapLab -StagedFile $candidate -HealthProbe $healthProbe
 Check ($result -eq '[OK] SANDBOX_SWAPPED_AND_HEALTHY') 'SWAP_AFTER_REAL_PROCESS_HEALTH'
 Check ((Get-FileHash -LiteralPath $old -Algorithm SHA256).Hash -eq (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash) 'HEALTHY_BYTES_APPLIED'
 Remove-Item -LiteralPath $backup -Force
 WriteUtf8 $old 'Write-Output "previous agent"'
 $healthFailure={
  param($updatedFile,$expectedHash)
  $childInLab=Join-Path $lab 'HealthFixture.ps1'
  Copy-Item -LiteralPath $updatedFile -Destination $childInLab -Force
  $response=Test-R62SandboxChildHealth -LabRoot $lab -ChildFile $childInLab -Mode Wrong -TimeoutMs 5000
  return ($response -eq '[OK] CHILD_HEALTH_VERIFIED')
 }.GetNewClosure()
 $failed=$false
 try{Invoke-R62SandboxSwap -LabRoot $swapLab -StagedFile $candidate -HealthProbe $healthFailure|Out-Null}catch{$failed=($_.Exception.Message -eq 'HEALTH_CHALLENGE_MISMATCH')}
 Check $failed 'INVALID_CHILD_HANDSHAKE_BLOCKED'
 Check ((Get-FileHash -LiteralPath $old -Algorithm SHA256).Hash -eq $oldHash) 'REAL_HEALTH_FAILURE_ROLLBACK'
 Write-Output 'LAB_TESTS_DESIGNED=4'
 Write-Output '[LIMIT] Verified fixture process only; real Guardian heartbeat integration and runtime supervision pending.'
 Write-Output '[NAO_EXECUTADO] Guardian ativo, Docker, PostgreSQL, rede, update'
$global:LASTEXITCODE=0
}catch{
 $safe=[string]$_.Exception.Message -replace '[^A-Z0-9_]','?'
 Write-Output ('[BLOQUEADO] '+$safe);exit 1
}finally{
 Remove-Item -LiteralPath $lab -Recurse -Force -ErrorAction SilentlyContinue
 Remove-Item -LiteralPath $swapLab -Recurse -Force -ErrorAction SilentlyContinue
}
