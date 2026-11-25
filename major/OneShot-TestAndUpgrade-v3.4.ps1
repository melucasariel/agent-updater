# ROTA62 Guardian major 3.4 — verify 11 files, run six Windows suites, migrate only if all pass.
[CmdletBinding()]
param([switch]$OnlyTests)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$commit='1574dd707c4e7ff3d0627a2771686be26e4efcff'
$files=@(
 @{path='candidates/GuardianUpdatePolicy-v3.1.ps1';sha='ED7BD793FC95A351B8A86C7CA2FD3EC09747C6C004C68960F5268A2D67AE4DEA'},
 @{path='candidates/GuardianSupervisorSandbox-v3.2.ps1';sha='6AD9D637137984FD73D9D2DF4A7CE0B10F2F2320335DE2B6B92B5E22F8F3EEE3'},
 @{path='candidates/GuardianHealthHandshake-v3.3.ps1';sha='13AA9BFCF1408542EA17013382A19F11AD14331AED83CB194E96BDCC3186A0DB'},
 @{path='tests/Test-GuardianUpdatePolicy-v3.1.ps1';sha='7318392140FA3E0810638D871867C1641525E91727E6745011073E7D551DC4C8'},
 @{path='tests/Test-GuardianSupervisorSandbox-v3.2.ps1';sha='253FB560E1D4CDF8F35DABBC4C6A0F1B1C6BB59401763253CF059C6827C2F8AD'},
 @{path='tests/Test-GuardianHealthHandshake-v3.3.ps1';sha='E521E5366B87A9843F6508A691927CEBDCCE31A1D115069B40981E3FFF23605F'},
 @{path='tests/Test-GuardianSupervisorHandshake-v3.3.ps1';sha='171A1A6825372C7DDA500367C4F139ABB5319EC4DFC04DDB56488D5A8D97E9B4'},
 @{path='tests/Test-GuardianMajor-v3.4.ps1';sha='D0D5A220379FE3387C4DB2D89122B368D0B5E50B5EFA3C0FAF4C0B58DDAB361F'},
 @{path='tests/Test-GuardianMajorIntegration-v3.4.ps1';sha='75BEA056202149EC3DC626320C8576D5341DCC39EF0C79E907394D64AFEF4725'},
 @{path='major/GuardianUpdater-v3.4.ps1';sha='7DAFA8779E0ABD3139934579033D27FD7BB71691C3A3178E8C224687A9FF20E2'},
 @{path='major/Bootstrap-Major-v3.4.ps1';sha='4529BFCB482EAE370ECCE4FCBD01D6D79BE070306DDB43A3BC51CE79B1164266'}
)
$tests=@(
 @{path='tests/Test-GuardianMajor-v3.4.ps1';ok='TESTS_PASSED=7/7'},
 @{path='tests/Test-GuardianUpdatePolicy-v3.1.ps1';ok='TESTS_DESIGNED=11'},
 @{path='tests/Test-GuardianSupervisorSandbox-v3.2.ps1';ok='TESTS_DESIGNED=10'},
 @{path='tests/Test-GuardianHealthHandshake-v3.3.ps1';ok='TESTS_PASSED=6/6'},
 @{path='tests/Test-GuardianSupervisorHandshake-v3.3.ps1';ok='LAB_TESTS_DESIGNED=4'},
 @{path='tests/Test-GuardianMajorIntegration-v3.4.ps1';ok='MAJOR_SANDBOX_TESTS_PASSED=7/7'}
)
$dir=Join-Path ([IO.Path]::GetTempPath()) ('R62_MAJOR_ONESHOT_'+[guid]::NewGuid().ToString('N'))
$report=New-Object System.Collections.Generic.List[string]
$report.Add('=== ROTA62 GUARDIAN v3.4 ONE-SHOT ===')
$success=$false
try {
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 New-Item -Path $dir -ItemType Directory -Force|Out-Null
 foreach($item in $files){
  $rel=[string]$item.path
  if($rel -notmatch '^(major|candidates|tests)/[A-Za-z0-9_.-]+[.]ps1$'){throw 'FILE_PATH_BLOCKED'}
  $target=Join-Path $dir ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
  $folder=Split-Path -Parent $target
  if(!(Test-Path -LiteralPath $folder)){New-Item -Path $folder -ItemType Directory -Force|Out-Null}
  $url='https://raw.githubusercontent.com/melucasariel/agent-updater/'+$commit+'/'+$rel
  Invoke-WebRequest -Uri $url -OutFile $target -UseBasicParsing -TimeoutSec 30
  if((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -cne [string]$item.sha){throw 'SHA256_PIN_MISMATCH'}
  $tokens=$null;$errors=$null
  [void][Management.Automation.Language.Parser]::ParseFile($target,[ref]$tokens,[ref]$errors)
  if(@($errors).Count -gt 0){throw 'POWERSHELL_PARSE_ERROR'}
 }
 $report.Add('[OK] Arquivos verificados: 11/11')
 foreach($item in $tests){
  $test=Join-Path $dir (([string]$item.path) -replace '/', [IO.Path]::DirectorySeparatorChar)
  $output=@(& $test 2>&1)
  if(@($output|Where-Object {([string]$_) -ceq [string]$item.ok}).Count -ne 1){throw ('TEST_FAILED_'+([IO.Path]::GetFileNameWithoutExtension($test) -replace '[^A-Za-z0-9_-]','_'))}
  $report.Add('[OK] '+[string]$item.ok)
 }
 $report.Add('[APROVADO] Seis suites Windows isoladas')
 if($OnlyTests){$report.Add('[MODO] Somente testes; nenhum arquivo instalado')}
 else{
  $installer=Join-Path $dir 'major/Bootstrap-Major-v3.4.ps1'
  $dry=@(& $installer -DryRun 2>&1)
  if(@($dry|Where-Object {([string]$_) -match 'MAJOR_DRY_RUN_PRECHECK'}).Count -ne 1){throw 'LOCAL_PREFLIGHT_BLOCKED'}
  $report.Add('[OK] Preflight local')
  $installed=@(& $installer 2>&1)
  if(@($installed|Where-Object {([string]$_) -match 'GUARDIAN_MAJOR_3_4_COM_HEALTH'}).Count -ne 1){throw 'LOCAL_INSTALL_NOT_APPROVED'}
  $report.Add('[APROVADO] Agent v3.4 com verificacao de saude')
  $report.Add('[OK] Feed de updates assinados configurado')
 }
 $success=$true
}catch {
 $reason=[string]$_.Exception.Message
 if($reason -notmatch '^[A-Za-z0-9_-]+$'){$reason='REDACTED_ERROR'}
 $report.Add('[BLOQUEADO] '+$reason)
 $report.Add('[SEGURANCA] Nenhuma continuidade automatica apos falha')
}finally{
 Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
 $text=$report -join [Environment]::NewLine
 Write-Output $text
 try{Set-Clipboard -Value $text -ErrorAction Stop;Write-Output '[OK] Relatorio copiado automaticamente'}catch{}
}
if(-not $success){exit 1}
