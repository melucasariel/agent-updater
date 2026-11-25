# ROTA62 major 3.4 end-to-end Windows sandbox integration, no real Guardian/DB/Docker touched.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$base=Join-Path ([IO.Path]::GetTempPath()) ('R62MajorIntegration_'+[guid]::NewGuid().ToString('N'))
$oldEnv=$env:LOCALAPPDATA
$source=Join-Path $PSScriptRoot '..\major\Bootstrap-Major-v3.4.ps1'
$test=Join-Path $base 'Bootstrap-Major-Test.ps1'
function Check([bool]$valid,[string]$label){if(-not $valid){throw ('TEST_FAILED_'+$label)};Write-Output ('PASS='+$label)}
function WriteUtf8([string]$path,[string]$content){[IO.File]::WriteAllText($path,$content,(New-Object Text.UTF8Encoding($false)))}
try{
 New-Item -Path $base -ItemType Directory -Force|Out-Null
 $env:LOCALAPPDATA=$base
 $root=Join-Path $base 'ROTA62_Guardian_AutoSend'
 New-Item -Path $root -ItemType Directory -Force|Out-Null
 $agent=Join-Path $root 'GuardianAgent_v3.ps1'
 $updater=Join-Path $root 'GuardianUpdater.ps1'
 $labMutex='Local\R62_Guardian_Lab_'+[guid]::NewGuid().ToString('N')
 $legacy=@'
$ErrorActionPreference='Stop'
$root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$stop=Join-Path $root 'stop_v3.flag'
$mutex=New-Object Threading.Mutex($false,'Local\ROTA62_Guardian_V3_Instance')
if(-not $mutex.WaitOne(0)){exit 11}
function Event([string]$value){}
try{
 Event 'agent_started'
 while(-not (Test-Path -LiteralPath $stop)){Start-Sleep -Milliseconds 150}
}finally{try{$mutex.ReleaseMutex()}catch{};$mutex.Dispose()}
'@
 $legacy=$legacy.Replace('Local\ROTA62_Guardian_V3_Instance',$labMutex)
 WriteUtf8 $agent $legacy
 WriteUtf8 $updater "Write-Output 'legacy updater'"
 WriteUtf8 (Join-Path $root 'update_source.json') '{"manifest_url":"","public_key_xml":""}'
 WriteUtf8 (Join-Path $root 'signing-private.dpapi') 'CI-ONLY-DUMMY-NO-SECRETS'
 $rsa=New-Object Security.Cryptography.RSACryptoServiceProvider(3072)
 try {WriteUtf8 (Join-Path $root 'signing-public.xml') $rsa.ToXmlString($false)}
 finally {$rsa.Dispose()}
 $script=[IO.File]::ReadAllText($source)
 $aHash=(Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash
 $uHash=(Get-FileHash -LiteralPath $updater -Algorithm SHA256).Hash
 $script=$script.Replace('84F9440890F1DBB550F0C57833ECD485E685839B8323B995147759A4090F9CE8',$aHash)
 $script=$script.Replace('9BE00D02A49457AC3A05B732F6746174241B5C545B6131368DF436604A914E0E',$uHash)
 $script=$script.Replace('Local\ROTA62_Guardian_V3_Instance',$labMutex)
 WriteUtf8 $test $script
 $before=(Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash
 $result=@(& $test -DryRun 2>&1)
 Write-Output ('DIAG_DRYRUN='+((@($result) -join ' | ') -replace '[^A-Za-z0-9_\[\]=: |.-]','_'))
 Check ([string]::Join(' ',@($result)) -match 'MAJOR_DRY_RUN_PRECHECK') 'BRIDGE_DRY_RUN'
 Check ((Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash -eq $before) 'DRY_RUN_NO_REPLACE'
 $result=@(& $test 2>&1)
 Write-Output ('DIAG_INSTALL='+((@($result) -join ' | ') -replace '[^A-Za-z0-9_\[\]=: |.-]','_'))
 Check ([string]::Join(' ',@($result)) -match 'GUARDIAN_MAJOR_3_4_COM_HEALTH') 'MAJOR_AGENT_LIVE_HANDSHAKE'
 Check ((Get-Content -LiteralPath (Join-Path $root 'installed_version.txt') -Raw).Trim() -eq '3.4.0') 'INSTALLED_VERSION_COMMITTED'
 $newContent=Get-Content -LiteralPath $agent -Raw
 Check ($newContent.Contains('R62_HEALTH_V34_PROTOCOL')) 'NEW_AGENT_WITH_HEALTH'
 $cfg=Get-Content -LiteralPath (Join-Path $root 'update_source.json') -Raw|ConvertFrom-Json
 Check ([string]$cfg.manifest_url -eq 'https://github.com/melucasariel/agent-updater/releases/latest/download/release.json') 'TRUSTED_FEED_CONFIGURED'
 Check ([string]$cfg.public_key_xml -match '<RSAKeyValue>') 'PINNED_RSA_PUBLIC_KEY'
 Write-Output 'MAJOR_SANDBOX_TESTS_PASSED=7/7'
 Write-Output '[LIMIT] Test only uses disposable fixture; actual user installation and signed Releases not exercised.'
}catch{
 Write-Output ('[BLOQUEADO] '+([string]$_.Exception.Message -replace '[^A-Za-z0-9_]','?'))
 exit 1
}finally{
 try{
  $stop=Join-Path $base 'ROTA62_Guardian_AutoSend\stop_v3.flag'
  if(Test-Path -LiteralPath (Split-Path $stop)){[IO.File]::WriteAllText($stop,'stop')}
  Start-Sleep -Milliseconds 800
 }catch{}
 $env:LOCALAPPDATA=$oldEnv
 Remove-Item -LiteralPath $base -Recurse -Force -ErrorAction SilentlyContinue
}
