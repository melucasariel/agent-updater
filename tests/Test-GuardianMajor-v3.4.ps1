# Offline Windows PowerShell 5.1 smoke tests, no GitHub requests, no installed Guardian touched.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$lab=Join-Path ([IO.Path]::GetTempPath()) ('R62MajorTest_'+[guid]::NewGuid().ToString('N'))
$prior=$env:LOCALAPPDATA
$source=Join-Path $PSScriptRoot '..\major\GuardianUpdater-v3.4.ps1'
$count=0
function Pass([bool]$condition,[string]$label) {
 if(-not $condition){throw ('FAILED_'+$label)}
 $script:count++
 Write-Output ('PASS='+$label)
}
try {
 if(!(Test-Path -LiteralPath $source)){throw 'UPDATER_SOURCE_MISSING'}
 New-Item -ItemType Directory -Path $lab -Force|Out-Null
 $env:LOCALAPPDATA=$lab
 $root=Join-Path $lab 'ROTA62_Guardian_AutoSend'
 New-Item -ItemType Directory -Path $root -Force|Out-Null
 $agent=Join-Path $root 'GuardianAgent_v3.ps1'
 [IO.File]::WriteAllText($agent,'Write-Output "LAB AGENT ONLY"')
 $before=(Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash
 $out=@(& $source -CheckOnly 2>&1)
 Pass ([string]::Join(' ',@($out)) -match 'UPDATES_DISABLED') 'NO_CONFIG_FAILS_CLOSED'
 Pass ((Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash -eq $before) 'NO_WRITE_ON_MISSING_CONFIG'
 $config=Join-Path $root 'update_source.json'
 [IO.File]::WriteAllText($config,'{"manifest_url":"","public_key_xml":""}')
 $out=@(& $source -Install 2>&1)
 Pass ([string]::Join(' ',@($out)) -match 'UPDATES_DISABLED') 'INSTALL_INERT_WITHOUT_TRUST'
 [IO.File]::WriteAllText($config,'{"manifest_url":"https://evil.invalid/release.json","public_key_xml":"test"}')
 $out=@(& $source -CheckOnly 2>&1)
 Pass ([string]::Join(' ',@($out)) -match 'FEED_URL_NOT_ALLOWED') 'UNTRUSTED_ORIGIN_REJECTED'
 [IO.File]::WriteAllText($config,'{"manifest_url":"https://github.com/melucasariel/agent-updater/releases/latest/download/release.json","public_key_xml":"test"}')
 $out=@(& $source -CheckOnly 2>&1)
 Pass ([string]::Join(' ',@($out)) -match 'PINNED_VERSION_MISSING') 'VERSION_PIN_REQUIRED'
 Pass ((Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash -eq $before) 'NO_AGENT_MUTATION'
 Pass (-not (Test-Path (Join-Path $root 'stop_v3.flag'))) 'NO_STOP_FLAG'
 Write-Output ('TESTS_PASSED='+$count+'/7')
 Write-Output '[LIMIT] CI smoke only; signed Release download and real Guardian restart remain untested.'
$global:LASTEXITCODE=0
} catch {
 Write-Output ('[BLOQUEADO] '+([string]$_.Exception.Message -replace '[^a-zA-Z0-9_]','?'))
 exit 1
} finally {
 $env:LOCALAPPDATA=$prior
 Remove-Item -LiteralPath $lab -Force -Recurse -ErrorAction SilentlyContinue
}
