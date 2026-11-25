# ROTA62 Guardian AES authenticated verification launcher v0.4
# Windows PowerShell 5.1, Node >=20. Reads DPAPI-backed file pointer. No DB calls.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
Add-Type -AssemblyName System.Security
$root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$pointer=Join-Path $root 'backup_selection.dpapi'
$manifestPath=Join-Path $root 'selected_backup_manifest.json'
$scriptUrl='https://raw.githubusercontent.com/melucasariel/agent-updater/16186a7b06200eaf1708717d1a61f988ccbcf571/backup/ROTA62_VerifyAES_v0.4.mjs'
$scriptSha='055FEC5FAE55394CF496DB75426D263A5A658546FCBCE95C81D6F8A6DF9C6928'
$expectedSha='35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA'
$stage='INIT'
$temp=$null
$secretBytes=$null
$ranVerifier=$false
try{
 $stage='NODE'
 $node=Get-Command node -ErrorAction SilentlyContinue
 if(!$node){throw 'NODE_NOT_INSTALLED'}
 $versionText=(& node --version 2>$null)
 if($LASTEXITCODE -ne 0 -or [string]$versionText -notmatch '^v(\d+)\.'){throw 'NODE_VERSION_UNAVAILABLE'}
 if([int]$Matches[1] -lt 20){throw 'NODE_20_REQUIRED'}
 $stage='POINTER'
 if(!(Test-Path -LiteralPath $pointer -PathType Leaf)){throw 'DPAPI_BACKUP_POINTER_MISSING'}
 $secretBytes=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($pointer),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
 $path=[Text.Encoding]::UTF8.GetString($secretBytes)
 [Array]::Clear($secretBytes,0,$secretBytes.Length)
 $secretBytes=$null
 if([string]::IsNullOrWhiteSpace($path) -or [IO.Path]::GetExtension($path) -cne '.r62db'){throw 'BACKUP_POINTER_INVALID'}
 if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw 'BACKUP_NOT_AVAILABLE'}
 $stage='SOURCE'
 if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $expectedSha){throw 'KNOWN_BACKUP_HASH_MISMATCH'}
 if((Get-Item -LiteralPath $path).Length -ne 5287976){throw 'KNOWN_BACKUP_SIZE_MISMATCH'}
 if(!(Test-Path -LiteralPath $manifestPath -PathType Leaf)){throw 'LOCAL_MANIFEST_MISSING'}
 $manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json
 if([string]$manifest.file_sha256 -cne $expectedSha.ToLowerInvariant()){throw 'MANIFEST_SHA256_MISMATCH'}
 if([bool]$manifest.aes_authentication_tested){throw 'MANIFEST_ALREADY_MARKED_AES_TESTED'}
 $stage='DOWNLOADING'
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $temp=Join-Path $env:TEMP ('ROTA62-VerifyAES-'+[guid]::NewGuid().ToString('N')+'.mjs')
 Invoke-WebRequest -Uri $scriptUrl -OutFile $temp -UseBasicParsing -TimeoutSec 30
 if((Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash -cne $scriptSha){throw 'NODE_SCRIPT_HASH_MISMATCH'}
 $stage='SELFTEST'
 $test=@(& node $temp --selftest 2>$null)
 if($LASTEXITCODE -ne 0 -or @($test|Where-Object{$_ -ceq 'AES_SELFTEST=PASS'}).Count -ne 1){throw 'AES_SELFTEST_FAILED'}
 Write-Output '[OK] AES_SELFTEST_PASSED'
 Write-Output '[INFO] A senha solicitada a seguir e a senha de criptografia do backup. Ela nao sera salva nem copiada.'
 $stage='AUTHENTICATION'
 $ranVerifier=$true
 & node $temp $path
 if($LASTEXITCODE -ne 0){exit 1}
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]+$'){$reason='LOCAL_VERIFIER_ERROR_REDACTED'}
 $report='=== ROTA62 BACKUP AES VERIFY v0.4 ==='+[Environment]::NewLine+'[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason
 Write-Output $report
 try{Set-Clipboard -Value $report -ErrorAction Stop}catch{}
 exit 1
}finally{
 if($secretBytes){[Array]::Clear($secretBytes,0,$secretBytes.Length)}
 if($temp){Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue}
}
