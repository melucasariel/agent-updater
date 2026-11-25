# Windows PowerShell 5.1 CI: validate canary ZIP + RSA signature locally, never publish or modify real Guardian.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security
$old=$env:LOCALAPPDATA
$lab=Join-Path ([IO.Path]::GetTempPath()) ('R62_Canary_Test_'+[guid]::NewGuid().ToString('N'))
$script=Join-Path $PSScriptRoot '..\releases\BuildAndPublish-GuardianCanary-v3.4.1.ps1'
try{
 $env:LOCALAPPDATA=$lab
 $root=Join-Path $lab 'ROTA62_Guardian_AutoSend'
 New-Item -ItemType Directory -Path $root -Force | Out-Null
 $agent='param([string]$GuardianChallenge="") # R62_HEALTH_V34_PROTOCOL'+[Environment]::NewLine+"[void]@{version='3.4.0'}"
 [IO.File]::WriteAllText((Join-Path $root 'GuardianAgent_v3.ps1'),$agent,(New-Object Text.UTF8Encoding($false)))
 [IO.File]::WriteAllText((Join-Path $root 'installed_version.txt'),'3.4.0')
 $rsa=New-Object System.Security.Cryptography.RSACryptoServiceProvider(3072)
 try{
  $rsa.PersistKeyInCsp=$false
  $pub=$rsa.ToXmlString($false)
  $key=[Text.Encoding]::UTF8.GetBytes($rsa.ToXmlString($true))
  try{
   $dpapi=[Security.Cryptography.ProtectedData]::Protect($key,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
   [IO.File]::WriteAllBytes((Join-Path $root 'signing-private.dpapi'),$dpapi)
  }finally{[Array]::Clear($key,0,$key.Length)}
 }finally{$rsa.Dispose()}
 [IO.File]::WriteAllText((Join-Path $root 'signing-public.xml'),$pub,(New-Object Text.UTF8Encoding($false)))
 $config=[ordered]@{manifest_url='https://github.com/melucasariel/agent-updater/releases/latest/download/release.json';public_key_xml=$pub}
 [IO.File]::WriteAllText((Join-Path $root 'update_source.json'),($config|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
 $out=@(& $script 2>&1)
 $out|Write-Output
 foreach($expected in @('[OK] CANARY_ZIP_SINGLE_ENTRY','[OK] LOCAL_RSA_SHA256_SIGN_AND_VERIFY','[MODO] PREPARAR_APENAS; NAO_PUBLICADO')){
  if(-not (@($out|Where-Object{([string]$_) -ceq $expected}).Count -eq 1)){throw 'LOCAL_CANARY_TEST_FAILED'}
 }
 Write-Output 'CANARY_OFFLINE_TEST=PASS'
}catch{
 Write-Output '[BLOQUEADO] CANARY_OFFLINE_TEST_FAIL'
 exit 1
}finally{
 $env:LOCALAPPDATA=$old
 Remove-Item -LiteralPath $lab -Force -Recurse -ErrorAction SilentlyContinue
}
