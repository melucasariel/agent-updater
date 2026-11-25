# ROTA62 Guardian - read-only trust diagnostics. Windows PowerShell 5.1.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Security -ErrorAction Stop
$root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$private=Join-Path $root 'signing-private.dpapi'
$public=Join-Path $root 'signing-public.xml'
$updater=Join-Path $root 'GuardianUpdater.ps1'
$agent=Join-Path $root 'GuardianAgent_v3.ps1'
$feed=Join-Path $root 'update_source.json'
$lines=New-Object System.Collections.Generic.List[string]
$lines.Add('=== GUARDIAN TRUST CHECK v1 ===')
try {
 if(!(Test-Path -LiteralPath $agent -PathType Leaf) -or !(Test-Path -LiteralPath $updater -PathType Leaf)){throw 'AGENT_V3_NAO_LOCALIZADO'}
 $lines.Add('[OK] AGENT_V3_PRESENTE')
 if(!(Test-Path -LiteralPath $private -PathType Leaf) -or !(Test-Path -LiteralPath $public -PathType Leaf)){throw 'PAR_DE_CHAVES_INCOMPLETO'}
 $wrapped=[IO.File]::ReadAllBytes($private)
 $plain=[Security.Cryptography.ProtectedData]::Unprotect($wrapped,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
 $rsaPriv=New-Object Security.Cryptography.RSACryptoServiceProvider
 $rsaPub=New-Object Security.Cryptography.RSACryptoServiceProvider
 try {
  $rsaPriv.PersistKeyInCsp=$false
  $rsaPub.PersistKeyInCsp=$false
  $rsaPriv.FromXmlString([Text.Encoding]::UTF8.GetString($plain))
  $rsaPub.FromXmlString([IO.File]::ReadAllText($public,[Text.Encoding]::UTF8))
  $msg=[Text.Encoding]::UTF8.GetBytes('ROTA62_GUARDIAN_LOCAL_KEY_PAIR_TEST')
  $sig=$rsaPriv.SignData($msg,'SHA256')
  if(-not $rsaPub.VerifyData($msg,'SHA256',$sig)){throw 'CHAVES_NAO_CORRESPONDEM'}
  $lines.Add('[OK] DPAPI_DESCRIPTOGRAFIA_LOCAL')
  $lines.Add('[OK] ASSINATURA_RSA_SHA256_LOCAL')
 } finally {
  [Array]::Clear($plain,0,$plain.Length)
  $rsaPriv.Dispose();$rsaPub.Dispose()
 }
 if(Test-Path -LiteralPath $feed -PathType Leaf){
  $cfg=Get-Content -LiteralPath $feed -Raw | ConvertFrom-Json
  if([string]::IsNullOrWhiteSpace([string]$cfg.manifest_url) -or [string]::IsNullOrWhiteSpace([string]$cfg.public_key_xml)){
   $lines.Add('[OK] AUTOUPDATE_DESATIVADO')
  } else {
   $lines.Add('[ATENCAO] FEED_CONFIGURADO_NAO_VERIFICADO')
  }
 } else { $lines.Add('[OK] AUTOUPDATE_SEM_FEED') }
 $lines.Add('[NAO EXECUTADO] Docker, SQL, escrita, update ou rede')
 $lines.Add('TRUST_CHECK=PASS')
} catch {
 $lines.Add('[BLOQUEADO] TRUST_CHECK=FAIL')
 $msg=[string]$_.Exception.Message
 if($msg -in @('AGENT_V3_NAO_LOCALIZADO','PAR_DE_CHAVES_INCOMPLETO','CHAVES_NAO_CORRESPONDEM')){$lines.Add('MOTIVO='+$msg)}
 else{$lines.Add('MOTIVO=ERRO_LOCAL_NAO_DETALHADO')}
}
$report=$lines -join "`n"
Write-Output $report
try{Set-Clipboard -Value $report -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{Write-Output '[INFO] SEM_CLIPBOARD'}
if($report -match 'TRUST_CHECK=FAIL'){exit 1}
