# ROTA62 Guardian - Portable Backup Readiness Inventory v0.1
# Windows PowerShell 5.1; read only. Never reads secrets or database rows.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 BACKUP READINESS v0.1 ===')
$report.Add('[MODO] INVENTARIO_LOCAL_SOMENTE_LEITURA')
$allGood=$true
function AddCheck([string]$name,[string]$status) {
 $report.Add($name+'='+$status)
}
function SafeCommandVersion([string]$command,[string[]]$arguments) {
 if(-not (Get-Command $command -ErrorAction SilentlyContinue)){return 'AUSENTE'}
 try {
  $o=@(& $command @arguments 2>$null)
  if($LASTEXITCODE -ne 0){return 'INSTALADO_MAS_ERRO'}
  return 'DISPONIVEL'
 }catch{return 'INSTALADO_MAS_ERRO'}
}
try {
 # Physical inventory only; never searches entire disk or external mounts.
 $roots=@(
  (Join-Path $env:USERPROFILE 'Documents'),
  (Join-Path $env:USERPROFILE 'Downloads'),
  'D:\ROTA62_GUARDIAN',
  'C:\ROTA62_GUARDIAN'
 )|Select-Object -Unique
 $found=New-Object 'System.Collections.Generic.List[object]'
 foreach($root in $roots){
  if(-not (Test-Path -LiteralPath $root -PathType Container)){continue}
  # Single level plus known dedicated output folders. No recursive scan.
  $dirs=@($root)
  foreach($name in @('Backups','Backup','backup','backups','output','exports')){
   $p=Join-Path $root $name
   if(Test-Path -LiteralPath $p -PathType Container){$dirs+=$p}
  }
  foreach($dir in ($dirs|Select-Object -Unique)){
   foreach($item in @(Get-ChildItem -LiteralPath $dir -Filter '*.r62db' -File -ErrorAction SilentlyContinue)){
    if(-not @($found|Where-Object {$_.FullName -ceq $item.FullName}).Count){[void]$found.Add($item)}
   }
  }
 }
 if($found.Count -eq 0){
  AddCheck 'R62DB' 'NAO_LOCALIZADO_NOS_DIRETORIOS_LIMITADOS'
  $report.Add('[NOTA] Arquivo pode estar em HD externo, pasta ou subpasta nao pesquisada')
 }else{
  AddCheck 'R62DB' ('LOCALIZADO_QTD_'+$found.Count)
  $nonempty=@($found|Where-Object {$_.Length -gt 128})
  AddCheck 'R62DB_ARQUIVOS_NAO_VAZIOS' ('QTD_'+$nonempty.Count)
  $report.Add('[LIMITE] Existencia e tamanho nao comprovam autenticidade AES ou restaurabilidade')
 }
 $guardian=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
 AddCheck 'GUARDIAN_AGENT' $(if(Test-Path -LiteralPath (Join-Path $guardian 'GuardianAgent_v3.ps1') -PathType Leaf){'PRESENTE'}else{'AUSENTE'})
 AddCheck 'GUARDIAN_UPDATER' $(if(Test-Path -LiteralPath (Join-Path $guardian 'GuardianUpdater.ps1') -PathType Leaf){'PRESENTE'}else{'AUSENTE'})
 $versionFile=Join-Path $guardian 'installed_version.txt'
 if(Test-Path -LiteralPath $versionFile -PathType Leaf){
  $v=([IO.File]::ReadAllText($versionFile)).Trim()
  if($v -match '^3\.[0-9]{1,4}\.[0-9]{1,4}$'){AddCheck 'GUARDIAN_VERSION' $v}else{AddCheck 'GUARDIAN_VERSION' 'INVALIDA'}
 }else{AddCheck 'GUARDIAN_VERSION' 'INDEFINIDA'}
 foreach($item in @(@('DOCKER','docker',@('--version')), @('SUPABASE_CLI','supabase',@('--version')), @('PSQL','psql',@('--version')), @('PG_DUMP','pg_dump',@('--version')), @('PG_RESTORE','pg_restore',@('--version')), @('GITHUB_CLI','gh',@('--version')))){
  AddCheck $item[0] (SafeCommandVersion $item[1] $item[2])
 }
 # Read-only status of known disposable lab containers; do not inspect databases or secrets.
 if(Get-Command docker -ErrorAction SilentlyContinue){
  foreach($c in @('rota62_guardian_fifth_pg','rota62_guardian_lab5_dispatch_v012','supabase_db_ROTA62_TESTE_SUPABASE')){
   try{
    $state=@(& docker inspect $c --format '{{.State.Status}}' 2>$null)
    if($LASTEXITCODE -eq 0 -and @($state).Count -gt 0){
     AddCheck ('LAB_CONTAINER_'+$c) ([string]$state[0]).ToUpperInvariant()
    }else{AddCheck ('LAB_CONTAINER_'+$c) 'NAO_LOCALIZADO'}
   }catch{AddCheck ('LAB_CONTAINER_'+$c) 'NAO_CONSULTAVEL'}
  }
 }
 $report.Add('[LIMITE] Nao houve dump, restauracao, inventario de Storage ou acesso ao Supabase remoto')
 $report.Add('[LIMITE] Secrets e senhas nao foram lidos; conteudo do banco nao foi consultado')
 $report.Add('[PROXIMO] Selecionar backup real, validar AES e criar manifesto sem secrets')
 $report.Add('[CONCLUIDO] INVENTARIO_SOMENTE_LEITURA')
}catch{
 $report.Add('[BLOQUEADO] INVENTARIO_ERRO_LOCAL')
 $allGood=$false
}finally{
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $allGood){exit 1}
