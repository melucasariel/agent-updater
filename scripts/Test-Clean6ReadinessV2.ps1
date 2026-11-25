# ROTA62 CLEAN6 v2 - read-only local discovery and readiness.
# Never decrypts archives, accesses secrets, starts/stops containers or runs SQL.
[CmdletBinding()]
param(
 [string]$AuditScriptPath='',
 [switch]$NoClipboard
)
$ErrorActionPreference='Stop'
$lines=New-Object 'System.Collections.Generic.List[string]'
$lines.Add('=== ROTA62 CLEAN6 READINESS V2 ===')
$lines.Add('MODE=READ_ONLY_NO_PASSWORD_NO_SQL_NO_RESTORE')
function Add([string]$key,[string]$value){
 if($key -notmatch '^[A-Z0-9_]+$'){throw 'Invalid report key'}
 $lines.Add($key+'='+$value)
}
try {
 $roots=@($env:TEMP, $env:LOCALAPPDATA, (Join-Path $env:USERPROFILE 'Documents')) | Where-Object {$_ -and (Test-Path -LiteralPath $_ -PathType Container)} | Select-Object -Unique
 $names=@('R62-Clean6-Semantics-v141.mjs','R62-Clean6-Semantics-v14.mjs','R62-Clean6-Semantics.mjs')
 $candidates=New-Object 'System.Collections.Generic.List[string]'
 if($AuditScriptPath){
  if(Test-Path -LiteralPath $AuditScriptPath -PathType Leaf){$candidates.Add([IO.Path]::GetFullPath($AuditScriptPath))}
 } else {
  foreach($root in $roots) {
   foreach($name in $names) {
    $direct=Join-Path $root $name
    if(Test-Path -LiteralPath $direct -PathType Leaf){$candidates.Add($direct)}
   }
   # Bounded depth, only match exact audit filenames; no file-content search.
   try {
    foreach($dir in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue | Select-Object -First 80)){
     foreach($name in $names){
      $p=Join-Path $dir.FullName $name
      if(Test-Path -LiteralPath $p -PathType Leaf){$candidates.Add($p)}
     }
    }
   } catch {}
  }
 }
 $found=@($candidates | Select-Object -Unique)
 Add 'AUDIT_CANDIDATES_FOUND' ([string]$found.Count)
 $node=Get-Command node -ErrorAction SilentlyContinue
 Add 'NODE_AVAILABLE' ([string][bool]$node)
 $docker=Get-Command docker -ErrorAction SilentlyContinue
 Add 'DOCKER_AVAILABLE' ([string][bool]$docker)
 if($docker){
  $null=& docker info --format '{{.ServerVersion}}' 2>$null
  $ok=$LASTEXITCODE -eq 0
  Add 'DOCKER_ENGINE_OK' ([string]$ok)
  if($ok){
   $ids=@(& docker ps -q 2>$null)
   if($LASTEXITCODE -eq 0){Add 'ACTIVE_CONTAINER_COUNT' ([string]$ids.Count)}
  }
 }
 $max=[Math]::Min($found.Count,5)
 for($i=0;$i -lt $max;$i++){
  $path=$found[$i]
  $item=Get-Item -LiteralPath $path
  Add ('AUDIT_'+($i+1)+'_SIZE_BYTES') ([string]$item.Length)
  Add ('AUDIT_'+($i+1)+'_SHA256') ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash)
  if($node){
   $null=& node --check $path 2>$null
   Add ('AUDIT_'+($i+1)+'_NODE_SYNTAX_OK') ([string]($LASTEXITCODE -eq 0))
  }
 }
 Add 'AUDIT_NAMES_OR_PATHS_REDACTED' 'YES'
 Add 'PRODUCTION_DATABASE_UNTOUCHED' 'YES'
 Add 'ROLLBACK_NOT_EXECUTED' 'YES'
 Add 'SEMANTIC_AUDIT_NOT_EXECUTED' 'YES'
 Add 'CHAT_AUTORETURN_UNAVAILABLE' 'YES'
} catch {
 Add 'DIAGNOSTIC_PARTIAL' 'YES'
 Add 'ERROR_DETAILS_REDACTED' 'YES'
}
$lines.Add('END_REPORT_OK')
$report=$lines -join [Environment]::NewLine
Write-Output $report
if(-not $NoClipboard){try { Set-Clipboard -Value $report -ErrorAction Stop }catch{}}
