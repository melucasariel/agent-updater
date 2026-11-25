# ROTA62 CLEAN6 — guarded, read-only readiness diagnostic.
# Never opens encrypted backups, asks a password, runs SQL, or changes Docker.
[CmdletBinding()]
param(
  [string]$AuditScriptPath=(Join-Path $env:TEMP 'R62-Clean6-Semantics-v141.mjs'),
  [switch]$SkipDocker
)
$ErrorActionPreference='Stop'
$lines=[System.Collections.Generic.List[string]]::new()
$lines.Add('=== ROTA62 CLEAN6 READINESS V1 ===')
$lines.Add('MODE=READ_ONLY_NO_PASSWORD_NO_SQL_NO_RESTORE')
try {
  $node=Get-Command node -ErrorAction SilentlyContinue
  $lines.Add('NODE_AVAILABLE='+[bool]$node)
  $docker=Get-Command docker -ErrorAction SilentlyContinue
  $lines.Add('DOCKER_AVAILABLE='+[bool]$docker)
  $lines.Add('DOCKER_CHECK_SKIPPED='+[bool]$SkipDocker)
  if($docker -and -not $SkipDocker) {
    $null=& docker info --format '{{.ServerVersion}}' 2>$null
    $ok=($LASTEXITCODE -eq 0)
    $lines.Add('DOCKER_ENGINE_OK='+$ok)
    if($ok) {
      $ids=@(& docker ps -q 2>$null)
      if($LASTEXITCODE -eq 0){$lines.Add('ACTIVE_CONTAINER_COUNT='+$ids.Count)}
      else{$lines.Add('ACTIVE_CONTAINER_COUNT=UNAVAILABLE')}
    }
  }
  $exists=Test-Path -LiteralPath $AuditScriptPath -PathType Leaf
  $lines.Add('AUDIT_SCRIPT_AT_REQUESTED_PATH='+$exists)
  if($exists) {
    $f=Get-Item -LiteralPath $AuditScriptPath
    $lines.Add('AUDIT_SCRIPT_SIZE_BYTES='+$f.Length)
    $lines.Add('AUDIT_SCRIPT_SHA256='+((Get-FileHash -LiteralPath $AuditScriptPath -Algorithm SHA256).Hash))
    if($node){
      $null=& node --check $AuditScriptPath 2>$null
      $lines.Add('AUDIT_JS_SYNTAX_OK='+($LASTEXITCODE -eq 0))
    }
  }
  $lines.Add('DATABASE_UNTOUCHED=YES')
  $lines.Add('ROLLBACK_NOT_TESTED=YES')
  $lines.Add('SEMANTIC_AUDIT_NOT_EXECUTED=YES')
  $lines.Add('AUTOMATIC_CHAT_RETURN_NOT_CONFIGURED=YES')
} catch {
  $lines.Add('DIAGNOSTIC_PARTIAL=YES')
  $lines.Add('ERROR_DETAILS_REDACTED=YES')
}
$lines.Add('END_REPORT_OK')
$report=$lines -join [Environment]::NewLine
Write-Output $report
try { Set-Clipboard -Value $report -ErrorAction Stop } catch {}
