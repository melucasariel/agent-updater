# ROTA62 CLEAN6 - single-command read-only triage.
# Runs two bundled diagnostics, returns a bounded sanitized report to clipboard.
# Never decrypts backups, asks passwords, executes SQL, or alters containers.
[CmdletBinding()]
param(
 [string]$AuditScriptPath='',
 [string]$SearchRoot=$env:TEMP,
 [ValidateRange(1,500)][int]$MaxFiles=150,
 [switch]$SkipDocker,
 [switch]$NoClipboard
)
$ErrorActionPreference='Stop'
$lines=New-Object 'System.Collections.Generic.List[string]'
$lines.Add('=== ROTA62 CLEAN6 UNIFIED TRIAGE V1 ===')
$lines.Add('MODE=READ_ONLY_NO_PASSWORD_NO_SQL_NO_RESTORE')
$allow='^(?:AUDIT_CANDIDATES_FOUND|NODE_AVAILABLE|DOCKER_AVAILABLE|DOCKER_CHECK_SKIPPED|DOCKER_ENGINE_OK|ACTIVE_CONTAINER_COUNT|AUDIT_[1-5]_(?:SIZE_BYTES|SHA256|NODE_SYNTAX_OK)|AUDIT_NAMES_OR_PATHS_REDACTED|FILES_SCANNED|FILES_MATCHED|SCAN_TRUNCATED|MATCH_[0-9]+_(?:SHA12|MARKERS)|FILE_NAMES_PATHS_CONTENTS_REDACTED|DIAGNOSTIC_PARTIAL|ERROR_DETAILS_REDACTED|SEARCH_ERROR_REDACTED)=[A-Za-z0-9_.,-]+$'
$readiness=$null
$locator=$null
function ProcessPart([string]$component,[object[]]$output){
  $strings=@($output | ForEach-Object { [string]$_ })
  if(-not (@($strings | Where-Object {$_ -match '(?m)^END_REPORT_OK\s*$'}).Count -gt 0)) {
    $lines.Add($component+'_RESULT=INCOMPLETE'); return
  }
  $lines.Add($component+'_RESULT=COMPLETE')
  foreach($entry in $strings){
    foreach($line in ($entry -split '\r?\n')){
      $trimmed=$line.Trim()
      if($trimmed -cmatch $allow){
        $lines.Add($component+'_'+$trimmed)
      }
    }
  }
}
try {
  $readinessPath=Join-Path $PSScriptRoot 'Test-Clean6ReadinessV2.ps1'
  $locatorPath=Join-Path $PSScriptRoot 'Locate-Clean6ErrorMarkers.ps1'
  if(-not(Test-Path -LiteralPath $readinessPath -PathType Leaf) -or -not(Test-Path -LiteralPath $locatorPath -PathType Leaf)){
    $lines.Add('TRIAGE_STATUS=BLOCKED_MISSING_COMPONENT')
  } else {
    try {
      $args1=@{NoClipboard=$true;SkipDocker=[bool]$SkipDocker}
      if($AuditScriptPath){$args1.AuditScriptPath=$AuditScriptPath}
      $readiness=@(& $readinessPath @args1)
      ProcessPart 'READINESS' $readiness
    } catch { $lines.Add('READINESS_RESULT=FAILED_REDACTED') }
    try {
      $locator=@(& $locatorPath -SearchRoot $SearchRoot -MaxFiles $MaxFiles -NoClipboard)
      ProcessPart 'LOCATOR' $locator
    } catch { $lines.Add('LOCATOR_RESULT=FAILED_REDACTED') }

    $readinessText=@($readiness) -join "`n"
    $locatorText=@($locator) -join "`n"
    $candidate=[regex]::Match($readinessText,'(?m)^AUDIT_CANDIDATES_FOUND=(\d+)\s*$')
    $matches=[regex]::Match($locatorText,'(?m)^FILES_MATCHED=(\d+)\s*$')
    if(-not $candidate.Success -or -not $matches.Success -or
       $lines -contains 'READINESS_RESULT=INCOMPLETE' -or $lines -contains 'LOCATOR_RESULT=INCOMPLETE'){
      $lines.Add('TRIAGE_STATUS=INCOMPLETE')
      $lines.Add('NEXT_ACTION=REVIEW_DIAGNOSTIC_ENVIRONMENT')
    } elseif(([int]$candidate.Groups[1].Value -eq 0) -and ([int]$matches.Groups[1].Value -eq 0)){
      $lines.Add('TRIAGE_STATUS=NO_CANDIDATES_IN_BOUNDED_SEARCH')
      $lines.Add('NEXT_ACTION=LOCATE_AUDIT_SCRIPT_OUTSIDE_SEARCH_ROOT')
    } elseif([int]$candidate.Groups[1].Value -gt 0){
      $lines.Add('TRIAGE_STATUS=AUDIT_CANDIDATE_IDENTIFIED')
      $lines.Add('NEXT_ACTION=REVIEW_HASH_AND_INSPECT_LOCAL_AUDIT_ERROR')
    } else {
      $lines.Add('TRIAGE_STATUS=ERROR_MARKER_CANDIDATE_IDENTIFIED')
      $lines.Add('NEXT_ACTION=REVIEW_SOURCE_BY_LOCAL_SHA_FINGERPRINT')
    }
  }
} catch {
  $lines.Add('TRIAGE_STATUS=FAILED_REDACTED')
}
$lines.Add('SEMANTIC_AUDIT_NOT_EXECUTED=YES')
$lines.Add('ROLLBACK_NOT_TESTED=YES')
$lines.Add('NO_CHAT_AUTO_SEND=YES')
$lines.Add('END_REPORT_OK')
$report=$lines -join [Environment]::NewLine
Write-Output $report
if(-not $NoClipboard){try {Set-Clipboard -Value $report -ErrorAction Stop}catch{}}
