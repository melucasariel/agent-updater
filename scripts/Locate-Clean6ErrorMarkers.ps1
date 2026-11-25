# CLEAN6 error-marker locator: bounded, read-only; never prints source or file paths.
[CmdletBinding()]
param(
  [string]$SearchRoot = $env:TEMP,
  [ValidateRange(1,500)][int]$MaxFiles = 150,
  [switch]$NoClipboard
)
$ErrorActionPreference='Stop'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN6 ERROR LOCATOR V1 ===')
$report.Add('MODE=READ_ONLY_NO_SQL_NO_NETWORK_NO_SECRETS')
$markers=@('LOCAL_ERROR_REDACTED','GUARDED_SEMANTIC_VERIFY_185_595_FORCE_ROLLBACK','PASSWORD_ENTRY_BEGIN','INVALID_REPORT_FOR_AUTO_SEND')
$count=0; $matched=0; $truncated=$false
try {
  $root=[IO.Path]::GetFullPath($SearchRoot)
  if(-not (Test-Path -LiteralPath $root -PathType Container)){throw 'Search root unavailable'}
  # Enumerate only root and one child level. File content is never printed.
  $dirs=New-Object 'System.Collections.Generic.List[string]'
  $dirs.Add($root)
  foreach($d in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue | Select-Object -First 80)){
    $dirs.Add($d.FullName)
  }
  $files=New-Object 'System.Collections.Generic.List[string]'
  foreach($d in $dirs){
    foreach($item in @(Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in @('.mjs','.js','.ps1') -and $_.Length -le 2097152 } | Select-Object -First 150)){
      if($files.Count -ge $MaxFiles){$truncated=$true;break}
      $files.Add($item.FullName)
    }
    if($truncated){break}
  }
  foreach($file in $files){
    $count++
    try {
      $contents=[IO.File]::ReadAllText($file)
      $hit=@($markers | Where-Object {$contents.Contains($_)})
      if($hit.Count -gt 0){
        $matched++
        $sha=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        $report.Add(('MATCH_'+$matched+'_SHA12='+$sha.Substring(0,12)))
        $report.Add(('MATCH_'+$matched+'_MARKERS='+($hit -join ',')))
      }
    } catch {}
  }
  $report.Add('FILES_SCANNED='+$count)
  $report.Add('FILES_MATCHED='+$matched)
  $report.Add('SCAN_TRUNCATED='+([string]$truncated))
  $report.Add('FILE_NAMES_PATHS_CONTENTS_REDACTED=YES')
  $report.Add('AUDIT_NOT_EXECUTED=YES')
} catch {
  $report.Add('SEARCH_ERROR_REDACTED=YES')
}
$report.Add('END_REPORT_OK')
$output=$report -join [Environment]::NewLine
Write-Output $output
if(-not $NoClipboard){try {Set-Clipboard -Value $output -ErrorAction Stop}catch{}}
