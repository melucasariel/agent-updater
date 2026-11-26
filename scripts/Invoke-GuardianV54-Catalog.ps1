# ROTA62 Guardian V5.4 — one-enter archive TOC, offline isolated PG17.
# Never executes SQL; ciphertext stays encrypted on disk, password local and hidden.
[CmdletBinding()]
param(
 [string]$ExpectedSha256='35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA',
 [string[]]$SearchRoots=@($env:TEMP,(Join-Path $env:USERPROFILE 'Downloads'),(Join-Path $env:USERPROFILE 'Documents'),(Join-Path $env:USERPROFILE 'Desktop')),
 [switch]$DeepRead,
 [switch]$NoClipboard
)
$ErrorActionPreference='Stop'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 GUARDIAN V5.4 OFFLINE CATALOG OPERATOR ===')
$report.Add($(if($DeepRead){'MODE=LOCAL_ENCRYPTED_BACKUP_TOC_AND_FULL_PAYLOAD'}else{'MODE=LOCAL_ENCRYPTED_BACKUP_TOC_ONLY'}))
$tempReport=$null
try{
 if($ExpectedSha256 -notmatch '^[0-9A-Fa-f]{64}$'){throw 'INVALID_SHA'}
 if(-not (Get-Command node -ErrorAction SilentlyContinue)){throw 'NODE_MISSING'}
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_MISSING'}
 $js=Join-Path $PSScriptRoot 'GuardianV54-ArchiveCatalog.mjs'
 $auth=Join-Path $PSScriptRoot 'GuardianV53-AuthenticateR62DB.mjs'
 $deps=Join-Path $PSScriptRoot 'GuardianV64-TocDependencyPreflight.mjs'
 $shape=Join-Path $PSScriptRoot 'GuardianV65-TocShapeRiskAudit.mjs'
 $blind=Join-Path $PSScriptRoot 'GuardianV66-TocBlindSpotAudit.mjs'
 $scope=Join-Path $PSScriptRoot 'GuardianV67-TableScopeAudit.mjs'
 $pairs=Join-Path $PSScriptRoot 'GuardianV68-TableDataPairAudit.mjs'
 if(-not (Test-Path -LiteralPath $js -PathType Leaf) -or -not (Test-Path -LiteralPath $auth -PathType Leaf) -or -not (Test-Path -LiteralPath $deps -PathType Leaf) -or -not (Test-Path -LiteralPath $shape -PathType Leaf) -or -not (Test-Path -LiteralPath $blind -PathType Leaf) -or -not (Test-Path -LiteralPath $scope -PathType Leaf) -or -not (Test-Path -LiteralPath $pairs -PathType Leaf)){throw 'SOURCES_MISSING'}
 & node --check $js 2>$null | Out-Null
 if($LASTEXITCODE -ne 0){throw 'SOURCE_PARSE_FAILED'}
 & node --check $deps 2>$null | Out-Null
 if($LASTEXITCODE -ne 0){throw 'DEPENDENCY_PARSE_FAILED'}
 & node --check $shape 2>$null | Out-Null
 if($LASTEXITCODE -ne 0){throw 'SHAPE_AUDIT_PARSE_FAILED'}
 & node --check $blind 2>$null | Out-Null
 if($LASTEXITCODE -ne 0){throw 'BLIND_AUDIT_PARSE_FAILED'}
 & node --check $scope 2>$null | Out-Null
 if($LASTEXITCODE -ne 0){throw 'SCOPE_AUDIT_PARSE_FAILED'}
 & node --check $pairs 2>$null | Out-Null
 if($LASTEXITCODE -ne 0){throw 'PAIR_AUDIT_PARSE_FAILED'}
 $found=New-Object 'System.Collections.Generic.List[string]'
 $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 $checked=0
 foreach($root in ($SearchRoots|Where-Object {$_ -and (Test-Path -LiteralPath $_ -PathType Container)}|Select-Object -Unique)){
  foreach($item in (Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.r62db' -ErrorAction SilentlyContinue|Select-Object -First 150)){
   if(-not $seen.Add($item.FullName)){continue}
   $checked++
   if($item.Length -lt 64 -or $item.Length -gt 1073741824){continue}
   try{
    if((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash -eq $ExpectedSha256){[void]$found.Add($item.FullName)}
   }catch{}
   if($found.Count -ge 3){break}
  }
  if($found.Count -ge 3){break}
 }
 $report.Add("ARCHIVES_CHECKED=$checked")
 $report.Add("MATCHING_CIPHERTEXT_COPIES=$($found.Count)")
 if($found.Count -lt 1){throw 'BACKUP_NOT_FOUND'}
 $tempReport=Join-Path $env:TEMP ('R62-V54-TOC-'+[guid]::NewGuid().ToString('N')+'.txt')
 $report.Add('PASSWORD_SOURCE=INTERACTIVE_LOCAL_TERMINAL')
 # Do not pipe or capture Node: interactive TTY is needed for hidden password.
 if($DeepRead){
  & node $js --archive $found[0] --expected-sha256 $ExpectedSha256 --report-file $tempReport --deep-read
 }else{
  & node $js --archive $found[0] --expected-sha256 $ExpectedSha256 --report-file $tempReport
 }
 $exit=$LASTEXITCODE
 if($exit -ne 0){throw 'AUTHENTICATED_READER_BLOCKED'}
 if(-not (Test-Path -LiteralPath $tempReport -PathType Leaf)){throw 'MISSING_SAFE_REPORT'}
 $items=@(Get-Content -LiteralPath $tempReport -ErrorAction Stop)
 if($items.Count -lt 3 -or $items.Count -gt 100 -or $items[-1] -ne 'END_REPORT_OK'){throw 'INVALID_SAFE_REPORT'}
 foreach($line in $items){
  $valid=$line -eq '=== ROTA62 GUARDIAN V5.4 AUTHENTICATED PG_RESTORE CATALOG ==='
  if(-not $valid){$valid=$line -eq 'END_REPORT_OK'}
  if(-not $valid){$valid=$line -match '^[A-Z0-9_]+=[A-Z0-9_]+$'}
  if(-not $valid){$valid=$line -match '^[A-Z0-9_]+=[0-9]+$'}
  if(-not $valid){$valid=$line -match '^[A-Z0-9_]+=[0-9A-F]{16}$'}
  if(-not $valid){throw 'UNSAFE_REPORT_LINE'}
  $report.Add([string]$line)
 }
 $report.Add('TOC_PROCESS_EXIT='+$(if($exit -eq 0){'SUCCESS'}else{'BLOCKED'}))
}catch{
 $report.Add('STATUS=BLOCKED_REDACTED')
}finally{
 if($tempReport -and (Test-Path -LiteralPath $tempReport -PathType Leaf)){
  Remove-Item -LiteralPath $tempReport -Force -ErrorAction SilentlyContinue
 }
}
$report.Add('NO_PASSWORD_IN_CLIPBOARD=YES')
$report.Add('DATABASE_NOT_RESTORED=YES')
$report.Add('NO_SQL_EXECUTED=YES')
$report.Add('PRODUCTION_TOUCHED=NO')
$report.Add('END_OPERATOR_REPORT_OK')
$out=$report -join [Environment]::NewLine
Write-Output $out
if(-not $NoClipboard){try{Set-Clipboard -Value $out}catch{}}
if($report.Contains('STATUS=BLOCKED_REDACTED')){exit 2}
