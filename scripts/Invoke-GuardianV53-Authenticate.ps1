# Guardian V5.3 -- authenticates legacy R62DB02 in memory. Password is typed interactively in Node only.
# Reads ciphertext; writes ONLY a short sanitized report in user TEMP, then deletes it.
[CmdletBinding()]
param(
 [string]$ExpectedSha256='35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA',
 [string[]]$SearchRoots=@($env:TEMP,(Join-Path $env:USERPROFILE 'Downloads'),(Join-Path $env:USERPROFILE 'Documents'),(Join-Path $env:USERPROFILE 'Desktop')),
 [switch]$NoClipboard
)
$ErrorActionPreference='Stop'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 GUARDIAN V5.3 AUTHENTICATE OPERATOR ===')
$report.Add('MODE=LOCAL_AUTHENTICATION_NO_DB_WRITES')
$tempReport=$null
try {
 if($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$'){throw 'BAD_HASH'}
 if(-not (Get-Command node -ErrorAction SilentlyContinue)){throw 'NODE_UNAVAILABLE'}
 $script=Join-Path $PSScriptRoot 'GuardianV53-AuthenticateR62DB.mjs'
 if(-not (Test-Path -LiteralPath $script -PathType Leaf)){throw 'SOURCE_UNAVAILABLE'}
 & node --check $script 2>$null|Out-Null
 if($LASTEXITCODE -ne 0){throw 'INVALID_NODE_SOURCE'}
 $found=New-Object 'System.Collections.Generic.List[string]'
 $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 $checked=0
 foreach($root in ($SearchRoots|Where-Object {$_ -and (Test-Path -LiteralPath $_ -PathType Container)}|Select-Object -Unique)){
  foreach($item in (Get-ChildItem -LiteralPath $root -File -Recurse -Filter '*.r62db' -ErrorAction SilentlyContinue|Select-Object -First 150)){
   if(-not $seen.Add($item.FullName)){continue}
   $checked++
   if($item.Length -gt 1073741824 -or $item.Length -lt 64){continue}
   try{
    if((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 -ErrorAction Stop).Hash -eq $ExpectedSha256){$found.Add($item.FullName)}
   }catch{}
   if($found.Count -ge 3){break}
  }
  if($found.Count -ge 3){break}
 }
 $report.Add('ARCHIVES_CHECKED='+$checked)
 $report.Add('MATCHING_CIPHERTEXT_COPIES='+$found.Count)
 if($found.Count -lt 1){throw 'BACKUP_NOT_FOUND'}
 $tempReport=Join-Path $env:TEMP ('R62-V53-AUTH-'+[guid]::NewGuid().ToString('N')+'.txt')
 $report.Add('PASSWORD_SOURCE=INTERACTIVE_LOCAL_TERMINAL')
 # IMPORTANT: this invocation must not be captured or piped, so Node has an interactive Windows terminal.
 & node $script --archive $found[0] --expected-sha256 $ExpectedSha256 --report-file $tempReport
 $code=$LASTEXITCODE
 if(Test-Path -LiteralPath $tempReport -PathType Leaf){
  $lines=@(Get-Content -LiteralPath $tempReport -ErrorAction Stop)
  if($lines.Count -lt 3 -or $lines.Count -gt 30 -or $lines[-1] -ne 'END_REPORT_OK'){throw 'INVALID_AUTH_REPORT'}
  foreach($line in $lines){
   if($line -match '^=== ROTA62 GUARDIAN V5\.3 AES-GCM AUTHENTICATION ===$' -or
      $line -match '^[A-Z0-9_]+=[A-Z0-9_]+$' -or
      $line -match '^[A-Z0-9_]+=[0-9]+$' -or
      $line -eq 'END_REPORT_OK'){$report.Add([string]$line)}
   else{throw 'INVALID_AUTH_REPORT'}
  }
 }else{throw 'AUTH_REPORT_UNAVAILABLE'}
 $report.Add('AUTH_PROCESS_EXIT='+$(if($code -eq 0){'SUCCESS'}else{'BLOCKED'}))
}catch{
 $report.Add('STATUS=BLOCKED_REDACTED')
}finally{
 if($tempReport -and (Test-Path -LiteralPath $tempReport -PathType Leaf)){Remove-Item -LiteralPath $tempReport -Force -ErrorAction SilentlyContinue}
}
$report.Add('PASSWORD_NOT_INCLUDED_IN_REPORT=YES')
$report.Add('PLAINTEXT_NOT_SAVED=YES')
$report.Add('DATABASE_NOT_MODIFIED=YES')
$report.Add('PRODUCTION_TOUCHED=NO')
$report.Add('END_OPERATOR_REPORT_OK')
$out=$report -join [Environment]::NewLine
Write-Output $out
if(-not $NoClipboard){try{Set-Clipboard -Value $out}catch{}}
