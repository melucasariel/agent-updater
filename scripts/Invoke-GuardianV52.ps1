# ROTA62 Guardian V5.2 — operator one-enter READ-ONLY preflight.
# Requires locally reviewed checkout. Never decrypts, uploads, writes backup or executes SQL.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ExpectedSha256,
  [string[]]$SearchRoots=@($env:TEMP,(Join-Path $env:USERPROFILE 'Downloads'),(Join-Path $env:USERPROFILE 'Documents'),(Join-Path $env:USERPROFILE 'Desktop'),'G:\'),
  [string]$StageFolder,
  [switch]$NoClipboard
)
$ErrorActionPreference='Stop'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 GUARDIAN V5.2 ONE ENTER OPERATOR ===')
$report.Add('MODE=READ_ONLY_NO_PASSWORD')
try {
  if(-not (Get-Command node -ErrorAction SilentlyContinue)){throw 'NODE_UNAVAILABLE'}
  $script=Join-Path $PSScriptRoot 'GuardianV52-EncryptedRecoveryInput.mjs'
  $dependency=Join-Path $PSScriptRoot 'GuardianV5-VerifyStage.mjs'
  if(-not (Test-Path -LiteralPath $script -PathType Leaf) -or -not (Test-Path -LiteralPath $dependency -PathType Leaf)){throw 'MISSING_SCRIPTS'}
  & node --check $script 2>$null | Out-Null
  if($LASTEXITCODE -ne 0){throw 'SCRIPT_SYNTAX_FAILED'}
  $foundFiles=New-Object 'System.Collections.Generic.List[string]'
  $examined=0
  $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach($root in ($SearchRoots|Where-Object{$_ -and (Test-Path -LiteralPath $_ -PathType Container)}|Select-Object -Unique)){
    $files=Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.r62db' -ErrorAction SilentlyContinue | Select-Object -First 150
    foreach($file in $files){
      if(-not $seen.Add($file.FullName)){continue}
      $examined++
      if($file.Length -gt 1073741824){continue}
      try{
        $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        if($hash -eq $ExpectedSha256){[void]$foundFiles.Add($file.FullName)}
      }catch{}
      if($foundFiles.Count -ge 3){break}
    }
    if($foundFiles.Count -ge 3){break}
  }
  $report.Add('ARCHIVES_EXAMINED='+$examined)
  $report.Add('MATCHING_CIPHERTEXT_COPIES='+$foundFiles.Count)
  if($foundFiles.Count -lt 1){throw 'NO_MATCHING_ARCHIVE'}
  $nodeArgs=@($script,'--archive',$foundFiles[0],'--reference-sha256',$ExpectedSha256)
  if($foundFiles.Count -ge 2){$nodeArgs+=@('--copy-1',$foundFiles[1])}
  if($foundFiles.Count -ge 3){$nodeArgs+=@('--copy-2',$foundFiles[2])}
  if($StageFolder){$nodeArgs+=@('--stage',$StageFolder)}
  $output=@(& node @nodeArgs 2>$null)
  $exitCode=$LASTEXITCODE
  if($output.Count -gt 100 -or $output.Count -eq 0){throw 'INVALID_REPORT'}
  foreach($line in $output){
    $valid=($line -eq 'END_REPORT_OK')
    if(-not $valid){$valid=($line -match '^[A-Z0-9_]+=[A-Z0-9_]+$')}
    if(-not $valid){$valid=($line -match '^[A-Z0-9_]+=\d+$')}
    if(-not $valid){$valid=($line -eq '=== ROTA62 GUARDIAN V5.2 ENCRYPTED RECOVERY INPUT GATE ===')}
    if(-not $valid){throw 'INVALID_REPORT'}
    $report.Add([string]$line)
  }
  $report.Add('AUDIT_EXIT='+$(if($exitCode -eq 0){'SUCCESS'}else{'BLOCKED'}))
}catch{
  $report.Add('STATUS=BLOCKED_REDACTED')
}
$report.Add('PRODUCTION_TOUCHED=NO')
$report.Add('BACKUP_NOT_DECRYPTED=YES')
$report.Add('END_OPERATOR_REPORT_OK')
$text=$report -join [Environment]::NewLine
Write-Output $text
if(-not $NoClipboard){try{Set-Clipboard -Value $text}catch{}}
