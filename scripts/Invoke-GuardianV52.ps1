# ROTA62 Guardian V5.2 — operator one-enter READ-ONLY preflight.
# Requires local reviewed checkout with GuardianV52-EncryptedRecoveryInput.mjs.
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
  $node=Get-Command node -ErrorAction Stop
  $script=Join-Path $PSScriptRoot 'GuardianV52-EncryptedRecoveryInput.mjs'
  $dependency=Join-Path $PSScriptRoot 'GuardianV5-VerifyStage.mjs'
  if(-not (Test-Path -LiteralPath $script -PathType Leaf) -or -not (Test-Path -LiteralPath $dependency -PathType Leaf)){throw 'MISSING_LOCAL_REVIEWED_SCRIPTS'}
  & node --check $script 2>$null | Out-Null
  if($LASTEXITCODE -ne 0){throw 'SCRIPT_SYNTAX_FAILED'}
  $matches=New-Object 'System.Collections.Generic.List[string]'
  $examined=0
  $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  foreach($root in ($SearchRoots|Where-Object{$_ -and (Test-Path -LiteralPath $_ -PathType Container)}|Select-Object -Unique)){
    $files=Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.r62db' -ErrorAction SilentlyContinue | Select-Object -First 150
    foreach($f in $files) {
      if(-not $seen.Add($f.FullName)){continue}
      $examined++
      if($f.Length -gt 1073741824){continue}
      try{
        $hash=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        if($hash -eq $ExpectedSha256){$matches.Add($f.FullName)}
      }catch{}
      if($matches.Count -ge 3){break}
    }
    if($matches.Count -ge 3){break}
  }
  $report.Add('ARCHIVES_EXAMINED='+$examined)
  $report.Add('MATCHING_CIPHERTEXT_COPIES='+$matches.Count)
  if($matches.Count -lt 1){throw 'NO_MATCHING_ENCRYPTED_ARCHIVE'}
  $args=@($script,'--archive',$matches[0],'--reference-sha256',$ExpectedSha256)
  if($matches.Count -ge 2){$args+=@('--copy-1',$matches[1])}
  if($matches.Count -ge 3){$args+=@('--copy-2',$matches[2])}
  if($StageFolder){$args+=@('--stage',$StageFolder)}
  $output=@(& node @args 2>$null)
  $code=$LASTEXITCODE
  if($output.Count -gt 100 -or $output.Count -eq 0){throw 'INVALID_REPORT'}
  foreach($line in $output){
    if($line -match '^[A-Z0-9_]+=[A-Z0-9_]+$' -or $line -match '^[A-Z0-9_]+=\d+$' -or $line -match '^=== ROTA62 GUARDIAN V5\.2 ENCRYPTED RECOVERY INPUT GATE ===$'){$report.Add([string]$line)}
    else{throw 'INVALID_REPORT'}
  }
  if($code -ne 0){$report.Add('AUDIT_EXIT=BLOCKED')}
  else{$report.Add('AUDIT_EXIT=SUCCESS')}
}catch{
  $report.Add('STATUS=BLOCKED_REDACTED')
}
$report.Add('PRODUCTION_TOUCHED=NO')
$report.Add('BACKUP_NOT_DECRYPTED=YES')
$report.Add('END_OPERATOR_REPORT_OK')
$text=$report -join [Environment]::NewLine
Write-Output $text
if(-not $NoClipboard){try{Set-Clipboard -Value $text}catch{}}
