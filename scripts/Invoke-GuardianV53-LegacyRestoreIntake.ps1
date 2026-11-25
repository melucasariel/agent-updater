# Guardian V5.3 Legacy Restore Intake -- source identification only.
# Read-only: never executes third-party source, does not request password, no SQL/Docker mutation.
[CmdletBinding()]
param(
 [string[]]$SearchRoots=@($env:TEMP,(Join-Path $env:USERPROFILE 'Downloads'),(Join-Path $env:USERPROFILE 'Documents'),(Join-Path $env:USERPROFILE 'Desktop')),
 [switch]$NoClipboard
)
$ErrorActionPreference='Stop'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 GUARDIAN V5.3 RESTORE INTAKE ===')
$report.Add('MODE=OFFLINE_READ_ONLY_SOURCE_DISCOVERY')
try {
 $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 $files=New-Object 'System.Collections.Generic.List[object]'
 $scanned=0
 foreach($root in ($SearchRoots|Where-Object {$_ -and (Test-Path -LiteralPath $_ -PathType Container)}|Select-Object -Unique)){
  # Limit each root so a corrupted or huge drive cannot monopolize the operation.
  foreach($item in (Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*backup-postgres*.mjs' -ErrorAction SilentlyContinue|Select-Object -First 50)){
   if(-not $seen.Add($item.FullName)){continue}
   $scanned++
   if($item.Length -le 1048576 -and $item.Length -ge 64){$files.Add($item)}
  }
 }
 $report.Add('LEGACY_CANDIDATE_FILES='+$files.Count)
 $report.Add('MATCHED_FILE_NAMES_EXAMINED='+$scanned)
 $digests=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 $n=0
 foreach($item in ($files|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 12)){
  $n++
  $sha=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
  [void]$digests.Add($sha)
  # Extract only boolean markers from source; NEVER print source, file path, connection strings or secrets.
  $code=[IO.File]::ReadAllText($item.FullName)
  $scrypt=[bool]($code -match 'scrypt')
  $gcm=[bool]($code -match 'aes-256-gcm|aes256gcm|AES-256-GCM')
  $restore=[bool]($code -match 'pg_restore')
  $ownershipRisk=[bool]($code -match '\-\-no-owner|\-\-no-privileges|\-\-no-acl|\-\-no-acl')
  $report.Add("LEGACY_$($n)_SHA256=$sha")
  $report.Add("LEGACY_$($n)_BYTES=$($item.Length)")
  $report.Add("LEGACY_$($n)_HAS_SCRYPT=$($scrypt.ToString().ToUpperInvariant())")
  $report.Add("LEGACY_$($n)_HAS_AES_GCM=$($gcm.ToString().ToUpperInvariant())")
  $report.Add("LEGACY_$($n)_HAS_PG_RESTORE=$($restore.ToString().ToUpperInvariant())")
  $report.Add("LEGACY_$($n)_OWNERSHIP_ACL_OMISSION_RISK=$($ownershipRisk.ToString().ToUpperInvariant())")
 }
 # Review packaged legacy source INSIDE ZIPs. No extraction, execution, password or content output.
 $zipCount=0
 $packagedCount=0
 $zipDigests=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 try{
  Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
  Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
  foreach($root in ($SearchRoots|Where-Object {$_ -and (Test-Path -LiteralPath $_ -PathType Container)}|Select-Object -Unique)){
   foreach($archive in (Get-ChildItem -LiteralPath $root -Recurse -File -Filter '*.zip' -ErrorAction SilentlyContinue|Select-Object -First 35)){
    if($archive.Length -gt 52428800){continue}
    $zipCount++
    try {
     $zip=[IO.Compression.ZipFile]::OpenRead($archive.FullName)
     try{
      foreach($entry in $zip.Entries){
       if($entry.Name -notlike '*backup-postgres*.mjs' -or $entry.Length -lt 64 -or $entry.Length -gt 1048576){continue}
       $stream=$entry.Open()
       $buffer=New-Object IO.MemoryStream
       try{$stream.CopyTo($buffer);$data=$buffer.ToArray()}finally{$stream.Dispose();$buffer.Dispose()}
       if($data.Length -ne $entry.Length){continue}
       $hasher=[Security.Cryptography.SHA256]::Create()
       try{$digest=[BitConverter]::ToString($hasher.ComputeHash($data)).Replace('-','')}finally{$hasher.Dispose()}
       [void]$zipDigests.Add($digest)
       $packagedCount++
       if($packagedCount -le 12){
        $text=[Text.Encoding]::UTF8.GetString($data)
        $risk=[bool]($text -match '\-\-no-owner|\-\-no-privileges|\-\-no-acl')
        $gcm=[bool]($text -match 'aes-256-gcm|aes256gcm|AES-256-GCM')
        $kdf=[bool]($text -match 'scrypt')
        $report.Add("PACKAGED_$($packagedCount)_SHA256=$digest")
        $report.Add("PACKAGED_$($packagedCount)_HAS_AES_GCM=$($gcm.ToString().ToUpperInvariant())")
        $report.Add("PACKAGED_$($packagedCount)_HAS_SCRYPT=$($kdf.ToString().ToUpperInvariant())")
        $report.Add("PACKAGED_$($packagedCount)_OWNERSHIP_ACL_OMISSION_RISK=$($risk.ToString().ToUpperInvariant())")
       }
      }
     }finally{$zip.Dispose()}
    }catch{$report.Add('ZIP_READ_PARTIAL=YES')}
   }
  }
 }catch{$report.Add('ZIP_SCAN_UNAVAILABLE=YES')}
 $report.Add('ZIP_ARCHIVES_EXAMINED='+$zipCount)
 $report.Add('ZIP_EMBEDDED_SOURCE_MATCHES='+$packagedCount)
 $report.Add('ZIP_EMBEDDED_UNIQUE_HASHES='+$zipDigests.Count)
 $report.Add('LEGACY_UNIQUE_SOURCE_HASHES='+$digests.Count)
 $report.Add('ORIGINAL_DECRYPTOR_PROVEN=NO')
 $report.Add('READY_TO_DECRYPT_REAL_BACKUP=NO')
 $report.Add('KNOWN_BACKUP_SHA256=35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA')
 $report.Add('KNOWN_BACKUP_COPIES=3')
 $report.Add('KNOWN_DISTINCT_RECOVERY_POINTS=1')
 $report.Add('RESTORE_WITH_OWNERS_ACL_PENDING=YES')
 $report.Add('WEB_API_STORAGE_RESTORE_PENDING=YES')
 $report.Add('RTO_TARGET_4_TO_6_HOURS_NOT_PROVEN=YES')
} catch {
 $report.Add('STATUS=BLOCKED_REDACTED')
}
$report.Add('SOURCE_EXECUTED=NO')
$report.Add('PASSWORD_REQUESTED=NO')
$report.Add('PRODUCTION_TOUCHED=NO')
$report.Add('END_REPORT_OK')
$out=$report -join [Environment]::NewLine
Write-Output $out
if(-not $NoClipboard){try{Set-Clipboard -Value $out}catch{}}
