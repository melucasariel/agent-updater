# ROTA62 Guardian - backup source selector v0.2
# Windows PowerShell 5.1. This tool NEVER opens databases, extracts archives, or decrypts backup data.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$report = New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 BACKUP SELECTOR v0.2 ===')
$report.Add('[MODO] LOCAL_FILE_SELECTION_ONLY')
$stage = 'START'
$success = $false
$selection = $null
try {
  Add-Type -AssemblyName System.Security -ErrorAction Stop
  Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
  $stage='FILE_PICKER'
  $filePicker = New-Object System.Windows.Forms.OpenFileDialog
  $filePicker.Title = 'ROTA62 Guardian - selecione seu backup .r62db ou arquivo ZIP/RAR'
  $filePicker.Filter = 'Backup ROTA62 (*.r62db)|*.r62db|Arquivos compactados (*.zip;*.rar;*.7z)|*.zip;*.rar;*.7z|Todos os arquivos (*.*)|*.*'
  $filePicker.FilterIndex=1
  $filePicker.Multiselect=$false
  $filePicker.CheckFileExists=$true
  $filePicker.CheckPathExists=$true
  $filePicker.RestoreDirectory=$true
  $initial=Join-Path $env:USERPROFILE 'Downloads'
  if(Test-Path -LiteralPath $initial -PathType Container){$filePicker.InitialDirectory=$initial}
  $choice=$filePicker.ShowDialog()
  if($choice -ne [System.Windows.Forms.DialogResult]::OK){throw 'FILE_SELECTION_CANCELLED'}
  $selection=[IO.Path]::GetFullPath($filePicker.FileName)
  $stage='VALIDATE_SELECTION'
  if(-not (Test-Path -LiteralPath $selection -PathType Leaf)){throw 'SELECTED_FILE_NOT_FOUND'}
  $ext=[IO.Path]::GetExtension($selection).ToLowerInvariant()
  if($ext -cnotin @('.r62db','.zip','.rar','.7z')){throw 'UNSUPPORTED_BACKUP_EXTENSION'}
  $f=Get-Item -LiteralPath $selection
  if($f.Length -lt 128){throw 'FILE_TOO_SMALL'}
  if($f.Length -gt 200GB){throw 'FILE_SIZE_LIMIT_EXCEEDED'}
  $report.Add('[OK] SOURCE_FILE_SELECTED')
  $report.Add('TYPE='+$(switch($ext){'.r62db' {'R62DB'} '.zip' {'ZIP_ARCHIVE'} '.rar' {'RAR_ARCHIVE'} '.7z' {'SEVENZIP_ARCHIVE'}}))
  $report.Add('SIZE_BYTES='+[string]$f.Length)
  $report.Add('SOURCE_DRIVE='+([IO.Path]::GetPathRoot($selection).TrimEnd('\')))
  $stage='HASH'
  $hash=(Get-FileHash -LiteralPath $selection -Algorithm SHA256).Hash
  if($hash -cnotmatch '^[A-F0-9]{64}$'){throw 'SHA256_FAILED'}
  $report.Add('[OK] SHA256_FILE_COMPUTED')
  $report.Add('FILE_SHA256='+$hash)
  $stage='SAVE_POINTER'
  $root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
  if(!(Test-Path -LiteralPath $root -PathType Container)){throw 'GUARDIAN_LOCAL_ROOT_NOT_FOUND'}
  # Current-user DPAPI protects the local path reference. We do not store file contents or secrets.
  $pathBytes=[Text.Encoding]::UTF8.GetBytes($selection)
  try {
    $protected=[Security.Cryptography.ProtectedData]::Protect($pathBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    $tmp=Join-Path $root ('backup_selection_'+[guid]::NewGuid().ToString('N')+'.tmp')
    $pointer=Join-Path $root 'backup_selection.dpapi'
    [IO.File]::WriteAllBytes($tmp,$protected)
    Move-Item -LiteralPath $tmp -Destination $pointer -Force
  }finally{[Array]::Clear($pathBytes,0,$pathBytes.Length)}
  $report.Add('[OK] SOURCE_POINTER_STORED_LOCALLY_WITH_DPAPI')
  if($ext -cne '.r62db'){
    $report.Add('[AVISO] ARCHIVE_SELECTED_BACKUP_NOT_YET_EXTRACTED_OR_VALIDATED')
    $report.Add('[NEXT] Inspect archive index locally; do not assume the inner .r62db exists')
  }else{
    $report.Add('[NEXT] Verify .r62db format and AES authentication locally before any restore')
  }
  $report.Add('[LIMITE] SHA256 proves file identity, not database recovery or AES validity')
  $success=$true
}catch{
  $reason=[string]$_.Exception.Message
  if($reason -cnotmatch '^[A-Z0-9_]+$'){$reason='LOCAL_ERROR_REDACTED'}
  $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
  $out=$report -join [Environment]::NewLine
  Write-Output $out
  try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] REPORT_COPIED'}catch{}
}
if(-not $success){exit 1}
