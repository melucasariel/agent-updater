# ROTA62 Guardian Backup Envelope Integrity v0.3 -- Windows PowerShell 5.1
# Validates a previously selected DPAPI-protected .r62db path and authentic envelope metadata.
# Does not decrypt, execute backups, restore a DB, contact Supabase or touch production.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
Add-Type -AssemblyName System.Security
$root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$pointer=Join-Path $root 'backup_selection.dpapi'
$expectedHash='35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA'
$expectedSize=5287976L
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 BACKUP ENVELOPE v0.3 ===')
$report.Add('[MODO] READ_ONLY_LOCAL_NO_DECRYPT_NO_RESTORE')
$stage='INIT'
$success=$false
$plain=$null
$fs=$null
try {
 $stage='DPAPI_POINTER'
 if(-not (Test-Path -LiteralPath $pointer -PathType Leaf)){throw 'BACKUP_POINTER_MISSING'}
 $plain=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($pointer),$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
 $path=[Text.Encoding]::UTF8.GetString($plain)
 if([string]::IsNullOrWhiteSpace($path) -or -not [IO.Path]::IsPathRooted($path)){throw 'BACKUP_POINTER_INVALID'}
 if([IO.Path]::GetExtension($path) -cne '.r62db'){throw 'SELECTED_FILE_NOT_R62DB'}
 $stage='SOURCE_PRESENT'
 if(-not (Test-Path -LiteralPath $path -PathType Leaf)){throw 'SELECTED_BACKUP_NOT_ACCESSIBLE'}
 $f=Get-Item -LiteralPath $path
 if($f.Length -ne $expectedSize){throw 'KNOWN_BACKUP_SIZE_MISMATCH'}
 $report.Add('[OK] SELECTED_BACKUP_ACCESSIBLE')
 $report.Add('SIZE_BYTES='+[string]$f.Length)
 $stage='SHA256'
 $sha=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
 if($sha -cne $expectedHash){throw 'KNOWN_BACKUP_SHA256_MISMATCH'}
 $report.Add('[OK] SOURCE_MATCHES_RECOVERED_ORIGINAL_SHA256')
 $stage='ENVELOPE'
 $fs=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 $reader=New-Object IO.BinaryReader($fs,[Text.Encoding]::UTF8,$true)
 $magic=[Text.Encoding]::ASCII.GetString($reader.ReadBytes(8))
 if($magic -cne ('R62DB02'+[char]10)){throw 'R62DB_MAGIC_INVALID'}
 $be=$reader.ReadBytes(4)
 if($be.Length -ne 4){throw 'HEADER_LENGTH_TRUNCATED'}
 [Array]::Reverse($be)
 $headerLength=[BitConverter]::ToUInt32($be,0)
 if($headerLength -lt 50 -or $headerLength -gt 8192){throw 'HEADER_LENGTH_INVALID'}
 $head=$reader.ReadBytes([int]$headerLength)
 if($head.Length -ne $headerLength){throw 'HEADER_TRUNCATED'}
 $metadata=[Text.Encoding]::UTF8.GetString($head)|ConvertFrom-Json -ErrorAction Stop
 if([int]$metadata.schema -ne 2 -or [string]$metadata.format -cne 'pg_dump_custom'){throw 'ENVELOPE_SCHEMA_INVALID'}
 if([string]$metadata.cipher -cne 'AES-256-GCM' -or [string]$metadata.kdf -cne 'scrypt'){throw 'CRYPTO_METADATA_UNEXPECTED'}
 if([int]$metadata.N -ne 32768 -or [int]$metadata.r -ne 8 -or [int]$metadata.p -ne 1){throw 'KDF_PARAMETERS_UNEXPECTED'}
 $salt=[string]$metadata.salt;$nonce=[string]$metadata.nonce
 if($salt -cnotmatch '^[a-fA-F0-9]{32}$' -or $nonce -cnotmatch '^[a-fA-F0-9]{24}$'){throw 'SALT_NONCE_FORMAT_UNEXPECTED'}
 $remaining=$fs.Length-$fs.Position
 if($remaining -lt 32){throw 'ENCRYPTED_PAYLOAD_TOO_SHORT'}
 $report.Add('[OK] R62DB02_HEADER_AND_METADATA')
 $report.Add('[OK] AES256_GCM_SCRYPT_METADATA')
 $report.Add('ENVELOPE_HEADER_BYTES='+[string]$headerLength)
 $report.Add('ENCRYPTED_PAYLOAD_BYTES='+[string]$remaining)
 $stage='WRITE_MANIFEST'
 $manifest=[ordered]@{
   manifest_version=1
   backup_format='R62DB02'
   file_size_bytes=$f.Length
   file_sha256=$sha.ToLowerInvariant()
   envelope_schema=2
   original_format='pg_dump_custom'
   cipher='AES-256-GCM'
   kdf='scrypt'
   kdf_N=32768
   kdf_r=8
   kdf_p=1
   aes_authentication_tested=$false
   restore_tested_in_this_run=$false
   selected_source_pointer='local_dpapi'
   verified_utc=[DateTime]::UtcNow.ToString('o')
   classification='BYTES_AND_METADATA_VERIFIED_ONLY'
 }
 $manifestPath=Join-Path $root 'selected_backup_manifest.json'
 $temp=Join-Path $root ('manifest_'+[guid]::NewGuid().ToString('N')+'.tmp')
 [IO.File]::WriteAllText($temp,($manifest|ConvertTo-Json -Depth 5),(New-Object Text.UTF8Encoding($false)))
 Move-Item -LiteralPath $temp -Destination $manifestPath -Force
 $report.Add('[OK] LOCAL_MANIFEST_WRITTEN_NO_SECRETS')
 $report.Add('[LIMITE] AES_TAG_NOT_VERIFIED_AND_DATABASE_NOT_RESTORED')
 $report.Add('[NEXT] AES authenticated verification with existing backup-format verifier')
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]+$'){$reason='ENVELOPE_PARSING_OR_LOCAL_IO_ERROR'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
 if($fs){$fs.Dispose()}
 if($plain){[Array]::Clear($plain,0,$plain.Length)}
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
