# ROTA62 CLEAN6 v0.7.5 — read-only backup preflight, never decrypt or restore
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$r=[System.Collections.Generic.List[string]]::new()
$r.Add('=== ROTA62 CLEAN6 BACKUP PREFLIGHT v0.7.5 ===')
$r.Add('[MODO] READ_ONLY_NO_DECRYPT_NO_RESTORE')
$stage='START';$ok=$false
function D([string[]]$a){
 $old=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$o=@(& docker @a 2>$null);$x=$LASTEXITCODE}
 catch{$o=@();$x=-1}finally{$ErrorActionPreference=$old}
 return [pscustomobject]@{Code=$x;Out=(($o -join [Environment]::NewLine).Trim())}
}
try{
 $stage='FILE_PICKER'
 Add-Type -AssemblyName System.Windows.Forms
 $dialog=New-Object System.Windows.Forms.OpenFileDialog
 $dialog.Title='Selecione o backup ROTA62 (.r62db)'
 $dialog.Filter='Backup ROTA62 (*.r62db)|*.r62db'
 $dialog.CheckFileExists=$true
 if($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK){throw 'SELECTION_CANCELED'}
 $path=$dialog.FileName
 if([System.IO.Path]::GetFileName($path) -cne 'R62_PG_20261124T053055_990Z_1aff95.r62db'){throw 'BACKUP_NAME_UNEXPECTED'}
 if((Get-Item -LiteralPath $path).Length -ne 5287976){throw 'BACKUP_SIZE_UNEXPECTED'}
 $stage='BACKUP_HASH'
 if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne '35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA'){throw 'BACKUP_SHA256_UNEXPECTED'}
 $r.Add('[OK] BACKUP_FILENAME_SIZE_SHA256_VALIDATED')
 $stage='BACKUP_HEADER'
 $fs=[System.IO.File]::OpenRead($path)
 try{
  $bytes=New-Object byte[] 12
  if($fs.Read($bytes,0,12) -ne 12){throw 'HEADER_TRUNCATED'}
  $magic=[System.Text.Encoding]::ASCII.GetString($bytes,0,8)
  if($magic -cne ('R62DB02'+[char]10)){throw 'MAGIC_INVALID'}
  $len=[int64]$bytes[8]*16777216+[int64]$bytes[9]*65536+[int64]$bytes[10]*256+[int64]$bytes[11]
  if($len -lt 10 -or $len -gt 4096){throw 'HEADER_LENGTH_INVALID'}
 }finally{$fs.Dispose()}
 $r.Add('[OK] R62DB02_HEADER_VALID')
 $stage='SERVER_ISOLATION'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_MISSING'}
 $s=D @('inspect','rota62_guardian_clean6_direct_pg')
 $c=D @('inspect','rota62_guardian_clean6_pg')
 if($s.Code -ne 0 -or $c.Code -ne 0){throw 'DOCKER_INSPECT_FAILED'}
 $a=@(ConvertFrom-Json -InputObject $s.Out)
 $b=@(ConvertFrom-Json -InputObject $c.Out)
 if($a.Count -ne 1 -or $b.Count -ne 1){throw 'DOCKER_INSPECT_INVALID'}
 $srv=$a[0];$clean=$b[0]
 if(-not [bool]$srv.State.Running -or [bool]$clean.State.Running){throw 'SERVER_STATE_UNEXPECTED'}
 if([string]$srv.HostConfig.NetworkMode -cne 'none'){throw 'NETWORK_UNSAFE'}
 if([string]$srv.Config.User -cne 'postgres'){throw 'USER_UNEXPECTED'}
 if([string]$srv.Image -cne [string]$clean.Image -or [string]$srv.Image -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'IMAGE_MISMATCH'}
 if(@($srv.Mounts).Count -ne 1 -or [string]$srv.Mounts[0].Name -cne 'rota62_guardian_clean6_data'){throw 'MOUNT_UNEXPECTED'}
 if($srv.HostConfig.PortBindings -and @($srv.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'PORTS_UNSAFE'}
 $r.Add('[OK] CLEAN6_SERVER_RUNNING_ISOLATED')
 $stage='SQL_READ_ONLY'
 $sql="SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses')='' AND current_setting('shared_preload_libraries')='' AND current_setting('max_worker_processes')='0' THEN 'R62_OK' ELSE 'R62_BAD' END"
 $q=D @('exec','--user','postgres','rota62_guardian_clean6_direct_pg','psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-h','/tmp','-U','postgres','-d','postgres','-c',$sql)
 if($q.Code -ne 0 -or $q.Out -cne 'R62_OK'){throw 'DB_ISOLATION_CHECK_FAILED'}
 $r.Add('[OK] PG17_SETTINGS_CONFIRMED_SELECT_ONLY')
 $stage='RESTORE_TOOLS'
 $tool=D @('exec','--user','postgres','rota62_guardian_clean6_direct_pg','pg_restore','--version')
 if($tool.Code -ne 0 -or $tool.Out -notmatch 'PostgreSQL\)\s+17\.'){throw 'PG_RESTORE_NOT_VERIFIED'}
 $r.Add('[OK] PG_RESTORE_17_AVAILABLE')
 $stage='EMPTY_DEFAULT_DB'
 $emptySql="SELECT CASE WHEN (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f'))=0 THEN 'R62_EMPTY' ELSE 'R62_NONEMPTY' END"
 $q2=D @('exec','--user','postgres','rota62_guardian_clean6_direct_pg','psql','-X','-A','-t','-q','-v','ON_ERROR_STOP=1','-h','/tmp','-U','postgres','-d','postgres','-c',$emptySql)
 if($q2.Code -ne 0 -or $q2.Out -cne 'R62_EMPTY'){throw 'DEFAULT_DB_NOT_EMPTY'}
 $r.Add('[OK] DEFAULT_DB_NO_USER_OBJECTS')
 $r.Add('[APROVADO] BACKUP_AND_CLEAN6_RESTORE_PREREQUISITES')
 $r.Add('[LIMITE] Password/decryption not tested; no SQL writes or restore')
 $r.Add('[NEXT] PREPARE_AUTHENTICATED_DECRYPT_AND_TEST_DB_RESTORE')
 $ok=$true
}catch{
 $msg=[string]$_.Exception.Message
 if($msg -cnotmatch '^[A-Z0-9_]{3,100}$'){$msg='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$msg)
}finally{
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
