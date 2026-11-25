# ROTA62 CLEAN6 Docker volume probe v0.6.4
# Read-only diagnostic: ephemeral image shell and READONLY volume mounts.
# Does not start CLEAN6 or run postgres/initdb/SQL. No raw Docker errors copied.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 DOCKER VOLUME PROBE v0.6.4 ===')
$r.Add('[MODO] READ_ONLY_VOLUME_MOUNT_NO_DATABASE_WRITES')
$stage='PRECHECK';$success=$false
function Query([string[]]$argv){
 $old=$ErrorActionPreference
 try{
  $ErrorActionPreference='Continue'
  $output=@(& docker @argv 2>$null)
  $exit=$LASTEXITCODE
 }catch{throw 'DOCKER_INSPECT_EXCEPTION'}finally{$ErrorActionPreference=$old}
 if($exit -ne 0){throw 'DOCKER_INSPECT_FAILED'}
 return (($output -join [Environment]::NewLine).Trim())
}
function Probe([string]$label,[string[]]$argv,[string]$expected){
 $old=$ErrorActionPreference
 $out=@();$exit=-1;$err=''
 try{
  $ErrorActionPreference='Continue'
  $out=@(& docker @argv 2>&1)
  $exit=$LASTEXITCODE
 }catch{$err='SHELL_EXCEPTION'}finally{$ErrorActionPreference=$old}
 if($exit -eq 0){
  $txt=($out -join [Environment]::NewLine).Trim()
  if($txt -ceq $expected){$r.Add($label+'=OK');return $true}
  $r.Add($label+'=EXIT_ZERO_UNEXPECTED_OUTPUT');return $false
 }
 $msg=($out -join [Environment]::NewLine)
 if($err){$r.Add($label+'='+$err)}
 elseif($msg -match '(?i)permission denied|operation not permitted'){$r.Add($label+'=PERMISSION_DENIED')}
 elseif($msg -match '(?i)read-only file system'){$r.Add($label+'=READ_ONLY_ROOTFS_CONFLICT')}
 elseif($msg -match '(?i)invalid mount|mount.*(failed|error)|volume.*(not found|does not exist)'){$r.Add($label+'=VOLUME_MOUNT_ERROR')}
 elseif($msg -match '(?i)no space left'){$r.Add($label+'=DISK_SPACE_ERROR')}
 elseif($msg -match '(?i)unable to find image|image.*not found'){$r.Add($label+'=IMAGE_NOT_FOUND')}
 elseif($msg -match '(?i)OCI runtime|container init'){$r.Add($label+'=RUNTIME_INIT_ERROR')}
 else{$r.Add($label+'=OTHER_DOCKER_ERROR')}
 $r.Add($label+'_EXIT_NONZERO=YES')
 return $false
}
try{
 $stage='SAFETY'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_NOT_FOUND'}
 $cArr=@(ConvertFrom-Json -InputObject (Query @('inspect',$cn)))
 $refArr=@(ConvertFrom-Json -InputObject (Query @('inspect',$reference)))
 if($cArr.Count -ne 1 -or $refArr.Count -ne 1){throw 'INSPECT_COUNT_INVALID'}
 $c=$cArr[0];$ref=$refArr[0]
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_NOT_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_UNSAFE'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn -or [string]$c.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'CLEAN6_VOLUME_MISMATCH'}
 if([string]$c.Image -cne [string]$ref.Image){throw 'IMAGE_MISMATCH'}
 $image=[string]$c.Image
 if($image -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'IMAGE_ID_INVALID'}
 $vs=@(ConvertFrom-Json -InputObject (Query @('volume','inspect',$vn)))
 if($vs.Count -ne 1 -or [string]$vs[0].Name -cne $vn){throw 'VOLUME_MISSING'}
 $r.Add('[OK] CLEAN6_STOPPED_IMAGE_PINNED')
 $envlist=@($c.Config.Env|Where-Object {$_ -match '^PGDATA='})
 if($envlist.Count -ne 1){throw 'PGDATA_NOT_UNIQUE'}
 $pgdata=([string]$envlist[0]).Substring(7)
 if($pgdata -notmatch '^/var/lib/postgresql/data(?:/[A-Za-z0-9._/-]+)?$' -or $pgdata -match '(^|/)\.\.(/|$)'){throw 'PGDATA_PATH_INVALID'}
 $stage='SHELL_TEST'
 $base=@('run','--rm','--pull','never','--network','none','--read-only',
   '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64')
 $smoke=@('--user','postgres','--entrypoint','/bin/sh',$image,'-c','printf R62_SAFE_SHELL_OK')
 if(-not (Probe 'SHELL_WITHOUT_VOLUME' ($base+$smoke) 'R62_SAFE_SHELL_OK')){
   throw 'IMAGE_SHELL_PROBE_FAILED'
 }
 $stage='READONLY_MOUNT'
 $roMount=@('--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data,readonly'))
 $shell=@('--user','postgres','--entrypoint','/bin/sh',$image,'-c','printf R62_SAFE_MOUNT_OK')
 $mounted=Probe 'SHELL_WITH_READONLY_VOLUME' ($base+$roMount+$shell) 'R62_SAFE_MOUNT_OK'
 $stage='VOLUME_CONTENT'
 if($mounted){
  $simple='if [ -d "$PGDATA" ]; then printf "PGDATA_KIND=DIR\n"; if [ -r "$PGDATA" ]; then printf "PGDATA_READABLE=YES\n"; else printf "PGDATA_READABLE=NO\n"; fi; if [ -n "$(find "$PGDATA" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then printf "PGDATA_EMPTY=NO"; else printf "PGDATA_EMPTY=YES"; fi; elif [ -e "$PGDATA" ]; then printf "PGDATA_KIND=OTHER"; else printf "PGDATA_KIND=MISSING"; fi'
  $old=$ErrorActionPreference
  try{
   $ErrorActionPreference='Continue'
   $raw=@(& docker @($base+$roMount+@('--env',('PGDATA='+$pgdata),'--user','postgres','--entrypoint','/bin/sh',$image,'-c',$simple)) 2>$null)
   $code=$LASTEXITCODE
  }catch{$code=-1;$raw=@()}finally{$ErrorActionPreference=$old}
  if($code -eq 0){
   $lines=@(($raw -join [Environment]::NewLine) -split '[\r\n]+' | Where-Object {$_ -ne ''})
   foreach($line in $lines){
    if($line -match '^PGDATA_KIND=(DIR|OTHER|MISSING)$' -or $line -match '^PGDATA_READABLE=(YES|NO)$' -or $line -match '^PGDATA_EMPTY=(YES|NO)$'){$r.Add($line)}
    else{throw 'PGDATA_OUTPUT_NOT_ALLOWLISTED'}
   }
   $r.Add('[OK] PGDATA_STATE_READ_ONLY_INSPECTED')
  }else{$r.Add('[BLOQUEADO] PGDATA_INSPECTION_FAILED')}
 } else {
   $r.Add('[BLOQUEADO] READONLY_MOUNT_FAILED_NO_CONTENT_CHECK')
 }
 $r.Add('[LIMITE] Docker shell probes on new ephemeral containers only')
 $r.Add('[LIMITE] No existing containers started or modified; volume mounted read-only')
 $r.Add('[NEXT] TARGET_SPECIFIC_DOCKER_VOLUME_FIX')
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]{3,100}$'){$reason='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
