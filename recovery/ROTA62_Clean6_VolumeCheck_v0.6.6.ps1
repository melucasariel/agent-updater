# ROTA62 CLEAN6 v0.6.6 - direct volume occupancy and permission check
# Strictly read-only probes on disposable CLEAN6 volume, with network disabled.
# No clean6 start, PostgreSQL commands, initdb, SQL, secret output or deletion.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$ref='supabase_db_ROTA62_TESTE_SUPABASE'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN6 VOLUME CHECK v0.6.6 ===')
$report.Add('[MODO] READ_ONLY_FIND_AND_PERMISSION_TEST_NO_INITDB')
$stage='IDENTITY'
$success=$false
function DockerRead([string[]]$a) {
 $prior=$ErrorActionPreference
 try {
  $ErrorActionPreference='Continue'
  $rows=@(& docker @a 2>$null)
  $code=$LASTEXITCODE
 } catch {throw 'DOCKER_METADATA_EXCEPTION'}
 finally {$ErrorActionPreference=$prior}
 if($code -ne 0){throw 'DOCKER_METADATA_FAILED'}
 return ($rows -join [Environment]::NewLine).Trim()
}
function RunProbe([string]$name,[string[]]$a) {
 $prior=$ErrorActionPreference
 $stdout=@();$code=-1
 try {
  $ErrorActionPreference='Continue'
  $stdout=@(& docker @a 2>$null)
  $code=$LASTEXITCODE
 } catch {$code=-1}
 finally {$ErrorActionPreference=$prior}
 return [pscustomobject]@{Label=$name;Exit=$code;Stdout=($stdout -join [Environment]::NewLine)}
}
try {
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_NOT_FOUND'}
 $cList=@(ConvertFrom-Json -InputObject (DockerRead @('inspect',$cn)))
 $rList=@(ConvertFrom-Json -InputObject (DockerRead @('inspect',$ref)))
 if($cList.Count -ne 1 -or $rList.Count -ne 1){throw 'INSPECT_COUNT_INVALID'}
 $c=$cList[0];$r=$rList[0]
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_NOT_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_NOT_NONE'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CLEAN6_PORT_BINDINGS_NOT_EMPTY'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn -or [string]$c.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'CLEAN6_VOLUME_MISMATCH'}
 if([string]$r.Image -cne [string]$c.Image){throw 'IMAGE_MISMATCH'}
 $image=[string]$c.Image
 if($image -cnotmatch '^sha256:[0-9a-f]{64}$'){throw 'IMAGE_DIGEST_INVALID'}
 $vList=@(ConvertFrom-Json -InputObject (DockerRead @('volume','inspect',$vn)))
 if($vList.Count -ne 1 -or [string]$vList[0].Name -cne $vn){throw 'VOLUME_MISSING'}
 $used=DockerRead @('ps','--filter',('volume='+$vn),'--format','{{.ID}}')
 if($used.Length -gt 0){throw 'VOLUME_ACTIVE_CONSUMER'}
 $env=@($c.Config.Env|Where-Object {$_ -match '^PGDATA='})
 if($env.Count -ne 1 -or [string]$env[0] -cne 'PGDATA=/var/lib/postgresql/data'){throw 'PGDATA_NOT_VOLUME_ROOT'}
 $report.Add('[OK] CLEAN6_STOPPED_EXCLUSIVE_VOLUME_ROOT')
 $stage='CONTENT_PROBE'
 $base=@('run','--rm','--pull','never','--network','none','--read-only',
  '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64',
  '--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data,readonly'),
  '--user','postgres','--entrypoint','/bin/sh',$image,'-c')
 # find returns 0 on success; stdout is captured but NEVER included in report.
 $occupancy=RunProbe 'FIND' ($base+@('find /var/lib/postgresql/data -mindepth 1 -maxdepth 1 -print -quit'))
 if($occupancy.Exit -ne 0){$report.Add('FIND_STATUS=ERROR');throw 'FIND_READONLY_FAILED'}
 if($occupancy.Stdout.Length -eq 0){$report.Add('PGDATA_OCCUPANCY=EMPTY')}
 else{$report.Add('PGDATA_OCCUPANCY=HAS_ENTRIES')}
 $stage='PERMISSION_PROBES'
 # Shell test only, no writes. The first uses a read-only volume; the second
 # mounts CLEAN6 RW but still executes only test -w (does not create files).
 $access=RunProbe 'TRAVERSE' ($base+@('test -x /var/lib/postgresql/data'))
 if($access.Exit -eq 0){$report.Add('POSTGRES_CAN_TRAVERSE=YES')}
 elseif($access.Exit -eq 1){$report.Add('POSTGRES_CAN_TRAVERSE=NO')}
 else{$report.Add('POSTGRES_CAN_TRAVERSE=ERROR')}
 $rwbase=@('run','--rm','--pull','never','--network','none','--read-only',
  '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64',
  '--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data'),
  '--user','postgres','--entrypoint','/bin/sh',$image,'-c')
 $write=RunProbe 'WRITABLE' ($rwbase+@('test -w /var/lib/postgresql/data'))
 if($write.Exit -eq 0){$report.Add('POSTGRES_CAN_WRITE=YES')}
 elseif($write.Exit -eq 1){$report.Add('POSTGRES_CAN_WRITE=NO')}
 else{$report.Add('POSTGRES_CAN_WRITE=ERROR')}
 $report.Add('[OK] VOLUME_STATE_CLASSIFIED')
 $report.Add('[LIMITE] No files created/deleted, no SQL/initdb, no secrets or filenames emitted')
 if($occupancy.Stdout.Length -eq 0 -and $write.Exit -eq 0){
  $report.Add('[NEXT] CLEAN6_DIRECT_INITDB_WITH_EXPLICIT_SAFE_PREFLIGHT')
 }else{
  $report.Add('[NEXT] INVESTIGATE_EXISTING_ENTRIES_OR_VOLUME_PERMISSIONS_NO_RESET')
 }
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]{3,100}$'){$reason='LOCAL_ERROR_REDACTED'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop; Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
