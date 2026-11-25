# ROTA62 CLEAN6 v0.6.5 — minimal read-only volume inspection
# Only Docker inspect + ephemeral no-network /bin/sh, volume mounted readonly.
# No initdb, SQL, backup, PGDATA filenames/contents, credentials or raw errors exposed.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$ref='supabase_db_ROTA62_TESTE_SUPABASE'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 MINIMAL VOLUME INSPECTION v0.6.5 ===')
$r.Add('[MODO] READONLY_MOUNT_NO_INITDB_NO_SQL')
$stage='PRECHECK';$ok=$false
function D([string[]]$a) {
 $prev=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$data=@(& docker @a 2>$null);$exit=$LASTEXITCODE}
 catch{throw 'DOCKER_METADATA_QUERY_EXCEPTION'}
 finally{$ErrorActionPreference=$prev}
 if($exit -ne 0){throw 'DOCKER_METADATA_QUERY_FAILED'}
 return ($data -join [Environment]::NewLine).Trim()
}
function Check([string]$label,[string]$sh) {
 $argsRun=@('run','--rm','--pull','never','--network','none','--read-only',
  '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64',
  '--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data,readonly'),
  '--user','postgres','--entrypoint','/bin/sh',$script:image,'-c',$sh)
 $prev=$ErrorActionPreference;$code=-1
 try {
  $ErrorActionPreference='Continue'
  # No stdout from probes. Redirect stderr to an in-memory variable; never report raw text.
  $raw=@(& docker @argsRun 2>&1)
  $code=$LASTEXITCODE
 }catch{$code=-1;$raw=@()}finally{$ErrorActionPreference=$prev}
 if($code -eq 0){$r.Add($label+'=YES');return $true}
 if($code -eq 1){$r.Add($label+'=NO');return $false}
 if($code -eq 2){$r.Add($label+'=SHELL_TEST_ERROR');return $false}
 if(($raw -join ' ') -match '(?i)permission denied|operation not permitted'){$r.Add($label+'=PERMISSION_ERROR')}
 elseif(($raw -join ' ') -match '(?i)OCI runtime|container init'){$r.Add($label+'=DOCKER_RUNTIME_ERROR')}
 else{$r.Add($label+'=OTHER_NONZERO')}
 return $false
}
try{
 $stage='IDENTITY'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $a=@(ConvertFrom-Json -InputObject (D @('inspect',$cn)))
 $b=@(ConvertFrom-Json -InputObject (D @('inspect',$ref)))
 if($a.Count -ne 1 -or $b.Count -ne 1){throw 'LAB_INSPECT_INVALID'}
 $c=$a[0];$p=$b[0]
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_NOT_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_MISMATCH'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn){throw 'CLEAN6_VOLUME_MISMATCH'}
 if([string]$c.Image -cne [string]$p.Image){throw 'IMAGE_MISMATCH'}
 $script:image=[string]$c.Image
 if($script:image -cnotmatch '^sha256:[a-f0-9]{64}$'){throw 'IMAGE_FORMAT_INVALID'}
 $volume=@(ConvertFrom-Json -InputObject (D @('volume','inspect',$vn)))
 if($volume.Count -ne 1 -or [string]$volume[0].Name -cne $vn){throw 'VOLUME_MISSING'}
 $running=D @('ps','--filter',('volume='+$vn),'--format','{{.ID}}')
 if($running.Trim()){throw 'VOLUME_USED_BY_RUNNING_CONTAINER'}
 $envdata=@($c.Config.Env|Where-Object {$_ -match '^PGDATA='})
 if($envdata.Count -ne 1){throw 'PGDATA_ENV_INVALID'}
 $pgdata=([string]$envdata[0]).Substring(7)
 if($pgdata -notmatch '^/var/lib/postgresql/data(?:/[a-zA-Z0-9._/-]+)?$' -or $pgdata -match '(^|/)\.\.(/|$)'){throw 'PGDATA_PATH_REJECTED'}
 $r.Add('[OK] CLEAN6_STOPPED_AND_VOLUME_ISOLATED')
 $r.Add('PGDATA_RELATIVE_SUBDIRECTORY='+$(if($pgdata -ceq '/var/lib/postgresql/data'){'NO'}else{'YES'}))
 $stage='MINIMAL_PROBES'
 # All probes avoid PGDATA env interpolation and sensitive output.
 $null=Check 'MOUNT_ROOT_DIRECTORY_EXISTS' 'test -d /var/lib/postgresql/data'
 $null=Check 'MOUNT_ROOT_READABLE' 'test -r /var/lib/postgresql/data'
 $null=Check 'MOUNT_ROOT_TRAVERSABLE' 'test -x /var/lib/postgresql/data'
 $null=Check 'MOUNT_ROOT_HAS_ANY_ENTRY' 'test -n "$(ls -A /var/lib/postgresql/data 2>/dev/null)"'
 if($pgdata -ceq '/var/lib/postgresql/data'){
  $r.Add('PGDATA_IS_ROOT=YES')
 }else{
  # Only validated path supplied as a shell positional argument; never returned to clipboard.
  $sh='test -d "$1"'
  $base=@('run','--rm','--pull','never','--network','none','--read-only',
   '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64',
   '--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data,readonly'),
   '--user','postgres','--entrypoint','/bin/sh',$script:image,'-c',$sh,'r62check',$pgdata)
  $prev=$ErrorActionPreference;$exit=-1
  try{$ErrorActionPreference='Continue';$null=@(& docker @base 2>$null);$exit=$LASTEXITCODE}
  catch{$exit=-1}finally{$ErrorActionPreference=$prev}
  $r.Add('PGDATA_DIRECTORY_EXISTS='+$(if($exit -eq 0){'YES'}elseif($exit -eq 1){'NO'}else{'ERROR'}))
 }
 $r.Add('[LIMITE] Only existence and access tests, not a proof of writable ownership')
 $r.Add('[LIMITE] No database processes or data writes performed')
 $r.Add('[NEXT] RESOLVE_VOLUME_PERMISSION_OR_ROOT_ENTRIES_BEFORE_INITDB')
 $ok=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]{3,100}$'){$reason='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
