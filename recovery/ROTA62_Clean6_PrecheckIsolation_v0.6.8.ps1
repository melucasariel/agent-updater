# ROTA62 CLEAN6 v0.6.8 - pinpoint failed combined preflight (read-only)
# Never runs initdb or PostgreSQL; no writes, SQL, secrets, or network.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$ref='supabase_db_ROTA62_TESTE_SUPABASE'
$r=[System.Collections.Generic.List[string]]::new()
$r.Add('=== ROTA62 CLEAN6 PRECHECK ISOLATION v0.6.8 ===')
$r.Add('[MODO] DIAGNOSTIC_ONLY_NO_INITDB_NO_WRITE')
$stage='IDENTITY';$ok=$false
function ReadDocker([string[]]$a){
 $prev=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$lines=@(& docker @a 2>$null);$rc=$LASTEXITCODE}
 catch{throw 'DOCKER_METADATA_EXCEPTION'}finally{$ErrorActionPreference=$prev}
 if($rc -ne 0){throw 'DOCKER_METADATA_FAILED'}
 return ($lines -join [Environment]::NewLine).Trim()
}
function TestShell([string]$label,[string]$script){
 $argsDocker=@('run','--rm','--pull','never','--network','none','--read-only',
  '--user','postgres','--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','128',
  '--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data,readonly'),
  '--env','PGDATA=/var/lib/postgresql/data','--entrypoint','/bin/sh',$script:image,'-c',$script)
 $prev=$ErrorActionPreference
 try{$ErrorActionPreference='Continue';$null=@(& docker @argsDocker 2>$null);$rc=$LASTEXITCODE}
 catch{$rc=-1}finally{$ErrorActionPreference=$prev}
 $v=$(if($rc -eq 0){'YES'}elseif($rc -eq 1){'NO'}else{'ERROR'})
 $r.Add($label+'='+$v)
 return ($rc -eq 0)
}
try{
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $cl=@(ConvertFrom-Json -InputObject (ReadDocker @('inspect',$cn)))
 $rr=@(ConvertFrom-Json -InputObject (ReadDocker @('inspect',$ref)))
 if($cl.Count -ne 1 -or $rr.Count -ne 1){throw 'INSPECT_COUNT_INVALID'}
 $c=$cl[0]
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_NOT_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_MISMATCH'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn){throw 'VOLUME_MISMATCH'}
 if([string]$c.Image -cne [string]$rr[0].Image){throw 'IMAGE_MISMATCH'}
 $script:image=[string]$c.Image
 if($script:image -cnotmatch '^sha256:[0-9a-f]{64}$'){throw 'IMAGE_ID_INVALID'}
 $envvar=@($c.Config.Env|Where-Object {$_ -ceq 'PGDATA=/var/lib/postgresql/data'})
 if($envvar.Count -ne 1){throw 'PGDATA_UNEXPECTED'}
 $v=@(ConvertFrom-Json -InputObject (ReadDocker @('volume','inspect',$vn)))
 if($v.Count -ne 1 -or [string]$v[0].Name -cne $vn){throw 'VOLUME_MISSING'}
 if((ReadDocker @('ps','--filter',('volume='+$vn),'--format','{{.ID}}')).Length -gt 0){throw 'VOLUME_IN_USE'}
 $r.Add('[OK] STOPPED_IMAGE_AND_VOLUME_PINNED')
 $stage='SHELL_CHECKS'
 $null=TestShell 'PGDATA_ENV_PRESENT' 'test -n "$PGDATA"'
 $null=TestShell 'VOLUME_ROOT_DIR' 'test -d /var/lib/postgresql/data'
 $null=TestShell 'VOLUME_ROOT_TRAVERSABLE' 'test -x /var/lib/postgresql/data'
 # Readonly-mount deliberately makes test -w inapplicable; test same flag in RW mount
 # through an independent shell invocation that performs no writes.
 $null=TestShell 'BINARY_INITDB_IN_PATH' 'command -v initdb >/dev/null'
 $null=TestShell 'BINARY_POSTGRES_IN_PATH' 'command -v postgres >/dev/null'
 $null=TestShell 'VOLUME_ROOT_EMPTY' 'test -z "$(find /var/lib/postgresql/data -mindepth 1 -maxdepth 1 -print -quit)"'
 $null=TestShell 'SHELL_QUOTES_PRESERVED' 'test x"$PGDATA" = x/var/lib/postgresql/data'
 $r.Add('[LIMITE] Readonly volume tests cannot prove write permission; v0.6.6 verified it separately')
 $r.Add('[LIMITE] No initdb, SQL, file modifications or cleanup')
 $r.Add('[NEXT] FIX_QUOTING_OR_SPECIFIC_FAILED_CHECK_NO_RESET')
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
