# ROTA62 CLEAN6 v0.6.1 - verify image executables without reference container or docker cp
# Runs only /bin/sh built-in command -v and test -x inside ephemeral read-only
# --network none container WITHOUT mounting any existing volume.
# CLEAN6 remains stopped. No initdb execution, SQL, secrets, or backup access.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$ref='supabase_db_ROTA62_TESTE_SUPABASE'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 IMAGE EXECUTABLE CHECK v0.6.1 ===')
$r.Add('[MODO] EPHEMERAL_READ_ONLY_NETWORK_NONE_NO_VOLUME_MOUNT')
$stage='PRECHECK'
$success=$false
function D([string[]]$a) {
 $o=@(& docker @a 2>$null)
 if($LASTEXITCODE -ne 0){throw 'DOCKER_QUERY_FAILED'}
 return (($o -join [Environment]::NewLine).Trim())
}
function Quiet([string[]]$a) {
 $old=$ErrorActionPreference
 try{
  $ErrorActionPreference='Continue'
  $null=@(& docker @a 2>$null)
  return ($LASTEXITCODE -eq 0)
 } catch {return $false} finally {$ErrorActionPreference=$old}
}
try {
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $stage='INSPECT'
 $objects=@(ConvertFrom-Json -InputObject (D @('inspect',$cn)))
 if($objects.Count -ne 1){throw 'CLEAN6_INSPECT_INVALID'}
 $c=$objects[0]
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_NOT_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NOT_ISOLATED'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn){throw 'CLEAN6_VOLUME_UNEXPECTED'}
 $reference=@(ConvertFrom-Json -InputObject (D @('inspect',$ref)))
 if($reference.Count -ne 1 -or [string]$reference[0].Image -cne [string]$c.Image){throw 'PINNED_IMAGE_MISMATCH'}
 $image=[string]$c.Image
 if($image -cnotmatch '^sha256:[0-9a-f]{64}$'){throw 'IMAGE_FORMAT_INVALID'}
 $r.Add('[OK] CLEAN6_STOPPED_SAME_IMAGE_AS_REFERENCE')
 $stage='IMAGE_SHELL'
 $base=@('run','--rm','--pull','never','--network','none','--read-only',
   '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64',
   '--user','postgres','--entrypoint','/bin/sh',$image,'-c')
 if(-not (Quiet ($base+@('test -x /bin/sh')))){throw 'IMAGE_SHELL_NOT_EXECUTABLE'}
 $r.Add('[OK] EPHEMERAL_SHELL_WORKS_NO_VOLUME_MOUNT')
 $stage='IMAGE_PATHS'
 $both=$true
 foreach($name in @('postgres','initdb')) {
  $nameUpper=$name.ToUpperInvariant()
  $old=$ErrorActionPreference
  try{
   $ErrorActionPreference='Continue'
   $lines=@(& docker @($base+@('command -v '+$name)) 2>$null)
   $code=$LASTEXITCODE
  }catch{$lines=@();$code=-1}finally{$ErrorActionPreference=$old}
  $path=($lines -join '').Trim()
  if($code -ne 0 -or $path -cnotmatch '^/[A-Za-z0-9._/-]{5,200}$' -or $path -match '(^|/)\.\.(/|$)'){
   $r.Add('IMAGE_'+$nameUpper+'_PATH=NOT_CONFIRMED')
   $both=$false
   continue
  }
  $r.Add('IMAGE_'+$nameUpper+'_PATH=FOUND')
  $r.Add('IMAGE_'+$nameUpper+'_CATEGORY='+$(if($path.StartsWith('/usr/local/')){'USR_LOCAL'}elseif($path.StartsWith('/usr/lib/postgresql/')){'USR_LIB_POSTGRESQL'}else{'OTHER_ABSOLUTE'}))
  if(Quiet ($base+@('test -x '+$path))){
   $r.Add('IMAGE_'+$nameUpper+'_EXECUTABLE=YES')
  }else{
   $r.Add('IMAGE_'+$nameUpper+'_EXECUTABLE=NO')
   $both=$false
  }
 }
 $r.Add('[OK] CLEAN6_WAS_NOT_STARTED')
 $r.Add('[OK] NO_EXISTING_VOLUMES_MOUNTED')
 $r.Add('[LIMITE] Shell probes only; no initdb process run or database changes')
 if($both){$r.Add('[APROVADO] BOTH_IMAGE_EXECUTABLES_VERIFIED')}
 else{$r.Add('[BLOQUEADO] IMAGE_EXECUTABLE_PATHS_REQUIRE_NEW_INIT_PLAN')}
 $r.Add('[NEXT] INITDB_DIRECTLY_FROM_PINNED_IMAGE_NO_DOCKER_CP')
 $success=$both
}catch{
 $msg=[string]$_.Exception.Message
 if($msg -cnotmatch '^[A-Z0-9_]{3,100}$'){$msg='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$msg)
}finally{
 $report=$r -join [Environment]::NewLine
 Write-Output $report
 try{Set-Clipboard -Value $report -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
