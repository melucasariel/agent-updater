# ROTA62 CLEAN6 boot design preflight v0.5.8
# READ ONLY: inspect stopped Docker container, copy small startup scripts for local static checks.
# No Docker run/start/exec, no SQL, no secrets or full paths in clipboard.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$container='rota62_guardian_clean6_pg'
$volume='rota62_guardian_clean6_data'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 CONTROLLED BOOT PLAN v0.5.8 ===')
$r.Add('[MODO] READ_ONLY_NO_START_NO_RESTORE')
$stage='INIT';$ok=$false;$tmp=$null
function D([string[]]$arguments) {
  $out=@(& docker @arguments 2>$null)
  if($LASTEXITCODE -ne 0){throw 'DOCKER_QUERY_FAILED'}
  return (($out -join [Environment]::NewLine).Trim())
}
function CopyOne([string]$src,[string]$dest) {
  $old=$ErrorActionPreference
  try {
    $ErrorActionPreference='Continue'
    $null=@(& docker cp ($container+':'+$src) $dest 2>$null)
    return ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $dest -PathType Leaf))
  } catch {return $false} finally {$ErrorActionPreference=$old}
}
try{
  $stage='SAFETY'
  if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_NOT_FOUND'}
  $obj=@(ConvertFrom-Json -InputObject (D @('inspect',$container)))
  if($obj.Count -ne 1){throw 'CLEAN6_INSPECT_COUNT_INVALID'}
  $c=$obj[0]
  if([string]$c.State.Status -cne 'created' -or $c.State.Running -ne $false){throw 'CLEAN6_NOT_STOPPED'}
  if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_NOT_NONE'}
  if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CLEAN6_PORTS_NOT_EMPTY'}
  if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $volume){throw 'CLEAN6_VOLUME_UNEXPECTED'}
  $r.Add('[OK] STOPPED_CONTAINER_ISOLATED')
  $stage='IMAGE_COMMANDS'
  $entry=@($c.Config.Entrypoint|Where-Object {$_ -ne $null -and [string]$_ -ne ''})
  $cmd=@($c.Config.Cmd|Where-Object {$_ -ne $null -and [string]$_ -ne ''})
  $firstEntry=$(if($entry.Count -gt 0){[string]$entry[0]}else{''})
  $firstCmd=$(if($cmd.Count -gt 0){[string]$cmd[0]}else{''})
  $r.Add('IMAGE_ENTRYPOINT_KIND='+$(if($firstEntry -match '(?i)entrypoint'){ 'ENTRYPOINT_SCRIPT' }elseif($firstEntry -match '(?i)(bash|sh)$'){'SHELL'}else{'OTHER'}))
  $r.Add('IMAGE_CMD_KIND='+$(if($firstCmd -match '(^|/)postgres$'){'POSTGRES'}elseif($firstCmd -match '(^|/)pg_ctl$'){'PG_CTL'}else{'OTHER'}))
  $r.Add('IMAGE_CMD_EXTRA_ARGUMENTS='+[Math]::Max(0,$cmd.Count-1))
  $stage='IMAGE_ENV'
  $names=@($c.Config.Env | ForEach-Object {([string]$_ -split '=',2)[0]})
  $r.Add('PGDATA_NAME_PRESENT='+($names -contains 'PGDATA'))
  $r.Add('POSTGRES_PASSWORD_NAME_PRESENT='+($names -contains 'POSTGRES_PASSWORD'))
  $r.Add('PGUSER_NAME_PRESENT='+($names -contains 'PGUSER'))
  $stage='POSTGRES_EXECUTABLES'
  $tmp=Join-Path $env:TEMP ('R62-bootplan-'+[guid]::NewGuid().ToString('N'))
  $null=New-Item -ItemType Directory -Path $tmp -Force
  # docker cp works on stopped images and reads source only, without process execution.
  $candidates=@(
    @('/usr/lib/postgresql/17/bin/postgres','POSTGRES17'),
    @('/usr/lib/postgresql/17/bin/initdb','INITDB17'),
    @('/usr/local/bin/postgres','POSTGRES_USRLOCAL'),
    @('/usr/local/bin/initdb','INITDB_USRLOCAL'),
    @('/usr/local/bin/docker-entrypoint.sh','DEFAULT_ENTRYPOINT')
  )
  $found=@{}
  foreach($candidate in $candidates){
    $dest=Join-Path $tmp ($candidate[1]+'.bin')
    if(CopyOne ([string]$candidate[0]) $dest){
      $fi=Get-Item -LiteralPath $dest
      if($fi.Length -gt 52428800){throw 'COPIED_EXECUTABLE_SIZE_LIMIT'}
      $found[$candidate[1]]=$true
      $r.Add('IMAGE_FILE_'+$candidate[1]+'=PRESENT')
    }else{
      $r.Add('IMAGE_FILE_'+$candidate[1]+'=NOT_VERIFIED')
    }
  }
  $stage='INIT_HOOK_HANDLING'
  $r.Add('DEFAULT_ENTRYPOINT_INIT_HOOKS=UNVERIFIED_RUNTIME_BEHAVIOR')
  $r.Add('DESIGN=SEPARATE_INITDB_AND_POSTGRES_WITH_EXPLICIT_FLAGS')
  $r.Add('DESIGN_NETWORK=NONE')
  $r.Add('DESIGN_AUTO_HOOKS=DO_NOT_RUN')
  $r.Add('DESIGN_BACKGROUND_WORKERS=OFF_FOR_INITIAL_RECOVERY')
  $r.Add('[LIMITE] Binary files were identified but not executed; no image runtime certified')
  $r.Add('[LIMITE] This script does not create, start, or change containers')
  if((!$found.ContainsKey('POSTGRES17') -and !$found.ContainsKey('POSTGRES_USRLOCAL')) -or
     (!$found.ContainsKey('INITDB17') -and !$found.ContainsKey('INITDB_USRLOCAL'))){
    $r.Add('[BLOQUEADO] POSTGRES_AND_INITDB_PATHS_NOT_BOTH_VERIFIED')
  }else{
    $r.Add('[APROVADO] CONTROLLED_BOOT_EXECUTABLES_IDENTIFIED')
    $ok=$true
  }
}catch{
  $m=[string]$_.Exception.Message
  if($m -cnotmatch '^[A-Z0-9_]{3,90}$'){$m='LOCAL_ERROR_REDACTED'}
  $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$m)
}finally{
  if($tmp -and (Test-Path -LiteralPath $tmp)){Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue}
  $output=$r -join [Environment]::NewLine
  Write-Output $output
  try{Set-Clipboard -Value $output -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
