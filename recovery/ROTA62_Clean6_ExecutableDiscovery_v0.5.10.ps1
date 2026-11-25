# ROTA62 CLEAN6 v0.5.10 - PostgreSQL executable discovery (safe read-only)
# Does not start CLEAN6 or change reference lab; no SQL; no credentials or executable paths printed.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$clean='rota62_guardian_clean6_pg'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 EXECUTABLE DISCOVERY v0.5.10 ===')
$r.Add('[MODO] READ_ONLY_REFERENCE_LOCAL_NO_SQL')
$stage='INIT'
$ok=$false
function InspectOne([string]$name){
  $data=@(& docker inspect $name 2>$null)
  if($LASTEXITCODE -ne 0){throw 'DOCKER_INSPECT_FAILED'}
  $objects=@(ConvertFrom-Json -InputObject ($data -join [Environment]::NewLine))
  if($objects.Count -ne 1){throw 'DOCKER_INSPECT_COUNT_FAILED'}
  return $objects[0]
}
function FindBinary([string]$name){
  # Literal command; no expansion of shell variables by PowerShell.
  $command='command -v '+$name
  $old=$ErrorActionPreference
  try{
    $ErrorActionPreference='Continue'
    $lines=@(& docker exec --user postgres $reference sh -c $command 2>$null)
    $code=$LASTEXITCODE
  }catch{
    $r.Add('LOOKUP_'+$name.ToUpperInvariant()+'=EXECUTION_EXCEPTION')
    return $false
  }finally{$ErrorActionPreference=$old}
  if($code -ne 0){
    $r.Add('LOOKUP_'+$name.ToUpperInvariant()+'=NOT_IN_PATH_OR_SHELL_ERROR')
    return $false
  }
  $value=(($lines -join '')).Trim()
  if($value -cmatch '^/[A-Za-z0-9_./-]{3,200}$' -and $value -notmatch '\.\.'){
    $r.Add('LOOKUP_'+$name.ToUpperInvariant()+'=FOUND_ABSOLUTE_PATH')
    if($value.StartsWith('/usr/lib/postgresql/')){$r.Add('BIN_CATEGORY_'+$name.ToUpperInvariant()+'=USR_LIB_POSTGRESQL')}
    elseif($value.StartsWith('/usr/local/')){$r.Add('BIN_CATEGORY_'+$name.ToUpperInvariant()+'=USR_LOCAL')}
    else{$r.Add('BIN_CATEGORY_'+$name.ToUpperInvariant()+'=OTHER_ABSOLUTE')}
    return $true
  }
  $r.Add('LOOKUP_'+$name.ToUpperInvariant()+'=OUTPUT_NOT_ABSOLUTE_PATH')
  $r.Add('LOOKUP_'+$name.ToUpperInvariant()+'_LINE_COUNT='+$lines.Count)
  return $false
}
try{
  $stage='SAFETY'
  if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
  $c=InspectOne $clean
  $p=InspectOne $reference
  if([string]$c.State.Status -cne 'created' -or $c.State.Running -ne $false){throw 'CLEAN6_NOT_STOPPED'}
  if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_MISMATCH'}
  if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne 'rota62_guardian_clean6_data'){throw 'CLEAN6_VOLUME_MISMATCH'}
  if([string]$p.State.Status -cne 'running'){throw 'REFERENCE_NOT_RUNNING'}
  if([string]$c.Image -cne [string]$p.Image){throw 'IMAGE_MISMATCH'}
  $r.Add('[OK] CLEAN6_STOPPED_AND_REFERENCE_IMAGE_MATCH')
  $stage='EXECUTABLES'
  $postgres=FindBinary 'postgres'
  $initdb=FindBinary 'initdb'
  if(-not $postgres -or -not $initdb){
    # pg_config is a safe configuration-printing utility, not a database client.
    $old=$ErrorActionPreference
    try{
      $ErrorActionPreference='Continue'
      $bindir=@(& docker exec --user postgres $reference pg_config --bindir 2>$null)
      $code=$LASTEXITCODE
    }catch{$code=-1;$bindir=@()}finally{$ErrorActionPreference=$old}
    $pdir=(($bindir -join '')).Trim()
    if($code -eq 0 -and $pdir -match '^/[A-Za-z0-9_./-]{3,200}$' -and $pdir -notmatch '\.\.'){
      $r.Add('PG_CONFIG_BINDIR=AVAILABLE')
      $r.Add('PG_CONFIG_BINDIR_CATEGORY='+$(if($pdir.StartsWith('/usr/lib/postgresql/')){'USR_LIB_POSTGRESQL'}elseif($pdir.StartsWith('/usr/local/')){'USR_LOCAL'}else{'OTHER_ABSOLUTE'}))
      foreach($name in @('postgres','initdb')){
        $candidate=$pdir.TrimEnd('/')+'/'+$name
        $old=$ErrorActionPreference
        try{
          $ErrorActionPreference='Continue'
          $null=@(& docker exec --user postgres $reference test -x $candidate 2>$null)
          $code=$LASTEXITCODE
        }catch{$code=-1}finally{$ErrorActionPreference=$old}
        $r.Add('PG_CONFIG_BIN_'+$name.ToUpperInvariant()+'='+$(if($code -eq 0){'EXECUTABLE'}else{'NOT_VERIFIED'}))
      }
    }else{$r.Add('PG_CONFIG_BINDIR=NOT_VERIFIED')}
  }
  $r.Add('[LIMITE] Reference lab lookup only; CLEAN6 not started')
  $r.Add('[LIMITE] No postgres/initdb process launched; no SQL/restore')
  $r.Add('[NEXT] PREPARE_OFFLINE_BOOT_WITH_EXPLICIT_INIT_CONTROL')
  $ok=$true
}catch{
  $reason=[string]$_.Exception.Message
  if($reason -cnotmatch '^[A-Z0-9_]{3,90}$'){$reason='LOCAL_ERROR_REDACTED'}
  $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
  $out=$r -join [Environment]::NewLine
  Write-Output $out
  try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
