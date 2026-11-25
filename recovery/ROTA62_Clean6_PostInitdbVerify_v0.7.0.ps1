# ROTA62 Guardian CLEAN6 - Post InitDB verification v0.7.0
# READ ONLY: inspect existing CLEAN6 and use ephemeral Docker shell with volume mounted READONLY.
# No initdb, postgres start, SQL, deletion, network, or exposure of file contents/secrets.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$reference='supabase_db_ROTA62_TESTE_SUPABASE'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 CLEAN6 POST-INITDB VERIFY v0.7.0 ===')
$report.Add('[MODO] READ_ONLY_PGDATA_FILES_NO_INITDB_NO_SQL')
$stage='IDENTITY'
$success=$false
function DockerGet([string[]]$argv) {
 $old=$ErrorActionPreference
 try {
  $ErrorActionPreference='Continue'
  $items=@(& docker @argv 2>$null)
  $exitcode=$LASTEXITCODE
 } catch {throw 'DOCKER_METADATA_EXCEPTION'} finally {$ErrorActionPreference=$old}
 if($exitcode -ne 0){throw 'DOCKER_METADATA_FAILED'}
 return (($items -join [Environment]::NewLine).Trim())
}
function Probe([string]$label,[string]$command) {
 $argsDocker=@('run','--rm','--pull','never','--network','none','--read-only',
   '--user','postgres','--cap-drop','ALL','--security-opt','no-new-privileges',
   '--pids-limit','64',
   '--mount',('type=volume,source='+$vn+',target=/var/lib/postgresql/data,readonly'),
   '--entrypoint','/bin/sh',$script:image,'-c',$command)
 $old=$ErrorActionPreference
 try {
  $ErrorActionPreference='Continue'
  $null=@(& docker @argsDocker 2>$null)
  $rc=$LASTEXITCODE
 }catch{$rc=-1}finally{$ErrorActionPreference=$old}
 if($rc -eq 0){$report.Add($label+'=YES');return $true}
 elseif($rc -eq 1){$report.Add($label+'=NO')}
 else{$report.Add($label+'=ERROR')}
 return $false
}
try{
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $cArr=@(ConvertFrom-Json -InputObject (DockerGet @('inspect',$cn)))
 $refArr=@(ConvertFrom-Json -InputObject (DockerGet @('inspect',$reference)))
 if($cArr.Count -ne 1 -or $refArr.Count -ne 1){throw 'DOCKER_INSPECT_COUNT_INVALID'}
 $c=$cArr[0];$ref=$refArr[0]
 if([string]$c.State.Status -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_MUST_BE_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_NOT_NONE'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CLEAN6_PORT_BINDINGS_PRESENT'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne $vn -or [string]$c.Mounts[0].Destination -cne '/var/lib/postgresql/data'){throw 'CLEAN6_MOUNT_UNEXPECTED'}
 if([string]$ref.Image -cne [string]$c.Image){throw 'PINNED_IMAGE_MISMATCH'}
 $script:image=[string]$c.Image
 if($script:image -cnotmatch '^sha256:[0-9a-f]{64}$'){throw 'IMAGE_ID_INVALID'}
 $vArr=@(ConvertFrom-Json -InputObject (DockerGet @('volume','inspect',$vn)))
 if($vArr.Count -ne 1 -or [string]$vArr[0].Name -cne $vn){throw 'CLEAN6_VOLUME_MISSING'}
 $active=DockerGet @('ps','--filter',('volume='+$vn),'--format','{{.ID}}')
 if($active.Trim().Length -ne 0){throw 'CLEAN6_VOLUME_IN_USE'}
 $pgdata=@($c.Config.Env|Where-Object {$_ -ceq 'PGDATA=/var/lib/postgresql/data'})
 if($pgdata.Count -ne 1){throw 'PGDATA_UNEXPECTED'}
 $report.Add('[OK] CLEAN6_STOPPED_IMAGE_PINNED_READONLY_PROBE')
 $stage='PGDATA_FILES'
 $root='/var/lib/postgresql/data'
 $file=$root+'/PG_VERSION'
 $exists=Probe 'PG_VERSION_FILE_EXISTS' ('test -f '+$file)
 $readable=Probe 'PG_VERSION_FILE_READABLE' ('test -r '+$file)
 $version17=Probe 'PG_VERSION_EQUALS_17' ('grep -qx 17 '+$file)
 $version16=Probe 'PG_VERSION_EQUALS_16' ('grep -qx 16 '+$file)
 $version18=Probe 'PG_VERSION_EQUALS_18' ('grep -qx 18 '+$file)
 $config=Probe 'POSTGRESQL_CONF_EXISTS' ('test -f '+$root+'/postgresql.conf')
 $hba=Probe 'PG_HBA_CONF_EXISTS' ('test -f '+$root+'/pg_hba.conf')
 $control=Probe 'PG_CONTROL_EXISTS' ('test -f '+$root+'/global/pg_control')
 $stage='HBA_POLICY'
 $peer=Probe 'HBA_LOCAL_PEER_RULE' ('grep -Eq '+"'"+'^local[[:space:]]+all[[:space:]]+all[[:space:]]+peer([[:space:]]|$)'+"'"+' '+$root+'/pg_hba.conf')
 $reject=Probe 'HBA_TCP_REJECT_RULE' ('grep -Eq '+"'"+'^host[[:space:]]+all[[:space:]]+all[[:space:]]+[^[:space:]]+[[:space:]]+reject([[:space:]]|$)'+"'"+' '+$root+'/pg_hba.conf')
 $report.Add('[LIMITE] Reads only fixed PostgreSQL files, never returns their contents')
 $report.Add('[LIMITE] No initdb repeat, no PostgreSQL start, no backup restoration')
 if($version17 -and $config -and $hba -and $control -and $peer -and $reject) {
  $report.Add('[APROVADO] PG17_CLUSTER_FILES_AND_AUTH_POLICY_VERIFIED')
  $report.Add('[NEXT] DESIGN_DIRECT_POSTGRES_START_WITHOUT_SUPABASE_HOOKS')
 }else{
  $report.Add('[BLOQUEADO] CLUSTER_FILES_OR_AUTH_RULES_NEED_REVIEW')
  $report.Add('[NEXT] INVESTIGATE_EXISTING_DATA_NO_RESET_NO_INITDB_REPEAT')
 }
 $success=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]{3,100}$'){$reason='LOCAL_ERROR_REDACTED'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $success){exit 1}
