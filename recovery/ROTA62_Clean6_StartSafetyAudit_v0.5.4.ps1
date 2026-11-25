# ROTA62 Guardian CLEAN6 - stopped container start-safety audit v0.5.4
# Windows PowerShell 5.1. Read-only Docker metadata audit. No starts, writes, SQL or secrets output.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cn='rota62_guardian_clean6_pg'
$vn='rota62_guardian_clean6_data'
$ref='supabase_db_ROTA62_TESTE_SUPABASE'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 START-SAFETY AUDIT v0.5.4 ===')
$r.Add('[MODO] DOCKER_INSPECT_ONLY_NO_START_NO_SQL')
$stage='START'
$pass=$false
function D([string[]]$arguments) {
 $lines=@(& docker @arguments 2>$null)
 if($LASTEXITCODE -ne 0){throw 'DOCKER_INSPECT_FAILED'}
 return (($lines -join [Environment]::NewLine).Trim())
}
function FullInspect([string]$name) {
 $raw=D @('inspect',$name)
 $objects=@(ConvertFrom-Json -InputObject $raw)
 if($objects.Count -ne 1){throw 'INSPECT_OBJECT_COUNT_INVALID'}
 return $objects[0]
}
try{
 $stage='DOCKER'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $null=D @('info','--format','{{.ServerVersion}}')
 $stage='CLEAN6_CONTAINER'
 $c=FullInspect $cn
 $state=[string]$c.State.Status
 if($state -cne 'created' -or [bool]$c.State.Running){throw 'CLEAN6_NOT_STOPPED'}
 $r.Add('[OK] CLEAN6_CREATED_NOT_RUNNING')
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NETWORK_NOT_NONE'}
 if([string]$c.HostConfig.RestartPolicy.Name -cne 'no'){throw 'CLEAN6_RESTART_POLICY_NOT_NO'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CLEAN6_PORTS_PRESENT'}
 if($c.NetworkSettings -and $c.NetworkSettings.Ports) {
  $published=@($c.NetworkSettings.Ports.PSObject.Properties | Where-Object {$_.Value})
  if($published.Count -gt 0){throw 'CLEAN6_PUBLISHED_PORTS_PRESENT'}
 }
 $r.Add('[OK] NETWORK_NONE_NO_PUBLISHED_PORTS_NO_RESTART')
 $stage='VOLUME'
 $vRaw=D @('volume','inspect',$vn)
 $volumes=@(ConvertFrom-Json -InputObject $vRaw)
 if($volumes.Count -ne 1 -or [string]$volumes[0].Name -cne $vn){throw 'CLEAN6_VOLUME_MISSING'}
 $mount=@($c.Mounts|Where-Object {$_.Destination -ceq '/var/lib/postgresql/data'})
 if($mount.Count -ne 1 -or [string]$mount[0].Type -cne 'volume' -or [string]$mount[0].Name -cne $vn -or $mount[0].RW -ne $true){throw 'CLEAN6_VOLUME_MAPPING_UNEXPECTED'}
 if(@($c.Mounts).Count -ne 1){throw 'CLEAN6_UNEXPECTED_EXTRA_MOUNTS'}
 $r.Add('[OK] CLEAN6_EXCLUSIVE_NAMED_VOLUME_MOUNT')
 $stage='IMAGE_IDENTITY'
 $refContainer=FullInspect $ref
 $image=[string]$refContainer.Image
 if($image -cnotmatch '^sha256:[0-9a-f]{64}$' -or [string]$c.Image -cne $image){throw 'CLEAN6_REFERENCE_IMAGE_MISMATCH'}
 $imRaw=D @('image','inspect',$image)
 $im=@(ConvertFrom-Json -InputObject $imRaw)
 if($im.Count -ne 1 -or [string]$im[0].Id -cne $image){throw 'CLEAN6_LOCAL_IMAGE_ID_MISMATCH'}
 $r.Add('[OK] IMAGE_MATCHES_EXISTING_SUPABASE_LAB')
 $stage='STARTUP_PROPERTIES'
 $entry=@($c.Config.Entrypoint|Where-Object {$_})
 $cmd=@($c.Config.Cmd|Where-Object {$_})
 $imgEntry=@($im[0].Config.Entrypoint|Where-Object {$_})
 $imgCmd=@($im[0].Config.Cmd|Where-Object {$_})
 $entryEncoded=ConvertTo-Json -InputObject $entry -Compress
 $cmdEncoded=ConvertTo-Json -InputObject $cmd -Compress
 if($entryEncoded -cne (ConvertTo-Json -InputObject $imgEntry -Compress) -or $cmdEncoded -cne (ConvertTo-Json -InputObject $imgCmd -Compress)){throw 'CLEAN6_START_COMMAND_OVERRIDDEN'}
 $r.Add('[OK] ENTRYPOINT_AND_CMD_MATCH_IMAGE_DEFAULTS')
 $flags=@([string]$c.HostConfig.Privileged,[string]$c.HostConfig.ReadonlyRootfs)
 if($c.HostConfig.Privileged -eq $true){throw 'PRIVILEGED_CONTAINER_NOT_ALLOWED'}
 if($c.HostConfig.CapAdd -and @($c.HostConfig.CapAdd).Count -gt 0){throw 'EXTRA_CAPABILITIES_PRESENT'}
 if($c.HostConfig.CapDrop -and -not (@($c.HostConfig.CapDrop) -contains 'ALL')){throw 'CAP_DROP_ALL_NOT_CONFIRMED'}
 if(@($c.HostConfig.SecurityOpt) -notcontains 'no-new-privileges'){throw 'NO_NEW_PRIVILEGES_NOT_CONFIRMED'}
 $r.Add('[OK] CONTAINER_NOT_PRIVILEGED_AND_CAPABILITIES_DROPPED')
 # No environment or entrypoint text is printed, because image env may contain secrets.
 $stage='RUNTIME_RISKS'
 $r.Add('[LIMITE] Image entrypoint/init scripts were not executed or semantically audited')
 $r.Add('[LIMITE] pg_cron/pg_net/background workers still require safe startup design')
 $r.Add('[LIMITE] Named volume emptiness and free disk capacity not certified by inspect')
 $r.Add('[APROVADO] STOPPED_CONTAINER_ISOLATION_AND_IMAGE_IDENTITY')
 $r.Add('[PROXIMO] BUILD_EXPLICIT_LOCAL_ONLY_POSTGRES_START_AND_INIT_CONTROL')
 $pass=$true
}catch{
 $msg=[string]$_.Exception.Message
 if($msg -cnotmatch '^[A-Z0-9_]+$'){$msg='DOCKER_METADATA_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$msg)
}finally{
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $pass){exit 1}
