# ROTA62 LAB5 v0.15.4 - read-only bind-mount discovery
# Does NOT start containers, alter mounts, make HTTP calls, or change SQL/production.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$container='rota62_guardian_lab5_dispatch_v012'
$expected='D:\ROTA62_GUARDIAN\LAB5_DISPATCH_ORIGINAL_v0.12'
$expectedIndex='ACFEB7E6F708DF3A932DD47A64DB70A937B1343D0EE26E069041729936C16CF8'
$expectedAdapter='42FB1E25CB3B6243D37308726C3BA91C3ADEDF86A7A908659AE54ED9ABFFB3D6'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 LAB5 MOUNT DIAGNOSTIC v0.15.4 ===')
$report.Add('[MODO] READ_ONLY_CONTAINER_INSPECT_NO_MUTATION')
$stage='START'
try {
 $stage='INSPECT'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 $raw=@(& docker inspect $container 2>$null)
 if($LASTEXITCODE -ne 0 -or $raw.Count -eq 0){throw 'CONTAINER_INSPECT_FAILED'}
 $d=@($raw -join [Environment]::NewLine | ConvertFrom-Json)[0]
 if(-not $d -or $d.State.Status -cne 'running'){throw 'CONTAINER_NOT_RUNNING'}
 if([string]$d.HostConfig.NetworkMode -cne 'rota62_guardian_fifth_internal'){throw 'NETWORK_NOT_EXPECTED'}
 if(-not [bool]$d.NetworkSettings.Networks.PSObject.Properties['rota62_guardian_fifth_internal']){throw 'NETWORK_NOT_ATTACHED'}
 if($d.HostConfig.ReadonlyRootfs -ne $true){throw 'ROOTFS_NOT_READONLY'}
 if(@($d.Mounts).Count -eq 0){throw 'NO_MOUNTS'}
 $report.Add('[OK] CONTAINER_RUNNING_INTERNAL_READONLY_ROOTFS')
 $report.Add('MOUNT_COUNT='+@($d.Mounts).Count)
 $stage='MOUNT'
 $target=@($d.Mounts|Where-Object {$_.Destination -ceq '/guardian-dispatch'})
 $report.Add('EXPECTED_DESTINATION_PRESENT='+($target.Count -gt 0))
 if($target.Count -ne 1){throw 'EXPECTED_MOUNT_DESTINATION_MISSING_OR_DUPLICATE'}
 $m=$target[0]
 $report.Add('MOUNT_TYPE='+$(if($m.Type -eq 'bind'){'BIND'}elseif($m.Type -eq 'volume'){'VOLUME'}else{'OTHER'}))
 $report.Add('MOUNT_READ_ONLY='+(-not [bool]$m.RW))
 if($m.Type -cne 'bind' -or $m.RW -ne $false){throw 'MOUNT_NOT_READONLY_BIND'}
 # Compare only normalized path classifications; do not disclose host path.
 $normalized=([string]$m.Source).Replace('\','/').TrimEnd('/').ToLowerInvariant()
 $expectedNorm=$expected.Replace('\','/').TrimEnd('/').ToLowerInvariant()
 $driveStyle=$normalized -match '^[a-z]:/'
 $dockerDesktopStyle=$normalized -match '^/run/desktop/mnt/host/[a-z]/'
 $mntStyle=$normalized -match '^/(host_)?mnt/[a-z]/'
 $report.Add('SOURCE_FORMAT='+$(if($driveStyle){'WINDOWS_DRIVE'}elseif($dockerDesktopStyle){'DOCKER_DESKTOP_HOST'}elseif($mntStyle){'UNIX_HOST_MOUNT'}else{'OTHER'}))
 $expectedUnix='/run/desktop/mnt/host/d/'+($expectedNorm -replace '^d:/','')
 $mappedEquivalent=($normalized -ceq $expectedNorm -or $normalized -ceq $expectedUnix)
 $report.Add('EXPECTED_SOURCE_EQUIVALENT='+$mappedEquivalent)
 $report.Add('[OK] MOUNT_READ_ONLY_BIND')
 $stage='HASH_HOST'
 foreach($check in @(@('index.ts',$expectedIndex),@('guardian_adapter.ts',$expectedAdapter))){
  $p=Join-Path $expected $check[0]
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw 'EXPECTED_HOST_SOURCE_FILE_MISSING'}
  if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -cne $check[1]){throw 'HOST_SOURCE_HASH_MISMATCH'}
 }
 $report.Add('[OK] HOST_SOURCE_SHA256_MATCH')
 $stage='HASH_MOUNTED'
 $work=Join-Path ([IO.Path]::GetTempPath()) ('R62_MOUNT_PROBE_'+[guid]::NewGuid().ToString('N'))
 New-Item -ItemType Directory -Force -Path $work|Out-Null
 try {
  foreach($check in @(@('index.ts',$expectedIndex),@('guardian_adapter.ts',$expectedAdapter))){
   $dest=Join-Path $work $check[0]
   $copy=@(& docker cp ($container+':/guardian-dispatch/'+$check[0]) $dest 2>$null)
   if($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $dest -PathType Leaf)){throw 'MOUNTED_SOURCE_READ_FAILED'}
   if((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -cne $check[1]){throw 'MOUNTED_SOURCE_HASH_MISMATCH'}
  }
 }finally{Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue}
 $report.Add('[OK] CONTAINER_MOUNTED_SOURCE_SHA256_MATCH')
 $report.Add('[APROVADO] LAB5_MOUNT_CONTENT_VERIFIED')
}catch{
 $code=[string]$_.Exception.Message
 if($code -cnotmatch '^[A-Z0-9_]+$'){$code='UNCLASSIFIED_SAFE_ERROR'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$code)
}finally{
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop; Write-Output '[OK] REPORT_COPIED'}catch{}
}
