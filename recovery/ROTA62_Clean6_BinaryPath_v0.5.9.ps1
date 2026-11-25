# ROTA62 Guardian CLEAN6 v0.5.9 - PostgreSQL binary path diagnosis
# Read-only Docker inspect and command -v in EXISTING LOCAL REFERENCE LAB ONLY.
# Does not start CLEAN6, run SQL, modify containers, networks, disks, or remote services.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$clean='rota62_guardian_clean6_pg'
$ref='supabase_db_ROTA62_TESTE_SUPABASE'
$r=New-Object 'System.Collections.Generic.List[string]'
$r.Add('=== ROTA62 CLEAN6 BINARY PATH DIAGNOSTIC v0.5.9 ===')
$r.Add('[MODO] REFERENCE_LAB_READ_ONLY_COMMAND_LOOKUP_NO_SQL')
$stage='INIT';$ok=$false
function Inspect([string]$name) {
 $raw=@(& docker inspect $name 2>$null)
 if($LASTEXITCODE -ne 0 -or @($raw).Count -eq 0){throw 'DOCKER_INSPECT_FAILED'}
 $objects=@(($raw -join [Environment]::NewLine)|ConvertFrom-Json)
 if($objects.Count -ne 1){throw 'INSPECT_OBJECT_COUNT_INVALID'}
 return $objects[0]
}
try {
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_MISSING'}
 $stage='VERIFY_LABS'
 $c=Inspect $clean
 $p=Inspect $ref
 if([string]$c.State.Status -cne 'created' -or $c.State.Running -ne $false){throw 'CLEAN6_NOT_STOPPED'}
 if([string]$c.HostConfig.NetworkMode -cne 'none'){throw 'CLEAN6_NOT_ISOLATED'}
 if($c.HostConfig.PortBindings -and @($c.HostConfig.PortBindings.PSObject.Properties).Count -gt 0){throw 'CLEAN6_PORTS_PRESENT'}
 if(@($c.Mounts).Count -ne 1 -or [string]$c.Mounts[0].Name -cne 'rota62_guardian_clean6_data'){throw 'CLEAN6_VOLUME_MISMATCH'}
 if([string]$p.State.Status -cne 'running'){throw 'REFERENCE_LAB_NOT_RUNNING'}
 if([string]$c.Image -cne [string]$p.Image){throw 'IMAGE_ID_MISMATCH'}
 $r.Add('[OK] CLEAN6_STOPPED_AND_REFERENCE_IMAGE_MATCH')
 $stage='REFERENCE_LOOKUP'
 # Commands below only resolve binary paths; they do not launch postgres/initdb or connect to DB.
 $sh='for b in postgres initdb; do p=$(command -v "$b" 2>/dev/null || true); case "$p" in /*) printf "%s=%s\n" "$b" "$p";; *) printf "%s=NOT_IN_PATH\n" "$b";; esac; done'
 $old=$ErrorActionPreference
 try {
   $ErrorActionPreference='Continue'
   $raw=@(& docker exec --user postgres $ref sh -c $sh 2>$null)
   $code=$LASTEXITCODE
 } finally {$ErrorActionPreference=$old}
 if($code -ne 0){throw 'REFERENCE_READONLY_SHELL_FAILED'}
 $lines=@($raw|Where-Object {$_ -match '^(postgres|initdb)=(/[-a-zA-Z0-9_./]+|NOT_IN_PATH)$'})
 if($lines.Count -ne 2){throw 'BINARY_LOOKUP_OUTPUT_UNEXPECTED'}
 $paths=@{}
 foreach($line in $lines){
   $parts=([string]$line).Split('=',2)
   $paths[$parts[0]]=$parts[1]
 }
 foreach($name in @('postgres','initdb')){
   $value=$paths[$name]
   if($value -eq 'NOT_IN_PATH'){
     $r.Add('BINARY_'+$name.ToUpperInvariant()+'=NOT_IN_REFERENCE_PATH')
   }else{
     if($value -notmatch '^/[-a-zA-Z0-9_./]+$' -or $value -match '\.\.'){throw 'BINARY_PATH_REJECTED'}
     # Only parent category, avoid uncontrolled path text in clipboard.
     $r.Add('BINARY_'+$name.ToUpperInvariant()+'=FOUND')
     $r.Add('BINARY_'+$name.ToUpperInvariant()+'_IN_USR_LIB='+[string]$value.StartsWith('/usr/lib/postgresql/'))
     $r.Add('BINARY_'+$name.ToUpperInvariant()+'_IN_USR_LOCAL='+[string]$value.StartsWith('/usr/local/'))
   }
 }
 $r.Add('[LIMITE] Binary path lookup is from running local reference, not CLEAN6 execution')
 $r.Add('[LIMITE] No CLEAN6 startup or PostgreSQL restore performed')
 if($paths.postgres -eq 'NOT_IN_PATH' -or $paths.initdb -eq 'NOT_IN_PATH'){
   $r.Add('[AVISO] TARGET_BINARY_NOT_IN_PATH_REQUIRES_IMAGE_INSPECTION')
 }else{
   $r.Add('[OK] POSTGRES_AND_INITDB_FOUND_IN_REFERENCE')
 }
 $r.Add('[NEXT] PREPARE_EXPLICIT_OFFLINE_POSTGRES_INITIALIZATION')
 $ok=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]+$'){$reason='LOCAL_ERROR_REDACTED'}
 $r.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
}finally{
 $out=$r -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop;Write-Output '[OK] RELATORIO_COPIADO'}catch{}
}
if(-not $ok){exit 1}
