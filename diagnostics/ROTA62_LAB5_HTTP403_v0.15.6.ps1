# Guardian LAB5 v0.15.6: controlled HTTP 403 diagnostic, read-only DB baseline.
# Requires Docker internal isolated network; no tokens, no database mutations.
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$pg='rota62_guardian_fifth_pg'
$edge='rota62_guardian_lab5_dispatch_v012'
$net='rota62_guardian_fifth_internal'
$db='rota62_guardian_fifth_restore'
$base='http://rota62_guardian_lab5_dispatch_v012:9000/guardian-lab5-original-rides'
$baseline='13|25|93|2|2|0|0|off'
$source='D:\ROTA62_GUARDIAN\LAB5_DISPATCH_ORIGINAL_v0.12'
$known=@{ 'index.ts'='ACFEB7E6F708DF3A932DD47A64DB70A937B1343D0EE26E069041729936C16CF8'; 'guardian_adapter.ts'='42FB1E25CB3B6243D37308726C3BA91C3ADEDF86A7A908659AE54ED9ABFFB3D6' }
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== ROTA62 LAB5 v0.15.6 - HTTP403 SAFE TEST ===')
$report.Add('[MODO] NO_REAL_TOKEN_NO_PRODUCTION_NO_SQL_WRITES')
$stage='INIT'
$passed=$false
function D {
 param([string[]]$Arguments)
 $result=@(& docker @Arguments 2>$null)
 if($LASTEXITCODE -ne 0){throw 'DOCKER_CALL_FAILED'}
 return (($result -join [Environment]::NewLine).Trim())
}
function Baseline {
 $sql="BEGIN READ ONLY; SELECT (SELECT count(*) FROM public.tr_users)::text||'|'||(SELECT count(*) FROM public.tr_sessions)||'|'||(SELECT count(*) FROM public.tr_rides)||'|'||(SELECT count(*) FROM public.tr_priority_drivers)||'|'||(SELECT count(*) FROM public.tr_driver_presence_v019)||'|'||(SELECT count(*) FROM public.tr_driver_declines_v019)||'|'||(SELECT count(*) FROM public.tr_users WHERE name LIKE 'GUARDIAN V014 %')||'|'||current_setting('cron.launch_active_jobs',true); ROLLBACK;"
 $raw=D -Arguments @('exec',$pg,'psql','-U','supabase_admin','-d',$db,'-X','-A','-t','-v','ON_ERROR_STOP=1','-c',$sql)
 $matches=@($raw -split '[\r\n]+' | Where-Object {$_ -match '^\d+(\|\d+){6}\|(off|on)$'})
 if($matches.Count -ne 1){throw 'BASELINE_FORMAT_UNKNOWN'}
 return $matches[0]
}
function Probe {
 param([string]$Name,[string]$Method,[string]$Body,[bool]$Fake)
 $arr=@('exec',$pg,'curl','--noproxy','*','--silent','--show-error','--max-time','8','--request',$Method,'--header','Accept: application/json','--header','Content-Type: application/json','--write-out',([string][char]10+'R62_HTTP:%{http_code}'))
 if($Fake){$arr+=@('--header',('Authorization: Bearer '+('0'*64)))}
 if($Method -eq 'POST'){$arr+=@('--data-binary',$Body)}
 $arr+=$base
 $raw=D -Arguments $arr
 $m=[regex]::Match($raw,'(?s)^(.*)\r?\nR62_HTTP:(\d{3})$')
 if(-not $m.Success){throw 'HTTP_RESPONSE_FORMAT_UNKNOWN'}
 $response=$m.Groups[1].Value
 $kind='non_json'
 try{
  $o=ConvertFrom-Json -InputObject $response -ErrorAction Stop
  if($o -and ($o.PSObject.Properties.Name -contains 'error')){
   $err=[string]$o.error
   if($err -ceq 'guardian_action_blocked'){$kind='blocked_by_guardian'}
   elseif($err -ceq 'guardian_lab_disabled'){$kind='lab_disabled'}
   elseif($err -match '^(Entre na sua conta para continuar\.|Sessão expirada\. Entre novamente\.|Conta indisponível\.)$'){$kind='auth_rejected'}
   else{$kind='other_json_error'}
  }else{$kind='other_json'}
 }catch{}
 $status=$m.Groups[2].Value
 $report.Add('CASO='+$Name+' STATUS='+$status+' CLASSE='+$kind+' BYTES='+[Text.Encoding]::UTF8.GetByteCount($response))
 return [pscustomobject]@{Status=$status;Kind=$kind}
}
try {
 $stage='DOCKER_AND_NETWORK'
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 if((D -Arguments @('network','inspect',$net,'--format','{{.Internal}}')) -cne 'true'){throw 'LAB_NETWORK_NOT_INTERNAL'}
 $stage='PG_ISOLATION'
 $pgInfo=@(
  (D -Arguments @('inspect',$pg,'--format','{{.State.Status}}'))
  (D -Arguments @('inspect',$pg,'--format','{{.HostConfig.NetworkMode}}'))
  (D -Arguments @('inspect',$pg,'--format','{{json .HostConfig.PortBindings}}'))
 )
 if($pgInfo[0] -cne 'running' -or $pgInfo[1] -cne $net -or ($pgInfo[2] -cne '{}' -and $pgInfo[2] -cne 'null')){throw 'PG_ISOLATION_UNVERIFIED'}
 $pgNetworks=ConvertFrom-Json -InputObject (D -Arguments @('inspect',$pg,'--format','{{json .NetworkSettings.Networks}}'))
 if(@($pgNetworks.PSObject.Properties.Name).Count -ne 1 -or -not $pgNetworks.PSObject.Properties[$net]){throw 'PG_SECONDARY_NETWORK_PRESENT'}
 $stage='EDGE_ISOLATION'
 $edgeInfo=@(
  (D -Arguments @('inspect',$edge,'--format','{{.State.Status}}'))
  (D -Arguments @('inspect',$edge,'--format','{{.HostConfig.NetworkMode}}'))
  (D -Arguments @('inspect',$edge,'--format','{{json .HostConfig.PortBindings}}'))
  (D -Arguments @('inspect',$edge,'--format','{{.HostConfig.ReadonlyRootfs}}'))
  (D -Arguments @('inspect',$edge,'--format','{{.HostConfig.RestartPolicy.Name}}'))
 )
 if($edgeInfo[0] -cne 'running' -or $edgeInfo[1] -cne $net -or ($edgeInfo[2] -cne '{}' -and $edgeInfo[2] -cne 'null') -or $edgeInfo[3] -cne 'true' -or $edgeInfo[4] -cne 'no'){throw 'EDGE_ISOLATION_UNVERIFIED'}
 $edgeNetworks=ConvertFrom-Json -InputObject (D -Arguments @('inspect',$edge,'--format','{{json .NetworkSettings.Networks}}'))
 if(@($edgeNetworks.PSObject.Properties.Name).Count -ne 1 -or -not $edgeNetworks.PSObject.Properties[$net]){throw 'EDGE_SECONDARY_NETWORK_PRESENT'}
 $stage='MOUNT_IDENTITY'
 # Proven v0.15.4 full docker inspect, instead of the fragile formatted .Mounts array.
 $inspectRaw=@(& docker inspect $edge 2>$null)
 if($LASTEXITCODE -ne 0 -or $inspectRaw.Count -eq 0){throw 'EDGE_INSPECT_FAILED'}
 $inspectObject=@(($inspectRaw -join [Environment]::NewLine | ConvertFrom-Json))[0]
 if(-not $inspectObject){throw 'EDGE_INSPECT_PARSE_FAILED'}
 $target=@($inspectObject.Mounts | Where-Object {$_.Destination -ceq '/guardian-dispatch'})
 if($target.Count -ne 1){throw 'LAB_MOUNT_DESTINATION_NOT_UNIQUE'}
 $mount=$target[0]
 if($mount.Type -cne 'bind' -or $mount.RW -ne $false){throw 'LAB_MOUNT_NOT_READONLY_BIND'}
 $src=([string]$mount.Source).Replace('\','/').TrimEnd('/').ToLowerInvariant()
 $want=$source.Replace('\','/').TrimEnd('/').ToLowerInvariant()
 $dockerWant='/run/desktop/mnt/host/d/'+($want -replace '^d:/','')
 if($src -cne $want -and $src -cne $dockerWant){throw 'LAB_MOUNT_SOURCE_NOT_PINNED'}
 $report.Add('[OK] LAB5_MOUNT_V0154_VERIFIED_METHOD')
 foreach($name in @('index.ts','guardian_adapter.ts')){
  $p=Join-Path $source $name
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw 'LAB_SOURCE_MISSING'}
  if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -cne $known[$name]){throw 'LAB_SOURCE_HASH_MISMATCH'}
 }
 $report.Add('[OK] ISOLATION_AND_SOURCE_PINNED')
 $stage='BASELINE_BEFORE'
 if((Baseline) -cne $baseline){throw 'INITIAL_DB_BASELINE_MISMATCH'}
 $report.Add('[OK] DB_BASELINE_BEFORE')
 $stage='HTTP_CLIENT'
 # No package installation, network probes only internal Docker; never use real creds.
 [void](D -Arguments @('exec',$pg,'curl','--version'))
 $stage='HTTP_NEGATIVE_CASES'
 $a=Probe -Name 'NO_TOKEN' -Method 'POST' -Body '{"action":"rides-list"}' -Fake $false
 $b=Probe -Name 'FAKE_TOKEN' -Method 'POST' -Body '{"action":"rides-list"}' -Fake $true
 $c=Probe -Name 'BAD_JSON' -Method 'POST' -Body 'not-json' -Fake $false
 $d=Probe -Name 'UNKNOWN_ACTION' -Method 'POST' -Body '{"action":"acao-desconhecida"}' -Fake $false
 $e=Probe -Name 'GET' -Method 'GET' -Body '' -Fake $false
 $stage='BASELINE_AFTER'
 if((Baseline) -cne $baseline){throw 'POST_HTTP_DB_BASELINE_MISMATCH'}
 $report.Add('[OK] DB_BASELINE_UNCHANGED')
 if($a.Status -ceq '401' -and $b.Status -ceq '401' -and $c.Status -ceq '403' -and $d.Status -ceq '403' -and $e.Status -ceq '403'){
  $report.Add('[APROVADO] EXPECTED_NEGATIVE_HTTP_STATUSES')
 }else{
  $report.Add('[DIAGNOSTICO] HTTP_STATUSES_DIFFER_SEE_CASES')
 }
 $report.Add('[LIMITE] No authenticated rides, uploads, live API or disaster recovery tested')
 $passed=$true
}catch{
 $reason=[string]$_.Exception.Message
 if($reason -cnotmatch '^[A-Z0-9_]+$'){$reason='SAFE_ERROR_UNCLASSIFIED'}
 $report.Add('[BLOQUEADO] ETAPA='+$stage+' CODIGO='+$reason)
 $report.Add('[AVISO] HTTP test not certified')
}finally{
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop; Write-Output '[OK] REPORT_COPIED'}catch{}
}
if(-not $passed){exit 1}
