# ROTA62 Guardian LAB5 v0.15.2 - diagnostics, no production operations
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$pg='rota62_guardian_fifth_pg'
$net='rota62_guardian_fifth_internal'
$edge='rota62_guardian_lab5_dispatch_v012'
$db='rota62_guardian_fifth_restore'
$base='http://rota62_guardian_lab5_dispatch_v012:9000/guardian-lab5-original-rides'
$baseline='13|25|93|2|2|0|0|off'
$source='D:\ROTA62_GUARDIAN\LAB5_DISPATCH_ORIGINAL_v0.12'
$expectedIndex='ACFEB7E6F708DF3A932DD47A64DB70A937B1343D0EE26E069041729936C16CF8'
$expectedAdapter='42FB1E25CB3B6243D37308726C3BA91C3ADEDF86A7A908659AE54ED9ABFFB3D6'
$report=New-Object 'System.Collections.Generic.List[string]'
$report.Add('=== GUARDIAN LAB5 v0.15.2 - HTTP 403 ===')
$report.Add('[MODO] Docker isolado; SQL SELECT; requests sem credenciais reais')
$failed=$false
function D([string[]]$args) {
 $res=@(& docker @args 2>$null)
 if($LASTEXITCODE -ne 0){throw 'DOCKER_QUERY_FAILED'}
 return ([string]($res -join [char]10)).Trim()
}
function Snapshot {
 $q="SELECT (SELECT count(*) FROM public.tr_users)::text||'|'||(SELECT count(*) FROM public.tr_sessions)||'|'||(SELECT count(*) FROM public.tr_rides)||'|'||(SELECT count(*) FROM public.tr_priority_drivers)||'|'||(SELECT count(*) FROM public.tr_driver_presence_v019)||'|'||(SELECT count(*) FROM public.tr_driver_declines_v019)||'|'||(SELECT count(*) FROM public.tr_users WHERE name LIKE 'GUARDIAN V014 %')||'|'||current_setting('cron.launch_active_jobs',true);"
 return D @('exec',$pg,'psql','-U','supabase_admin','-d',$db,'-X','-A','-t','-v','ON_ERROR_STOP=1','-c',$q)
}
function Probe([string]$name,[string]$method,[string]$body,[bool]$bearer) {
 $args=@('exec',$pg,'curl','--noproxy','*','--silent','--show-error','--max-time','8','--request',$method,'--header','Accept: application/json','--header','Content-Type: application/json','--write-out',([char]10+'R62_HTTP:%{http_code};TYPE:%{content_type}'))
 if($bearer){$args+=@('--header',('Authorization: Bearer '+('0'*64)))}
 if($method -eq 'POST'){$args+=@('--data-binary',$body)}
 $args+=$base
 $response=D $args
 $m=[regex]::Match($response,'(?s)^(.*)\r?\nR62_HTTP:(\d{3});TYPE:([^\r\n]*)$')
 if(-not $m.Success){throw 'HTTP_STATUS_UNAVAILABLE'}
 $raw=$m.Groups[1].Value;$code=$m.Groups[2].Value;$ct=$m.Groups[3].Value
 $kind='unknown'
 try{
  $json=ConvertFrom-Json -InputObject $raw -ErrorAction Stop
  if($json -and ($json.PSObject.Properties.Name -contains 'error')){
   $err=[string]$json.error
   if($err -eq 'guardian_action_blocked'){$kind='application_firewall'}
   elseif($err -eq 'guardian_lab_disabled'){$kind='lab_disabled'}
   elseif($err -match '^(Entre na sua conta para continuar\.|Sessão expirada\. Entre novamente\.|Conta indisponível\.)$'){$kind='application_auth'}
   else{$kind='other_error'}
  }else{$kind='json_other'}
 }catch{$kind='non_json'}
 $report.Add("CASO=$name HTTP=$code CLASSE=$kind JSON=$($ct -match 'json') TAMANHO=$($raw.Length)")
 return [pscustomobject]@{Code=$code;Kind=$kind}
}
try{
 if(-not (Get-Command docker -ErrorAction SilentlyContinue)){throw 'DOCKER_CLI_MISSING'}
 if((D @('network','inspect',$net,'--format','{{.Internal}}')) -cne 'true'){throw 'NETWORK_NOT_INTERNAL'}
 $pgState=D @('inspect',$pg,'--format','{{.State.Status}}|{{.HostConfig.NetworkMode}}|{{json .HostConfig.PortBindings}}')
 if($pgState -cne ('running|'+$net+'|{}')){throw 'POSTGRES_NOT_ISOLATED'}
 if((Snapshot) -cne $baseline){throw 'INITIAL_BASELINE_CHANGED'}
 $edgeState=D @('inspect',$edge,'--format','{{.State.Status}}|{{.HostConfig.NetworkMode}}|{{json .HostConfig.PortBindings}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.RestartPolicy.Name}}')
 if($edgeState -cne ('running|'+$net+'|{}|true|no')){throw 'EDGE_NOT_ISOLATED'}
 $mounts=@(ConvertFrom-Json (D @('inspect',$edge,'--format','{{json .Mounts}}')))
 $mountOk=$false
 foreach($m in $mounts){
  if($m.Destination -eq '/guardian-dispatch' -and $m.RW -eq $false -and ([string]$m.Source).TrimEnd('\','/') -ieq $source.TrimEnd('\','/')){$mountOk=$true}
 }
 if(-not $mountOk){throw 'SOURCE_MOUNT_CHANGED'}
 foreach($entry in @(@('index.ts',$expectedIndex),@('guardian_adapter.ts',$expectedAdapter))){
  $p=Join-Path $source $entry[0]
  if(!(Test-Path -LiteralPath $p -PathType Leaf) -or (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -cne $entry[1]){throw 'SOURCE_SHA256_CHANGED'}
 }
 $report.Add('[OK] ISOLATION_BASELINE_SHA256')
 $a=Probe 'NO_TOKEN' 'POST' '{"action":"rides-list"}' $false
 $b=Probe 'FAKE_TOKEN' 'POST' '{"action":"rides-list"}' $true
 $c=Probe 'INVALID_JSON' 'POST' 'not-json' $false
 $d=Probe 'UNKNOWN_ACTION' 'POST' '{"action":"acao-desconhecida"}' $false
 $e=Probe 'GET' 'GET' '' $false
 if((Snapshot) -cne $baseline){throw 'BASELINE_CHANGED_AFTER_HTTP'}
 $report.Add('[OK] BASELINE_UNCHANGED_AFTER_HTTP')
 if($a.Code -eq '401' -and $b.Code -eq '401' -and $c.Code -eq '403' -and $d.Code -eq '403' -and $e.Code -eq '403'){
  $report.Add('[APROVADO] HTTP_NEGATIVE_CASES_MATCH_CONTRACT')
 }else{
  $report.Add('[DIAGNOSTICO] HTTP_CLASSES_REQUIRE_REVIEW')
 }
 $report.Add('[LIMITE] No real authentication or write behavior tested')
}catch{
 $failed=$true
 $reason=[string]$_.Exception.Message
 if($reason -notmatch '^[A-Z0-9_]+$'){$reason='REDACTED_ERROR'}
 $report.Add('[BLOQUEADO] '+$reason)
 try{if((Snapshot) -eq $baseline){$report.Add('[RECHECK] BASELINE_OK')}else{$report.Add('[RECHECK] BASELINE_CHANGED')}}catch{$report.Add('[RECHECK] UNAVAILABLE')}
}finally{
 $out=$report -join [Environment]::NewLine
 Write-Output $out
 try{Set-Clipboard -Value $out -ErrorAction Stop}catch{}
}
if($failed){exit 1}
