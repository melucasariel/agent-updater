# ROTA62 Guardian v3.1 - candidate: SAFE CHECK ONLY. No installation under any parameter.
# Replaces the check portion of original GuardianUpdater.ps1, but is NOT auto-deployed.
[CmdletBinding()]
param([switch]$CheckOnly,[switch]$Install)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$root=Join-Path $env:LOCALAPPDATA 'ROTA62_Guardian_AutoSend'
$cfgPath=Join-Path $root 'update_source.json'
$agentPath=Join-Path $root 'GuardianAgent_v3.ps1'
$versionPath=Join-Path $root 'installed_version.txt'
function Block([string]$reason){throw $reason}
function V([string]$v){
 if($v -cnotmatch '^3\.(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$'){Block 'VERSION_INVALIDA'}
 return [version]$v
}
function UriOk([string]$raw,[string]$kind){
 $u=$null
 if(-not [Uri]::TryCreate($raw,[UriKind]::Absolute,[ref]$u)){return $false}
 if($u.Scheme -cne 'https' -or $u.Host -cne 'github.com' -or $u.Port -ne 443 -or $u.UserInfo -or $u.Query -or $u.Fragment){return $false}
 if($kind -eq 'manifest'){
  return ($u.AbsolutePath -cmatch '^/melucasariel/agent-updater/releases/download/v3\.[0-9]{1,4}\.[0-9]{1,4}/release\.json$')
 }
 return ($u.AbsolutePath -cmatch '^/melucasariel/agent-updater/releases/download/v3\.[0-9]{1,4}\.[0-9]{1,4}/[A-Za-z0-9_.-]+\.zip$')
}
function DownloadManifest([string]$url,[string]$path){
 # WebClient can follow redirects; this candidate checks the final ResponseUri to fail closed.
 $request=[Net.HttpWebRequest]::Create($url)
 $request.Timeout=15000;$request.ReadWriteTimeout=15000
 $request.AllowAutoRedirect=$false
 $response=$null;$stream=$null;$output=$null
 try{
  $response=$request.GetResponse()
  if([int]$response.StatusCode -ne 200){Block 'HTTP_STATUS_NAO_200'}
  if(-not (UriOk $response.ResponseUri.AbsoluteUri 'manifest')){Block 'ORIGEM_FINAL_NAO_AUTORIZADA'}
  if($response.ContentLength -gt 8192){Block 'MANIFESTO_GRANDE'}
  $stream=$response.GetResponseStream()
  $output=[IO.File]::Create($path)
  $buffer=New-Object byte[] 2048;$count=0
  while(($n=$stream.Read($buffer,0,$buffer.Length)) -gt 0){
   $count+=$n
   if($count -gt 8192){Block 'MANIFESTO_GRANDE'}
   $output.Write($buffer,0,$n)
  }
 }finally{if($output){$output.Dispose()};if($stream){$stream.Dispose()};if($response){$response.Dispose()}}
}
try{
 if($Install){Block 'INSTALACAO_DESABILITADA_CANDIDATO'}
 if(!(Test-Path -LiteralPath $agentPath -PathType Leaf)){Block 'AGENT_V3_AUSENTE'}
 if(!(Test-Path -LiteralPath $cfgPath -PathType Leaf)){Block 'CONFIG_AUSENTE'}
 $cfg=Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
 if([string]::IsNullOrWhiteSpace([string]$cfg.manifest_url) -or [string]::IsNullOrWhiteSpace([string]$cfg.public_key_xml)){
  Write-Output '[OK] UPDATE_DESATIVADO_SEM_FONTE_CONFIAVEL';exit 0
 }
 $url=[string]$cfg.manifest_url
 if(-not (UriOk $url 'manifest')){Block 'FONTE_NAO_PERMITIDA'}
 if(!(Test-Path -LiteralPath $versionPath -PathType Leaf)){
  # Do not assume installed version from file text or filename.
  Block 'VERSAO_INSTALADA_NAO_FIXADA'
 }
 $current=(Get-Content -LiteralPath $versionPath -Raw).Trim()
 $currentVersion=V $current
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $tmp=Join-Path $env:TEMP ('R62_manifest_'+[guid]::NewGuid().ToString('N')+'.json')
 try{
  DownloadManifest $url $tmp
  $m=Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json
  $target=[string]$m.version
  $targetVersion=V $target
  if($targetVersion -le $currentVersion){Block 'DOWNGRADE_OU_REPLAY'}
  $bundle=[string]$m.bundle_url;$hash=[string]$m.bundle_sha256;$signature=[string]$m.signature_base64
  if(-not (UriOk $bundle 'bundle')){Block 'BUNDLE_URL_NAO_PERMITIDA'}
  if($bundle -cnotmatch ('/releases/download/v'+[regex]::Escape($target)+'/')){Block 'VERSAO_TAG_DIVERGENTE'}
  if($url -cnotmatch ('/releases/download/v'+[regex]::Escape($target)+'/')){Block 'MANIFESTO_TAG_DIVERGENTE'}
  if($hash -cnotmatch '^[a-f0-9]{64}$' -or $signature.Length -lt 80 -or $signature.Length -gt 1024){Block 'METADADOS_INVALIDOS'}
  $rsa=New-Object Security.Cryptography.RSACryptoServiceProvider
  try{
   $rsa.PersistKeyInCsp=$false
   $rsa.FromXmlString([string]$cfg.public_key_xml)
   if($rsa.KeySize -lt 3072){Block 'CHAVE_PUBLICA_FRACA'}
   $payload=$target+"`n"+$bundle+"`n"+$hash
   $ok=$rsa.VerifyData([Text.Encoding]::UTF8.GetBytes($payload),'SHA256',[Convert]::FromBase64String($signature))
  }finally{$rsa.Dispose()}
  if(-not $ok){Block 'ASSINATURA_INVALIDA'}
  Write-Output '[OK] ASSINATURA_RSA_SHA256_VALIDA'
  Write-Output ('VERSAO_ATUAL='+$current)
  Write-Output ('NOVA_VERSAO_DISPONIVEL='+$target)
  Write-Output '[OK] CONSULTA_APENAS_SEM_INSTALACAO'
 }finally{Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}
}catch{
 $msg=$_.Exception.Message
 if($msg -notmatch '^[A-Z0-9_]+$'){$msg='ERRO_NAO_CLASSIFICADO'}
 Write-Output ('[BLOQUEADO] '+$msg);exit 1
}
