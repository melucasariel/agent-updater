# ROTA62 Bridge V6 - strictly limited signed-command receiver.
# All output is LOCAL. This program never sends reports to GitHub or ChatGPT.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$PublicKeyPath,
  [string]$StateDirectory = (Join-Path $env:LOCALAPPDATA 'ROTA62_BridgeV6'),
  [ValidateRange(15,3600)][int]$PollSeconds=30,
  [string]$RequestFile,
  [switch]$Once
)
$ErrorActionPreference='Stop'
$script:StopReceiver=$false
$script:StateRoot=[IO.Path]::GetFullPath($StateDirectory)
$script:LogFile=Join-Path $script:StateRoot 'status.log'
$script:RequestUrl='https://raw.githubusercontent.com/melucasariel/agent-updater/main/bridge-v6/requests/current.json'
function Status([string]$code) {
  if($code -cnotmatch '^[A-Z0-9_]{2,80}$'){ throw 'Invalid status code' }
  $line='['+([DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))+'] '+$code
  Write-Output $line
  Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
}
function ProcessRequest([string]$localPath) {
  $verified=@(& (Join-Path $PSScriptRoot 'Test-BridgeV6ReplayGuard.ps1') -RequestPath $localPath -PinnedPublicKeyPath $PublicKeyPath -ReplayDirectory (Join-Path $script:StateRoot 'seen'))
  $code=$LASTEXITCODE
  if($code -ne 3 -or $verified -notcontains '[OK] SIGNATURE_VERIFIED_AND_REPLAY_RECORDED'){
    Status 'REQUEST_REJECTED_OR_ALREADY_PROCESSED'; return
  }
  $req=Get-Content -LiteralPath $localPath -Raw -Encoding UTF8 | ConvertFrom-Json
  switch -CaseSensitive ([string]$req.command) {
    'SELFTEST' {
      $docker=Get-Command docker -ErrorAction SilentlyContinue
      if($null -eq $docker){Status 'SELFTEST_DOCKER_NOT_FOUND'; break}
      $null=& docker info --format '{{.ServerVersion}}' 2>$null
      if($LASTEXITCODE -ne 0){Status 'SELFTEST_DOCKER_UNAVAILABLE'; break}
      $ids=@(& docker ps --quiet 2>$null)
      if($LASTEXITCODE -ne 0){Status 'SELFTEST_DOCKER_PS_FAILED'; break}
      Status 'SELFTEST_OK'
      Write-Output ('CONTAINER_COUNT='+$ids.Count)
      break
    }
    'AUDIT_PREFLIGHT' {
      # Never open backups, request passwords, connect to database, or run SQL.
      if(Test-Path -LiteralPath (Join-Path $env:TEMP 'R62-Clean6-Semantics-v141.mjs') -PathType Leaf) {
        Status 'AUDIT_SCRIPT_AT_EXPECTED_TEMP_PATH'
      } else { Status 'AUDIT_SCRIPT_NOT_AT_EXPECTED_TEMP_PATH' }
      break
    }
    'STOP' { Status 'SIGNED_STOP_ACCEPTED'; $script:StopReceiver=$true; break }
    default { Status 'COMMAND_NOT_ALLOWED' }
  }
}
if(-not [IO.File]::Exists([IO.Path]::GetFullPath($PublicKeyPath))){ throw 'Missing locally pinned public key' }
[IO.Directory]::CreateDirectory($script:StateRoot) | Out-Null
[IO.Directory]::CreateDirectory((Join-Path $script:StateRoot 'seen')) | Out-Null
$mutex=New-Object Threading.Mutex($false,'Local\ROTA62_Bridge_V6_Receiver')
$locked=$false
try {
  try { $locked=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked=$true }
  if(-not $locked){Status 'ANOTHER_RECEIVER_ALREADY_RUNNING'; exit 2}
  Status 'RECEIVER_STARTED_NO_REMOTE_REPORTING'
  do {
    $source=$RequestFile
    $tempFile=$null
    try {
      if([string]::IsNullOrWhiteSpace($source)){
        # HTTPS endpoint is pinned; response is only DATA and is never executed.
        try { $resp=Invoke-WebRequest -Uri $script:RequestUrl -TimeoutSec 12 -UseBasicParsing -ErrorAction Stop }
        catch {
          Status 'NO_SIGNED_REQUEST_OR_GITHUB_UNAVAILABLE'
          if($Once){ break }
          Start-Sleep -Seconds $PollSeconds
          continue
        }
        $payload=[string]$resp.Content
        if([Text.Encoding]::UTF8.GetByteCount($payload) -gt 4096){Status 'REQUEST_TOO_LARGE'; break}
        $tempFile=Join-Path $script:StateRoot ('incoming-'+[guid]::NewGuid().ToString('N')+'.json')
        [IO.File]::WriteAllText($tempFile,$payload,[Text.UTF8Encoding]::new($false))
        $source=$tempFile
      }
      ProcessRequest $source
    } catch {
      Status 'REQUEST_PROCESSING_FAILED_REDACTED'
    } finally {
      if($tempFile -and (Test-Path -LiteralPath $tempFile)){Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue}
    }
    if($Once -or $script:StopReceiver){break}
    Start-Sleep -Seconds $PollSeconds
  } while($true)
  Status 'RECEIVER_STOPPED'
} finally {
  if($locked){$mutex.ReleaseMutex()}
  $mutex.Dispose()
}
