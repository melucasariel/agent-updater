# Guardian v3.3 candidate: verify real Windows PowerShell child process startup in an ISOLATED TEMP lab.
# NOT a production agent installer. Do not point it at live Guardian paths.
Set-StrictMode -Version Latest
function Test-R62SandboxChildHealth {
 [CmdletBinding()]
 param(
  [Parameter(Mandatory=$true)][string]$LabRoot,
  [Parameter(Mandatory=$true)][string]$ChildFile,
  [ValidateSet('Good','Wrong','Silent')][string]$Mode='Good',
  [ValidateRange(500,15000)][int]$TimeoutMs=4000
 )
 $ErrorActionPreference='Stop'
 $root=[IO.Path]::GetFullPath($LabRoot).TrimEnd('\')
 $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
 if(-not $root.StartsWith(($temp+'\'),[StringComparison]::OrdinalIgnoreCase) -or $root -notmatch 'R62_Health_Test_[a-f0-9]{32}$'){throw 'LAB_ROOT_NOT_ALLOWED'}
 $child=[IO.Path]::GetFullPath($ChildFile)
 if(-not $child.StartsWith(($root+'\'),[StringComparison]::OrdinalIgnoreCase)){throw 'CHILD_OUTSIDE_LAB'}
 if(!(Test-Path -LiteralPath $child -PathType Leaf)){throw 'CHILD_MISSING'}
 $expected=(Get-FileHash -LiteralPath $child -Algorithm SHA256).Hash
 $nonce=[guid]::NewGuid().ToString('N')
 $receipt=Join-Path $root ('receipt_'+$nonce+'.json')
 $psi=New-Object Diagnostics.ProcessStartInfo
 $psi.FileName=Join-Path $PSHOME 'powershell.exe'
 $psi.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$child+'" -Challenge '+$nonce+' -ReceiptFile "'+$receipt+'" -Mode '+$Mode
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $proc=New-Object Diagnostics.Process;$proc.StartInfo=$psi
 try {
  if(-not $proc.Start()){throw 'CHILD_START_FAILED'}
  $sw=[Diagnostics.Stopwatch]::StartNew()
  while($sw.ElapsedMilliseconds -lt $TimeoutMs){
   if($proc.HasExited){throw 'CHILD_EXITED_BEFORE_HEALTH'}
   if(Test-Path -LiteralPath $receipt -PathType Leaf){break}
   Start-Sleep -Milliseconds 70
  }
  if(!(Test-Path -LiteralPath $receipt -PathType Leaf)){throw 'HEALTH_TIMEOUT'}
  if((Get-Item -LiteralPath $receipt).Length -gt 2048){throw 'RECEIPT_TOO_LARGE'}
  $ack=Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
  if([string]$ack.challenge -cne $nonce){throw 'HEALTH_CHALLENGE_MISMATCH'}
  if([int]$ack.process_id -ne $proc.Id){throw 'HEALTH_PID_MISMATCH'}
  if([string]$ack.script_sha256 -cne $expected){throw 'HEALTH_HASH_MISMATCH'}
  if($proc.HasExited){throw 'CHILD_EXITED_AFTER_HEALTH'}
  return '[OK] CHILD_HEALTH_VERIFIED'
 }finally{
  if($proc -and -not $proc.HasExited){try{$proc.Kill();$proc.WaitForExit(3000)|Out-Null}catch{}}
  if($proc){$proc.Dispose()}
  Remove-Item -LiteralPath $receipt -Force -ErrorAction SilentlyContinue
 }
}
