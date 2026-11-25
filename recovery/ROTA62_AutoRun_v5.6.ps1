$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms

if (-not ('R62V56Window' -as [type])) {
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class R62V56Window {
 [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
}
"@
}
function Get-ActiveBrave {
 $h=[R62V56Window]::GetForegroundWindow()
 if($h -eq [IntPtr]::Zero){return [IntPtr]::Zero}
 [uint32]$id=0
 [void][R62V56Window]::GetWindowThreadProcessId($h,[ref]$id)
 try {
  if((Get-Process -Id $id -ErrorAction Stop).ProcessName -eq 'brave'){return $h}
 }catch{}
 return [IntPtr]::Zero
}
function Send-Report([string]$report){
 if($report.Length -gt 12000 -or $report -notmatch '^=== ROTA62 CLEAN6 '){
  Write-Host '[BLOQUEADO] INVALID_REPORT_FOR_AUTO_SEND'
  return
 }
 Write-Host '[INFO] VOLTE_A_CONVERSA_NO_BRAVE_E_CLIQUE_NO_CAMPO_DE_MENSAGEM'
 $h=[IntPtr]::Zero
 for($i=0;$i -lt 80;$i++){
  Start-Sleep -Milliseconds 500
  $h=Get-ActiveBrave
  if($h -ne [IntPtr]::Zero){break}
 }
 if($h -eq [IntPtr]::Zero){
  Write-Host '[BLOQUEADO] BRAVE_NOT_FOREGROUND_REPORT_REMAINS_COPIED'
  Set-Clipboard -Value $report
  return
 }
 [System.Windows.Forms.SendKeys]::SendWait('^l')
 Start-Sleep -Milliseconds 200
 [System.Windows.Forms.SendKeys]::SendWait('^c')
 Start-Sleep -Milliseconds 400
 $address=([string](Get-Clipboard -Raw)).Trim()
 [System.Windows.Forms.SendKeys]::SendWait('{ESC}')
 $uri=$null
 if(-not [uri]::TryCreate($address,[UriKind]::Absolute,[ref]$uri) -or
    $uri.Scheme -ne 'https' -or
    $uri.Host -notin @('chatgpt.com','chat.openai.com') -or
    $uri.AbsolutePath -notmatch '^/c/'){
   Write-Host '[BLOQUEADO] CHATGPT_CONVERSATION_NOT_VERIFIED'
   Set-Clipboard -Value $report
   return
 }
 if((Get-ActiveBrave) -ne $h){
  Write-Host '[BLOQUEADO] FOCUS_CHANGED'
  Set-Clipboard -Value $report
  return
 }
 Set-Clipboard -Value $report
 [System.Windows.Forms.SendKeys]::SendWait('+{ESC}')
 Start-Sleep -Milliseconds 550
 if((Get-ActiveBrave) -ne $h){
  Write-Host '[BLOQUEADO] FOCUS_CHANGED_BEFORE_PASTE'
  return
 }
 [System.Windows.Forms.SendKeys]::SendWait('^v')
 Start-Sleep -Milliseconds 1100
 if((Get-ActiveBrave) -ne $h){
  Write-Host '[BLOQUEADO] FOCUS_CHANGED_BEFORE_ENTER'
  return
 }
 [System.Windows.Forms.SendKeys]::SendWait('{ENTER}')
 Write-Host '[OK] BRAVE_PASTE_AND_SEND_REQUESTED'
 Write-Host '[INFO] VERIFY_RECEIPT_IN_THIS_CONVERSATION'
}
function Run-SemanticAudit {
 $path=Join-Path $env:TEMP 'R62-Clean6-Semantics-AutoRun-v141.mjs'
 try {
  if(-not (Get-Command node -ErrorAction SilentlyContinue)){
   throw 'NODEJS_NOT_FOUND'
  }
  $url='https://raw.githubusercontent.com/melucasariel/agent-updater/17af4e679318c25ba6b1c9a062672dfd63c8d209/recovery/ROTA62_Clean6_InTransactionSemantics_v1.4.2.mjs'
  Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing
  $expected='C765AEA9F1F46E50A925EFD792E0F466E41495420A250AEAED8B0083BAC55DBB'
  if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -cne $expected){
   throw 'SCRIPT_SHA256_MISMATCH'
  }
  Write-Host '[OK] SEMANTIC_AUDIT_SCRIPT_SHA256_VERIFIED'
  $picker=New-Object System.Windows.Forms.OpenFileDialog
  $picker.Title='ROTA62: selecione o backup original criptografado'
  $picker.Filter='Backup ROTA62 (*.r62db)|*.r62db'
  $picker.CheckFileExists=$true
  $owner=New-Object System.Windows.Forms.Form
  $owner.TopMost=$true
  $owner.ShowInTaskbar=$false
  $backupFile=$null
  try{
   if($picker.ShowDialog($owner) -ne [System.Windows.Forms.DialogResult]::OK){
    Write-Host '[INFO] BACKUP_SELECTION_CANCELLED'
    return $null
   }
   $backupFile=$picker.FileName
  }finally{$owner.Dispose();$picker.Dispose()}
  Write-Host '[INFO] DIGITE_A_SENHA_LOCALMENTE_NESTA_JANELA'
  & node $path $backupFile
  $exit=$LASTEXITCODE
  $copied=[string](Get-Clipboard -Raw -ErrorAction SilentlyContinue)
  if($copied -notmatch '^=== ROTA62 CLEAN6 IN TRANSACTION SEMANTIC AUDIT v1\.4\.1'){
   Write-Host '[BLOQUEADO] EXPECTED_REPORT_NOT_FOUND_IN_CLIPBOARD'
   return $null
  }
  $allowed='^(=== ROTA62 CLEAN6 IN TRANSACTION SEMANTIC AUDIT v1\.4\.1 ===|\[(?:MODO|OK|INFO|BLOQUEADO|PENDENTE|LIMITE|APROVADO|NEXT)\]\s+.{0,300}|(?:SOURCE_OWNER_STATEMENTS|SOURCE_ACL_STATEMENTS|EVENT_TRIGGER_OWNER_STATEMENTS_SKIPPED|COMPATIBLE_OWNER_STATEMENTS_TO_TEST|LAST_EXECUTED_PHASE_MARKER|TOTAL_PHASE_MARKERS|OWNER_TEST_REACHED_END|ACL_TEST_REACHED_END|EXPLICIT_ROLLBACK_CONFIRMED|OWNER_ACL_STATE_POSTCHECK|SEMANTIC_QUERIES_COMPLETE|R62_SEM_[A-Z_]+|DRYRUN_EXIT_CODE)=?.{0,500})$'
  $safe=@($copied -split '\r?\n' | Where-Object {$_ -match $allowed})
  $report=$safe -join [Environment]::NewLine
  if($report.Length -lt 60 -or $report.Length -gt 12000){
   Write-Host '[BLOQUEADO] REPORT_REDACTION_UNEXPECTED'
   return $null
  }
  if($exit -ne 0){Write-Host '[INFO] AUDIT_BLOCKED_REPORT_SANITIZED'}
  else{Write-Host '[OK] AUDIT_FINISHED_REPORT_SANITIZED'}
  return $report
 }catch{
  $code=if($_.Exception.Message -match '^[A-Z0-9_]+$'){$_.Exception.Message}else{'LOCAL_ERROR_REDACTED'}
  return "=== ROTA62 CLEAN6 AUTORUN V5.5 AUDIT ==="+[Environment]::NewLine+"[BLOQUEADO] CODIGO=$code"
 }finally{
  Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
 }
}
$mutex=New-Object System.Threading.Mutex($false,'Local\ROTA62_AutoRun_V56')
$locked=$false
try{
 $locked=$mutex.WaitOne(0)
 if(-not $locked){Write-Host '[BLOQUEADO] V56_ALREADY_RUNNING';exit 1}
 Write-Host '=== ROTA62 AUTORUN V5.5 ==='
 Write-Host '[OK] ONE_MONITOR_RUNNING'
 Write-Host '[OK] ALLOWED_ACTIONS=SELFTEST,SEMANTICS,STOP'
 Write-Host '[INFO] WAITING_FOR_COPY_BUTTON'
 $last=[string](Get-Clipboard -Raw -ErrorAction SilentlyContinue)
 $lastRun=[datetime]::MinValue
 while($true){
  Start-Sleep -Milliseconds 400
  try{
   $current=[string](Get-Clipboard -Raw -ErrorAction Stop)
   if($current -eq $last){continue}
   $last=$current
   $token=$current.Trim()
   if($token -eq 'R62RUN:V56:STOP'){Write-Host '[OK] MONITOR_STOPPED';break}
   if($token -notin @('R62RUN:V56:SELFTEST','R62RUN:V56:SEMANTICS')){continue}
   if(((Get-Date)-$lastRun).TotalSeconds -lt 8){Write-Host '[INFO] DUPLICATE_IGNORED';continue}
   $lastRun=Get-Date
   Write-Host '[OK] AUTHORIZED_TOKEN_DETECTED'
   if($token -eq 'R62RUN:V56:SELFTEST'){
    $report="=== ROTA62 CLEAN6 AUTORUN V5.5 TEST ==="+[Environment]::NewLine+"[OK] TOKEN_DETECTED"+[Environment]::NewLine+"[OK] NO_SQL_EXECUTED"
   }else{
    $report=Run-SemanticAudit
   }
   if([string]::IsNullOrWhiteSpace($report)){continue}
   Set-Clipboard -Value $report
   $last=[string](Get-Clipboard -Raw)
   Send-Report $report
   $last=[string](Get-Clipboard -Raw)
  }catch{Write-Host '[BLOQUEADO] MONITOR_LOCAL_ERROR_REDACTED'}
 }
}finally{
 if($locked){$mutex.ReleaseMutex()}
 $mutex.Dispose()
}
