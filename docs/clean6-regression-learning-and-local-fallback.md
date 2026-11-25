# ROTA62 — delivery protocol and regression learning

This project uses *engineering feedback*, not AI model retraining. Each observed failure must become a named and reproducible test in GitHub Actions. No claim is made that ChatGPT model weights changed.

## Failures turned into checks
| Failure observed | Durable prevention |
|---|---|
| Truncated/duplicated replay-guard source | Windows PowerShell Parser check before acceptance |
| Child script `exit 2/3` terminated parent session | Isolated child PowerShell processes + explicit expected exit-code assertions |
| Multiline/CRLF report matching | Line-aware normalized assertions |
| Repeated request ID with different nonce | Persistent request-ID replay check + re-signed duplicate-ID test |
| No audit file at guessed TEMP path | Bounded filename discovery plus separate marker fingerprint search |
| Unknown error root cause `LOCAL_ERROR_REDACTED` | Sanitized triage; forbid assuming the semantic audit succeeded |
| Missing diagnostic component | Explicit fail-closed regression test |
| Invalid candidate JavaScript | Syntax-error regression; no source content in report |
| Marker-only unknown script | Marker-only decision test |
| Public GitHub cannot return sensitive local reports | Local clipboard only, never commit reports |

## Release acceptance gate
1. All relevant GitHub Actions green for exact candidate commit.
2. Actual Windows installation and correct signature/public key pin authenticated independently.
3. Valid signed `SELFTEST` reaches local receiver and invalid/replayed requests are refused.
4. Operator locally runs `CLEAN6_TRIAGE` (read-only); verified sanitized output is pasted into chat by human, until a separately approved private return integration exists.
5. For CLEAN6: identify audit script SHA; diagnose `LOCAL_ERROR_REDACTED`; prove 185/595 semantic assertions in disposable PG17 with forced ROLLBACK; independently verify pre/post state.
6. No production restore, decrypted backup material, credentials or personally identifiable data appear in public GitHub.

## One-command local fallback that works without installing V6
For the initial real-machine environment check, paste into PowerShell (runs locally; nothing is downloaded):

```powershell
$r=@('=== ROTA62 CLEAN6 LOCAL FALLBACK ===');$d=Get-Command docker -ErrorAction SilentlyContinue;$n=Get-Command node -ErrorAction SilentlyContinue;$r+='DOCKER_CLI='+[bool]$d;$r+='NODE_AVAILABLE='+[bool]$n;if($d){$null=& docker info --format '{{.ServerVersion}}' 2>$null;$ok=$LASTEXITCODE -eq 0;$r+='DOCKER_ENGINE_OK='+$ok;if($ok){$ids=@(& docker ps -q 2>$null);$r+='ACTIVE_CONTAINERS='+$ids.Count}};$roots=@($env:TEMP,$env:LOCALAPPDATA,(Join-Path $env:USERPROFILE 'Documents'))|Where-Object{$_ -and (Test-Path -LiteralPath $_ -PathType Container)};$names=@('R62-Clean6-Semantics-v141.mjs','R62-Clean6-Semantics-v14.mjs','R62-Clean6-Semantics.mjs');$found=@(foreach($root in $roots){foreach($name in $names){$p=Join-Path $root $name;if(Test-Path -LiteralPath $p -PathType Leaf){$p}};foreach($sub in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue|Select-Object -First 40)){foreach($name in $names){$p=Join-Path $sub.FullName $name;if(Test-Path -LiteralPath $p -PathType Leaf){$p}}}})|Select-Object -Unique;$r+='AUDIT_CANDIDATES_FOUND='+@($found).Count;foreach($p in @($found|Select-Object -First 3)){$r+='AUDIT_SHA256='+((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash)};$r+='SEMANTIC_AUDIT_EXECUTED=NO';$r+='NO_SQL_NO_PASSWORD_NO_RESTORE=YES';$r+='END_REPORT_OK';$out=$r -join [Environment]::NewLine;$out;Set-Clipboard -Value $out
```

The fallback deliberately checks only a bounded set of known filenames; zero candidates does not establish absence. It does not read backup bytes, run SQL or expose local file paths. **It only copies output to the clipboard, not into ChatGPT.**
