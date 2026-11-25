# ROTA62 CLEAN6 — return to backup verification

## Real observed last state
- Report: `ENCRYPTED_BACKUP_SHA256_VERIFIED`, `CLEAN6_PRELOAD_SERVER_ONLY_VOLUME_CONSUMER`, `PG17_PRELOAD_CRON_JOBS_OFF_NO_TCP`, `RESTORED_DATABASE_76_TABLES_6_EXTENSIONS_FIVE_ROLES`.
- Audit `GUARDED_SEMANTIC_VERIFY_185_595_FORCE_ROLLBACK` blocked after local password capture, with `LOCAL_ERROR_REDACTED`.
- Earlier discovery searched a specific TEMP file that was absent; this does **not** establish that audit script is absent elsewhere.
- A Bridge V6 SELFTEST reported Docker OK, 15 active containers, but did not execute semantics.

## Next reliable step
Use reviewed `scripts/Test-Clean6Readiness.ps1` **locally** against the actual audit script path (if known). This only checks availability, SHA-256 and Node syntax, and reports Docker engine status/count; it does not read any passwords or backup bytes, run SQL, stop processes, restore data, or alter Docker.

Do not infer backup correctness from this check. Before declaring successful recovery, verify in a disposable environment:
1. Explicitly identify and pin the encrypted archive hash and audit script hash.
2. Confirm isolated PostgreSQL instance, disabled cron jobs and no TCP exposure.
3. Diagnose and correct the real local exception with a redacted error code (no password or secret in logs).
4. Run semantic verification of the target ownership/ACL statements inside a transaction, `ROLLBACK` unconditionally, and independently confirm persistent state unchanged.
5. Exercise a restore/recovery drill on a new isolated environment and validate services/edge functions/storage separately.

## Automated chat return
Not available with the current GitHub connector. It can write GitHub artifacts but does not grant ChatGPT direct access to local PowerShell output. Do not publish local diagnostics to this public repo or imply that clipboard copying automatically sends anything to this chat.
