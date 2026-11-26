# ROTA62 Guardian V6.8 — hardening review and recovery proof gates

**Scope:** draft PR #8 only; no production, CLEAN6, live Supabase, credentials, plaintext, restore or deployment changes. Review date: 2026-11-25. This is an engineering risk register, NOT a certificate that TaxiRadar can be restored.

## Observed, reproducible evidence

- The **prior integrated V6.8 commit** `3ae9f9cc7b21563ecacfe83275ee6434c7fba3ad` had 34/34 successful GitHub Action runs. Any later hardening commit requires **new, commit-specific CI**.
- The **last authenticated real-archive TOC reading was V6.7**, before the present hardening: 3/3 encrypted copies matched; SHA-256 and AES-GCM checks passed; 919 catalog entries; 77 TABLE (25 public, 52 other simple schemas), 73 TABLE DATA; no parsed ambiguous schema tokens. Owner/role/ACL readiness remained unverified.
- **The real encrypted archive has NOT yet been processed by the current V6.8 hardened pairing code.** A TABLE entry need not have TABLE DATA (for example partitioned parents), and a TABLE DATA entry cannot establish row counts. The historical reference of 76 user tables is a separately-scoped observation, not a synonym for the 77 TOC TABLE entries.
- Dependencies identified in safe form: 210 ACL, 27 DEFAULT ACL, 52 ROW SECURITY and 6 EXTENSION entries. The 12 visible owner-role tokens do not prove historical global roles or role grants.
- The **read-only** report format itself is not a cryptographically signed provenance receipt. The report says `AUDIT_PROFILE=V68_STRUCTURAL_TABLE_DATA`; it is a claim about the selected tool path, not an independently signed attestation.

## Root causes and safeguards

| Failure mode (severity) | How it would fail | Defense in this branch | Evidence still required |
| --- | --- | --- | --- |
| **P0 — wrong release/filename hash** | Previous operator diagnostics blocked from one stale Git blob SHA while scripts were fine | Eight-file SHA-pinned bundle, one immutable commit per run, refuse any mismatched source | Pin hashes from the final successful-**CI** commit; do not reuse previous command |
| **P0 — false TABLE/DATA pairing** | Name collision, differing owner tokens, repeated entries or orphan duplicated data give misleading counts | V6.8 pairs only strictly simple schema, object and owner *text*; tracks duplicates from union of keys; never pairs ambiguous or duplicated shapes | Real V6.8 authenticated aggregate, independently checked |
| **P0 — false data recovery claim** | Catalog contains TABLE DATA without accessible rows; partitioned parent omitted; dump truncated or data corrupt | Structural-only report; `PAIR_ROWS_VERIFIED=NO`, `CATALOG_COUNTS_DO_NOT_VALIDATE_DATA=YES`, `DATABASE_RESTORED=NO` | Full isolated restore, table-level row checks and application smoke tests |
| **P0 — roles/ACL/RLS not recreated** | Tables restore, permissions or RLS break access and services | Mandatory globals/owner/ACL/default ACL/RLS preflight gates; do not infer ownership from TOC trailing text | Official Supabase globals/roles sources, isolated grants and policy round trip |
| **P0 — side effects during restore** | pg_cron, pg_net, triggers/functions or external notifications run early | Disposable local Docker, no network for inspection; no SQL in TOC preflight | Restore rehearsal with cron/egress disabled and verified before any re-enable |
| **P0 — secrets/key loss or leakage** | Backups unusable without decryption material, or private values exposed by copy/log | Interactive local password; whitelist, fixed counters only; never expose names or secrets; key kept separately | Controlled offline/offsite key recovery rehearsal with approved custodian |
| **P1 — report/parser version drift** | Handwritten safe fixture passes while actual report emitter changes | Shared pure `renderSafeCatalogReport` used by main and authenticated synthetic contract test against V5.5; strict required `AUDIT_PROFILE` for PAIR counters | Commit-specific Ubuntu/Windows CI and operator smoke test |
| **P1 — identifier syntax ambiguity** | Quoted, Unicode, spaced owner/schema names misparsed as verified matches | Classify as ambiguous, never infer exact match; errors contain fixed codes only | Corpus of valid PG17 and future-version TOC variants; check ambiguous rates |
| **P1 — wrong Docker image/context** | Image only tagged differently, or script connects to remote engine | Only recognized local context, preloaded PG17 image verified by pg_restore --version, --pull never, isolated --network none | Local operator check on final pinned SHA; reject remote contexts |
| **P1 — cloud components omitted** | PostgreSQL restores but TaxiRadar web/push/storage unavailable | Separate deployment gates for Supabase Edge Functions, Storage, Cloudflare, routes, env/secrets, VAPID and API integrations | Staging redeploy and smoke tests with production access disabled |
| **P1 — copy consistency is not recoverability** | Three matching encrypted copies all contain a logical defect or lack essential assets | 3/3 SHA copies recorded; never equate with recoverability | Independent media check, rotated offsite copy and full recovery rehearsal |
| **P1 — misleading 4–6h RTO** | Rebuild delays exceed target | `RTO_4_TO_6_HOURS_PROVEN=NO` always until timed end-to-end rehearsal | Measured start to TaxiRadar working in clean staging, including secrets/storage/web |

## Required release sequence (do not skip stages)

1. **CI & provenance:** Final branch head, 34/34 pass including authenticated PG17 synthetic test and V5.5 report parser. Capture head SHA and exact file blob SHAs; review/test of the one-enter PowerShell operator. No new commits after attested CI without repeating CI check.
2. **Real TOC only:** Run the pinned eight-file operator against local AES-GCM-authenticated archive, with hidden interactive password, existing offline PG17 image, no SQL and automated clipboard sanitization. Record only aggregated `PAIR_*`, `SCOPE_*` and required no-write flags. If blocked, report sanitized error code and do not run recovery.
3. **Metadata reconciliation:** Obtain historical original schema table inventory/scope from authorized backups/catalogs, not from guessed differences. Compare partitions, inherited/foreign tables, extension-owned objects, user tables and TABLE DATA entries. No object names need to be published in chat.
4. **Role/extension readiness:** Acquire the official historical global-role artifacts and validate owners/ACL/DEFAULT ACL/RLS/extension versions in isolated environment. Supabase-specific migrations, policies and CRON definitions must be enumerated. Never treat TOC owner candidates as proof.
5. **Disposable isolated full restore:** Use fresh locked-down networkless Docker volumes and frozen credentials; disable cron, triggers with external side effects, pg_net and egress until reviewed. Verify pg_restore exit codes, extension compatibility, constraints, row counts, critical queries, policies and ownership. Do not write to CLEAN6 or production.
6. **Separate app/service recovery:** Rehydrate Storage file bodies and metadata, Edge Functions, frontend/Cloudflare, environment variables and encrypted secrets from separately governed offline references. Test push (VAPID), PIX workflow and two-role driver dispatch in staging with test endpoints only.
7. **RTO drill and UX gates:** Time the cold-start end-to-end recovery and establish real RTO/RPO evidence. Only after tests prove reproducible recovery should the interface expose the three requested actions (Criar Backup, Testar Recuperação, Recuperar Sistema) with explicit confirmations, owner-only permissions, protected logs and rollback.


## Operator-reported isolated PG17 synthetic recovery — 2026-11-26

The operator supplied an offline diagnostic report for the **local** V13 PowerShell laboratory (not a CI attestation): `STATUS=PASS`, `ISOLATION_VERIFIED=YES`, `DIRECT_INITDB_COMPLETED=YES`, `POSTGRES_READY=YES`, `SYNTHETIC_RESTORE=YES`, `DATA_VERIFIED=YES`, `RLS_POLICY_VERIFIED=YES`, `MUTATION_DETECTED=YES`, and `TEMP_CONTAINER_CLEANED=YES`. The disposable image was PostgreSQL 17.12+ with a resolved `postgres` UID/GID, 512 MiB `/dev/shm`, 1 GiB container memory, read-only filesystem with tmpfs, no network, and no published ports. The successful path explicitly ran `initdb` then `postgres`; the image-specific entrypoint previously exited before readiness. The specific entrypoint defect is **not** proven. No real archive or production database was used.

This is evidence that the user's machine can carry out a small synthetic dump/restore, including one RLS policy and a changed-value detection. **Not** evidence of authenticated real-backup restore, historical roles, ACL fidelity, extension availability, all-table row integrity, Cloudflare/Storage/Secrets recovery, or measured RTO. Preserve the historical-global-role and extension compatibility gates before real SQL. Future local operator scripts must keep single-paste PowerShell execution, sanitized diagnostics automatically copied using `Set-Clipboard`, and identity-verified cleanup.

## Operator-reported PG17 extension control-file availability — 2026-11-26

The operator supplied local offline V18 report: `STATUS=PASS`, `EXTENSION_DIRECTORY=FOUND`, `EXTENSIONS_CHECKED=6`; control files for `pgcrypto`, `pg_cron`, `pg_net`, `pg_graphql`, `vector`, and `postgis` all reported `YES` on a locally available PostgreSQL 17 image. This is **control-file presence only**, not proof of installed SQL definitions, library loadability, dependencies, restore compatibility, historical extension version matching, or production recovery. The probe used no SQL/server, backup data, image download, production or CLEAN6. Next gates: query local extension control default versions plus available migration scripts without sharing paths; obtain historical extension versions/roles from authorized historical artifacts before real restore. 

## Operator-reported extension default versions — 2026-11-26

Local V19 operator diagnostic: `STATUS=PASS`, six control files read on preloaded PostgreSQL 17 image, defaults: `pgcrypto=1.3`, `pg_cron=1.6.4`, `pg_net=0.20.4`, `pg_graphql=1.6.3`, `vector=0.8.2`, `postgis=3.3.7`. These are **local control-file default versions only**. No extension creation, SQL library load, backup content, historical version comparison, or global roles verification occurred. Next offline gate: locate matching versioned installation scripts and library artifacts, then obtain independent historical extension and globals evidence before real restore.

## Operator-reported extension installation artifact check — 2026-11-26

V20 reported `STATUS=PASS` for six local extension artifact checks on the image. Direct `name--default_version.sql` file found for `pgcrypto`, `pg_net`, `pg_graphql`, `vector`, `postgis`; **not found** for `pg_cron--1.6.4.sql` although the corresponding control file reported `default_version=1.6.4`. This is an *unresolved installation path* (may require a base-version script plus an update chain), **not** evidence of irreparable extension or actual CREATE EXTENSION failure. No SQL executed, no restore, no historical globals or version comparison. Next: enumerate only versioned `pg_cron` SQL artifact filenames, verify reachable update graph offline, then check library dependencies and historical origin.

## Regression policy

- Retain synthetic valid, corrupted AES-GCM, duplicate TOC ID, duplicate DATA-only name, two-owner mismatch, quoted schema/name, Unicode, nonstandard role, interrupted stream, missing Docker image, remote context, bad blob hash, clipboard sanitization and malformed/legacy V5.5 report cases.
- Keep the **zero-production-touch** guarantee in all catalogue/audit tests. No real passwords, database names, private table names, PII, bearer tokens or plaintext backups in PRs, CI logs or issue comments.
- Never say restore-ready or provide a timed recovery promise based solely on authenticated TOC counts, matching ciphertext copies or green CI.
