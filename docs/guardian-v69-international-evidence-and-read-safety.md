# Guardian V6.9 — International research, scorecard and evidence gates (2026-11-25)

## What 10/10 means

10/10 is **conditional, reproducible evidence of each specific capability**, not a claim that every failure is impossible. No inherited green status: each SHA / Docker image digest / fixture set must be tested on its final committed version.

| Capability | Evidence required for **engineering 10/10** | Not demonstrated by this check |
| --- | --- | --- |
| A. Authenticated archive | exact 3/3 encrypted copies SHA256, strict AES-256-GCM tag/AAD and `PGDMP` header, same ciphertext **and same plaintext** on every pass, corrupted-header/tag/bitflip/truncation/replace-between-passes failures, strict key secrecy, key-recovery rehearsal | data decompressibility, live ownership and app recovery |
| B. Complete PostgreSQL archive parsing | PostgreSQL **17.12+** runtime on immutable local image ID, signed image provenance assessed separately, successful `pg_restore --list` plus explicit opt-in `pg_restore --file=/dev/null` without `-d`, exhaustive streamed plaintext from exactly the authenticated archive; wrong format and truncated authenticated archive rejection; repeatable Linux/Windows host integration | SQL execution, row accuracy, RLS/ACL semantics, all output data ever tested in a restored DB |
| C. TOC structural interpretation | all object class counters reconcile (919), TABLE schema split sums to TABLE=77, TABLE/DATA paired/unpaired/ambiguous counts reconcile, explicit owners treated as **tokens only**, duplicate/complex/Unicode/partition/foreign/extension cases, malformed report denied, no private object names emitted, original-scope 76 reference independently reconciled | no guarantee every DB row exists, nor that global roles were included in the database dump |

**Important:** 10/10 in (A), (B), (C) would **still not** mean 10/10 recovery. Actual encrypted backup data can be logically incomplete even with a valid GCM tag, and a successful `pg_restore --file=/dev/null` produces SQL/text but never executes SQL. A database restore may execute code embedded by source superusers; review generated SQL and isolate any full rehearsal.

## Confirmed engineering findings

1. Official PostgreSQL 17 documentation distinguishes `pg_restore --list` from script emission. With **no** `-d`, it emits SQL text instead of connecting to a DB; `-f /dev/null` discards it in the disposable Linux container. No `--jobs` for piped archive input, as standard input only works without parallel restore.
2. `--data-only` covers TABLE DATA, large objects, and sequence values, but not full schema definitions; for deeper broad-read validation use default full script emission, **not** `--data-only` alone. The full stream may still fail to prove database acceptability.
3. PostgreSQL 17.12 is the official 17.x maintenance release as of 2026-11-25. Deep-read path must **refuse** unpatched 17.x images instead of silently switching images or downloading from a network.
4. PostgreSQL `pg_verifybackup` applies to physical/base backups, **not** to custom-format `pg_dump -Fc`; never use it as a validity certificate for `.r62db` decrypted PGDMP.
5. A logical dump from a single DB does **not** include cluster-wide global role definitions. Use `pg_dumpall --globals-only` or provider-supported historical role dumps, independently protected and verified.
6. Supabase's database backups contain Storage metadata but not the actual Storage object bodies; app recovery additionally requires Storage objects, Edge Functions, environment secrets, web deployment and external API configuration.
7. PostgreSQL warns that restoring a dump from an untrusted source can execute arbitrary SQL or code under the restore privileges. An isolated Docker `--network none`, `--read-only`, no mount, limited resources, and **no** DB destination are mandatory for inspection.
8. As discovered by CI, a missing capturing group for owner text caused the V6.8 pairing algorithm to declare a false match. Corrected in draft; this reinforces negative tests for false positives and the rule that plain tokens are never ownership proof.
9. Time-of-check/time-of-use applies to both cipher bytes and Docker tags. The read path now binds second-pass plaintext/cipher hashes and pins a local immutable Docker image ID.

## Cross-language source review (official documentation prioritized)

Research consulted authoritative English, Japanese and Russian PostgreSQL 17 references, and Portuguese/Spanish Azure PostgreSQL operational guidance. Search across every language on the internet is impossible; technical consensus is grounded in upstream normative docs and cross-checked translations.

- EN upstream PostgreSQL 17 pg_restore: https://www.postgresql.org/docs/17/app-pgrestore.html
- JP PostgreSQL 17 pg_restore: https://www.postgresql.jp/docs/17/app-pgrestore.html
- RU Postgres Professional pg_restore: https://postgrespro.ru/docs/postgresql/17/app-pgrestore
- PT-BR Microsoft Azure PostgreSQL migration: https://learn.microsoft.com/pt-br/azure/postgresql/migrate/how-to-migrate-using-dump-and-restore
- ES Microsoft Azure pg_dump and pg_restore: https://learn.microsoft.com/es-es/azure/postgresql/troubleshoot/how-to-pgdump-restore
- EN PostgreSQL 17 release / 17.12 maintenance: https://www.postgresql.org/support/versioning/
- EN PostgreSQL physical `pg_verifybackup`: https://www.postgresql.org/docs/17/app-pgverifybackup.html
- EN PostgreSQL `pg_dumpall` globals: https://www.postgresql.org/docs/17/app-pg-dumpall.html
- EN Supabase backups: https://supabase.com/docs/guides/platform/backups
- EN Supabase CLI migration/roles: https://supabase.com/docs/guides/platform/migrating-within-supabase/backup-restore
- EN Node.js AES-GCM finalization: https://nodejs.org/api/crypto.html
- EN Docker --network none: https://docs.docker.com/engine/network/drivers/none/
- EN Docker --read-only and resource limits: https://docs.docker.com/reference/cli/docker/container/run

## Implementation / release status

- V6.7 authentic read: real backup 919 TOC, 77 TABLE, 73 TABLE DATA, 25 public, 52 other schemas; 3/3 ciphertext copies validated. **No actual record values or SQL restored.**
- V6.8: TOC pairs with strict syntax and arithmetic checks, safe report parser. New hardening (owner-text false match fix, data-only duplicates, deterministic tests) requires **final-commit CI**.
- V6.9 experimental deep read: opt-in `--deep-read` only after local PG17.12+ check; writer is `/dev/null` inside a disposable isolated container. Authenticated input streamed from encrypted file; no plaintext disk file, no DB, no SQL executed. This must pass synthetic good/truncated/corrupted PGDMP tests on CI before any real backup read. No auto image download. Disposable Docker cleanup only if unique per-invocation ownership label matches.
- Release is **NOT YET CERTIFIED** for live V6.9 until those jobs succeed; **no** merge/deploy/restore permitted.

## Next high-value checks

1. Fix the first failing synthetic CI case; don't treat a previous 34/34 green commit as evidence for a new SHA.
2. Verify generated and consumed byte counts and kill/timeout behavior for piped `pg_restore --file=/dev/null`, including truncated mid-payload and valid re-encryption of a damaged PGDMP.
3. After final green CI, create a pinned one-enter Windows PowerShell operator for opt-in full read; clipboard only whitelisted counts/status. The password remains local and interactive.
4. Run **read-only** full scan against the real encrypted archive only after version/privileges safeguards pass; no data or names in conversation.
5. For 10/10 of semantic restoreability, still conduct an isolated full database restore with source-code/RLS review, then row and app integration checks separately; do not conflate with these three read-only scores.
