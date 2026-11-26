# CLEAN6 PG17 catalog exporter candidate — controlled read-only

`scripts/Export-Clean6Catalog.sql` creates a *private local JSON semantic inventory* directly from PostgreSQL catalogs. SQL is in a repeatable-read **READ ONLY** transaction and ends in `ROLLBACK`; it makes no grants, schema changes or writes.

**Do not run against production or an unidentified Docker container.** Verify an isolated disposable PG17 database and the expected copy of the archive first. There is no automatic production/isolated database recognition in this script. Do not enable TCP exposure or reconnect to Supabase production.

The exporter includes app schemas outside `pg_*` and `information_schema`, schema, relation, function, standalone type owners and effective catalog ACL (explicit ACL or PostgreSQL built-in defaults), plus default ACL entries. It compares *catalog-semantic* privilege tuples, not runtime execution policy/permissions. Roles must be consistently present. Schema membership and representation may differ from the historic CLEAN6 v1.4.1 implementation; **do not equate its row counts with 185 owners and 595 ACL without establishing object scope and provenance**.

For an **already independently verified disposable PG17 lab**, using an authenticated psql session without displaying credentials, run locally:
`psql -X -qAt -v ON_ERROR_STOP=1 -f scripts/Export-Clean6Catalog.sql > PRIVATE_MANIFEST.json`.
The resulting inventory includes **object names and role names**: keep it private, outside Git/public logs. No SQL export should be run until host, database name, service role and isolation have been verified, and the SQL reviewed. Never paste manifest data into ChatGPT: share only the sanitized comparer report.

Then compare against a *separately sourced authentic* reference manifest:
`node scripts/Compare-Clean6Semantics.mjs --expected PRIVATE_REFERENCE.json --actual PRIVATE_MANIFEST.json`.

The present exporter is **not** an automatic backup restore checker: it cannot prove the restored data provenance or independent reference, cannot prove a mutation + rollback, and does not reproduce the missing original v1.4.1 script byte-for-byte. CI uses a synthetic Postgres service only. The older `aplicar-acl-docker.mjs` should not be used to perform read-only checks.
