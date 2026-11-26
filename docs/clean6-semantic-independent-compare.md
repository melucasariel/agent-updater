# CLEAN6 independent offline semantic comparison

The historic CLEAN6 v1.4.1 script with SHA-256 `05335AD3C603F2E552470B8A95A7D626A1442A0CE9082F4AA9674B46AD29907A` was **not found** in the bounded local search (1,511 JS files and 36 ZIP JS entries). Three PowerShell history references do not recover the script. The recovered older ACL modules are not a replacement: `aplicar-acl-docker.mjs` can change grants; do not run it as an auditor.

`scripts/Compare-Clean6Semantics.mjs` is an **offline pure comparer** for two explicitly provided **locally stored** JSON semantic manifests, each with:

```json
{
  "format":"r62-clean6-semantic-v1",
  "owners":[{"id":"object-identity","owner":"role-name"}],
  "acls":[{"id":"object-identity","grantee":"role-name","privilege":"SELECT","grantor":"role-name","grantable":false}]
}
```

The `id` must uniquely and consistently identify objects in the two independently generated inventories. The manifests themselves contain role/object identifiers and **must remain local/private**. This verifier prints only counts, never identifiers, paths, or source content. It detects owner changes, missing and extra objects, missing/extra ACL tuple records, duplicates, and schema errors. It requires 185 owner records and 595 ACL tuples to return exit code zero **in addition** to an exact match. It explicitly marks `REAL_CLEAN6_VERIFIED=NO` regardless of result.

Usage *only after actual trusted manifests exist*: `node scripts/Compare-Clean6Semantics.mjs --expected C:\private\reference.json --actual C:\private\isolated-restore.json`. Do not publish those manifests to the public GitHub repo.

**This is not a replacement for PostgreSQL semantic extraction.** Actual recovery requires independent trustworthy reference/export inventories, the isolated PG17 environment, verified expected object identity and ACL catalog semantics, and proof of forced rollback/pre-post state. Never assume count equality alone proves ACL correctness; never substitute a synthetic fixture for recovery evidence.
