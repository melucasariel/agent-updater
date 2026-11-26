# CLEAN6 Unified Triage V1 — one local diagnostic command

The reviewed script `scripts/Invoke-Clean6Triage.ps1` invokes **both** bounded read-only diagnostics in one action. It returns a sanitized consolidated report and copies it to the clipboard by default. It does not ask for passwords, execute the semantic audit, decrypt the backup, run SQL, modify Docker, or send messages over the network.

The local operator supports `-Mode CLEAN6_TRIAGE` after a trusted, separately reviewed installation. For deterministic testing, provide an explicit `-AuditScriptPath`, `-SearchRoot` and `-SkipDocker`. The default checks Docker availability and bounded audit candidates and marker files. No source filenames, local paths, script contents, database data or secrets are included in the output.

Decision codes:
- `AUDIT_CANDIDATE_IDENTIFIED`: a recognized audit file was discovered; **not** a claim of valid or executable audit.
- `ERROR_MARKER_CANDIDATE_IDENTIFIED`: marker found in scripts; not proof of error cause.
- `NO_CANDIDATES_IN_BOUNDED_SEARCH`: not found in the search limits; not proof of absence.
- `INCOMPLETE` or `FAILED_REDACTED`: diagnose local environment without copying secrets.

The script copies the report; the user must still paste it into ChatGPT. The public GitHub repository is NOT a private report channel. The original `LOCAL_ERROR_REDACTED` remains unresolved, and the PG17 semantic transaction/forced ROLLBACK has not been revalidated.
