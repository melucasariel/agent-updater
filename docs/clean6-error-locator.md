# CLEAN6 marker-based local error locator

Script: `scripts/Locate-Clean6ErrorMarkers.ps1`

Purpose: identify candidate script fingerprints behind `LOCAL_ERROR_REDACTED` without needing the script's exact filename. The scan is bounded to the supplied directory and its first-level children, at most 150 selected source files by default, and excludes files above 2 MiB. The only source text used for matching is four fixed diagnostic markers. The report contains marker names, SHA-256 prefix, counts, no paths and no source snippets. The program reads source text locally, never transmits it, and does not run commands from it.

The default search root is Windows TEMP. If no candidate is found, the marker may be embedded in another directory, different language, or dynamic code; `FILES_MATCHED=0` does not prove absence. This tool does not diagnose the error cause by itself. This script is separate from the signed receiver and requires local trusted setup before use.

Neither file-fingerprint matching nor CI success proves CLEAN6's audit of 185 owners and 595 ACLs. The audit stays disabled until the script is inspected and its failure path is understood, with rollback independently verified in isolated PostgreSQL.
