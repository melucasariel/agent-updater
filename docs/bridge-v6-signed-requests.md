# Bridge V6 — signed request format (offline validation only)

Status: **verification code published, no remote execution enabled**.

## Wire format
UTF-8 JSON object with EXACT fields `protocol_version`, `request_id`, `command`, `issued_at`, `expires_at`, `nonce`, `signature`. Format version `6.0`. Allowed commands: `SELFTEST`, `AUDIT_PREFLIGHT`, `STOP`. The timestamp format is UTC `yyyy-MM-ddTHH:mm:ssZ` with second precision; expiry is at most 5 minutes from issue. IDs and nonce need uniqueness.

## Exact signature payload
Sign the UTF-8 bytes of these seven strings joined with LF (no trailing LF):
```
ROTA62-BRIDGE-V6
6.0
<request_id>
<command>
<issued_at>
<expires_at>
<nonce>
```
Use RSA-2048 or higher with PKCS#1 v1.5 SHA-256. Encode the signature as base64. The public key is an RSAKeyValue **public-only XML** locally pinned through an independently authenticated setup step. Never publish the private key or store a trusted public key supplied inside the command being verified.

The offline validator at `scripts/Verify-BridgeV6Request.ps1` validates fields, time window, signature and key. Success exits code 3 with `[OK] REQUEST_SIGNATURE_VERIFIED` followed by `[BLOQUEADO] NO_LOCAL_EXECUTION_REPLAY_PROTECTION_REQUIRED`: the tool intentionally never executes a command.

## Activation blockers
- Implement local replay cache (atomic and persistent, with expiry), endpoint authentication, request origin and destination binding, concurrency limits and emergency stop.
- Inspect the actual installed Windows monitor before modifying it.
- GitHub repository is public and remains *update distribution only*; do not use it to collect reports, secrets or personal data.
- No automatic ChatGPT response transport exists yet; do not infer success from a GitHub commit.
- Keep `SEMANTICS`, PostgreSQL mutation, restore and production actions disabled.
