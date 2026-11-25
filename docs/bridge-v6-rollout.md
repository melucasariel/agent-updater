# ROTA62 Bridge V6 — receiver rollout

## Status
**Source-only candidate. Not installed on the user's Windows, not enabled for unattended operation, and no ChatGPT return transport.**

The receiver (`scripts/Receive-BridgeV6.ps1`) pulls ONLY:
`https://raw.githubusercontent.com/melucasariel/agent-updater/main/bridge-v6/requests/current.json`.
No request is currently published to that path.

It uses the locally pinned RSA public key, offline signature verification, persistent replay markers and a single-instance mutex. Only three fixed operations exist: `SELFTEST` (Docker status/count), `AUDIT_PREFLIGHT` (file-existence test), and `STOP` (only this receiver). There is no arbitrary PowerShell or SQL action and no auto-send functionality.

## Local bootstrap requirements (not done)
1. Independent verification of package signature and inspected agent code before any installation. Existing Guardian v3 updates are explicitly disabled and must NOT be used to bootstrap this receiver.
2. Generate signing key in a trusted local environment or controlled GitHub Action. Pin PUBLIC key to the Windows machine over an authenticated channel. Never commit the private key.
3. Set local `-PublicKeyPath` and `-StateDirectory`, run first in `-Once` mode and inspect `status.log`.
4. Add a separate authenticated publisher for a signed `current.json` request; publishing raw unsigned files cannot trigger actions.
5. A private, consented response destination is needed to return results to ChatGPT. This repository is PUBLIC and MUST NEVER receive diagnostic logs, database records, tokens, passwords or backups.
6. Investigate existing local V5/V6 monitors before stopping processes; do not force-stop unrelated Windows tasks.

## Constraints
- `SEMANTICS`, backup decryption, PostgreSQL write, restores and production deployment are forbidden here.
- Replays are rejected; logs are local and intentionally omit request contents.
- A public GitHub commit by itself cannot authenticate requests or make ChatGPT view local results.
- The static current.json endpoint is a provisional test transport and not a multi-request queue.
