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

## Consolidated guarded installer (candidate)

Run `scripts/Install-BridgeV6.ps1` only from a separately authenticated and manually reviewed local checkout. Supply an RSA public key that was already pinned through a trusted channel. Without `-Install`, it only checks script availability, PowerShell syntax and key material, and does not stage anything. `-Install` copies reviewed scripts to a chosen user directory; it deliberately **does not** create a Windows scheduled task, Windows service, background watcher, autostart or GitHub credential.

`scripts/BridgeV6-Operator.ps1 -Mode STATUS` reports only local staging state. `-Mode SELFTEST_ONCE` requires the installed receiver and a signed request at the configured endpoint; it is **not** a proof of end-to-end ChatGPT integration.

## Operational blockers — do not describe as ready

- Remote request publisher with protected signing key and authenticated operator is absent; public GitHub content alone is not authority.
- No private return transport to this ChatGPT session is available.
- The endpoint `bridge-v6/requests/current.json` remains intentionally unprovisioned.
- No configured Windows installation or local public-key pinning has been verified.
- No unattended task has been registered; the candidate receiver does not run in background by default.
- GitHub Actions execution results must be confirmed before any rollout.
- Keep existing local V5/V6 monitor active or inactive according to its current safe state until verified migration; do not blanket-kill unknown PowerShell instances.
