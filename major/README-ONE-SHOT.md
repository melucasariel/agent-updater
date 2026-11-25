# ROTA62 Guardian major v3.4: one command, six suites, guarded installation

## First use (Windows PowerShell 5.1)

This is a **one-time** action because the installed Guardian v3.0 cannot execute unrecognized update commands.

The command downloads exactly one audited orchestrator from an immutable GitHub commit, checks its SHA256, and runs **all six** tests before updating. It downloads all 11 dependencies with individually pinned SHA256 values. If tests or the local preflight fail, installation is blocked.

```powershell
$ErrorActionPreference='Stop'
$f=Join-Path $env:TEMP 'R62-Major-v34-OneShot.ps1'
try {
  Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/melucasariel/agent-updater/5fc0188a60e9f07c92e85f0b98274b5d33ac0ca8/major/OneShot-TestAndUpgrade-v3.4.ps1' -OutFile $f -UseBasicParsing
  if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -cne '1C17E3DF2F691AB178710B55789188D0D8DCEA4FBC2D7C4E17BC19D8A1AC5680') { throw 'SHA256_DIVERGENTE' }
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f
  if ($LASTEXITCODE -ne 0) { throw 'GUARDIAN_MAJOR_NAO_APROVADO' }
} finally {
  Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
}
```

The orchestrator copies a **safe diagnostic result** to the clipboard automatically. Paste only that safe report into ChatGPT. Never paste keys, tokens or backups.

## Tests automatically performed

- Fail-closed updater and no-trust smoke tests (7)
- Signed manifest, origin validation, anti-downgrade (11)
- Disposable supervisor/rollback tests (10)
- Actual Windows child-process nonce/PID/hash health tests (6)
- Integrated supervisor/health rollback tests (4)
- Complete major bootstrap on a disposable Windows fixture (7)

These do **not** run on live TaxiRadar containers. Passing isolated tests doesn't prove the real user's installation until the resulting local health report returns.

## Local switch safeguards

The bridge verifies exact SHA256 of the installed v3.0 Agent and updater. Any mismatch prevents the change. It downloads and verifies a fixed v3.4 updater, patches only the Agent's startup health handshake, backs up both files, releases the old mutex, swaps the files, validates the new child PID/nonce/hash/version, and restores the previous Agent on failure.

## Important limit

Configuring the signed GitHub feed **does not create a signed Release**. Future unattended updates only work after a valid signed `release.json` and matching ZIP are published to GitHub Releases using the local DPAPI signing key; this stage remains pending. Never upload private signing keys to GitHub.

## No live database changes

No SQL writes, Docker modifications, or TaxiRadar production operations are in this workflow.
