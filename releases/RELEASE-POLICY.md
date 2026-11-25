# Guardian 3.4.1 — signed canary release policy

## Current verified baseline
Local Guardian v3.4.0 was installed and passed health verification; six isolated PowerShell test suites passed on the user's Windows. These facts do **not** demonstrate release-delivery or unattended upgrade yet.

## Signing
The private RSA key resides only in the Windows user's DPAPI CurrentUser file. It is never placed in GitHub Actions secrets, GitHub repository files, release assets, reports, or this chat.

`releases/BuildAndPublish-GuardianCanary-v3.4.1.ps1` creates a small ZIP containing exactly one `GuardianAgent.ps1` by minimally modifying the installed Agent's health version to `3.4.1`. It signs `release.json` using the exact string:

`3.4.1 + LF + https://github.com/melucasariel/agent-updater/releases/download/v3.4.1/guardian-v3.4.1.zip + LF + lowercase(zip SHA256)`

The manifest has `version`, `bundle_url`, `bundle_sha256` and `signature_base64`; the existing Guardian 3.4 updater verifies all of them.

## Canary publish
The script's default invocation creates/validates the ZIP and signed manifest in a temporary directory and removes them; nothing is published. With `-PublishCanary`, it requires GitHub CLI (`gh`) installed and authenticated **on the user's Windows computer**. The ChatGPT GitHub connection does not automatically authenticate `gh` on the user's machine.

On successful authentication, it publishes assets to a **GitHub prerelease** tagged `v3.4.1`, with `--prerelease --latest=false`. It then downloads the published assets and validates ZIP SHA256 and the signed manifest again. It refuses to overwrite an existing release.

Because prereleases are not selected by GitHub's `/releases/latest` endpoint, this canary does not yet reach the Guardian 24-hour automatic update check.

## Promotion gate — do not skip
1. Check that the canary assets were published and downloaded intact.
2. Independently validate a signed manifest retrieval and a candidate Agent startup under the **real updater** in a disposable Windows lab.
3. Include tests for network redirects, invalid signatures, untrusted URLs, downgrade, interrupted switch, and rollback.
4. Only after complete approval can `v3.4.1` be promoted to an ordinary (non-prerelease) Latest release, activating automatic installation on scheduled checks.
5. Monitor rollout health and retain the locally protected signing key and old Agent backup.

Do not promote merely because an offline signer test passes.

## No database actions
No scripts in the signing/publishing workflow invoke Docker or PostgreSQL or perform TaxiRadar app updates.
