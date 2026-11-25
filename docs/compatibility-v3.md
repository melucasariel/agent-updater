# Current installed Guardian v3.0 updater — verified contract

This document was derived from the exact `GuardianUpdater.ps1` in the previously provided `ROTA62_Guardian_Agent_v3_Estavel.zip`. It is not a claim that automatic updates are already enabled.

## The exact current manifest format

```json
{
  "version": "3.0.1",
  "bundle_url": "https://github.com/melucasariel/agent-updater/releases/download/v3.0.1/guardian-3.0.1.zip",
  "bundle_sha256": "lowercase sha256 hex",
  "signature_base64": "RSA PKCS1 v1.5 SHA256 signature base64"
}
```

The v3.0 updater computes the signature payload **exactly** as UTF-8 bytes of:

```text
version + LF + bundle_url + LF + lowercase(bundle_sha256)
```

The public key is read from `%LOCALAPPDATA%\ROTA62_Guardian_AutoSend\update_source.json` as XML in `public_key_xml`. The URL is read from `manifest_url`. These values must be provisioned locally through a trusted process; merely linking a public key on GitHub is not sufficient.

The v3 updater accepts manifest HTTPS sources on `github.com` or `raw.githubusercontent.com`. It validates the RSA signature and SHA-256 of the downloaded ZIP, and allows only a one-file ZIP with `GuardianAgent.ps1`. It has no proper semantic-version downgrade protection and does not automatically restore a prior Agent if the updated one fails. **Do not enable unattended installation yet.**

## Required hardening before activating unattended install

1. Add semantic version comparison; reject same-version, downgrade and replayed feeds.
2. Add timeout, redirects/origin restrictions, and safer download error handling.
3. Add verified rollback after new-Agent startup failure.
4. Make update installation atomic; handle stop/restart races and backups.
5. Add self-tests for valid/tampered signatures, rollback, downgrade, and service startup.
6. Keep the DPAPI encrypted signing key local; never upload it or private XML to GitHub.
7. Test against an isolated mock/fixture before touching the installed Agent.

## Current state

Repo is configured for preparation only. There is no production Release, trusted key pinning, or unattended update enabled. Tools in `scripts/` generate signing materials locally; they do not connect to production and do not install any files.
