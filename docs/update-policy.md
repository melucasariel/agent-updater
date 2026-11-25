# Guardian secure-update policy — v3.0 compatibility

## Verified local updater contract

The installed v3.0 reads `%LOCALAPPDATA%\ROTA62_Guardian_AutoSend\update_source.json` containing `manifest_url` (HTTPS) and `public_key_xml` (RSA public key pinned locally).

The exact remote manifest fields are:
- `version`: strict `3.x.y`, e.g. `3.0.1`
- `bundle_url`: HTTPS ZIP download URL
- `bundle_sha256`: 64 hexadecimal digits
- `signature_base64`: RSA PKCS#1 v1.5 signature over UTF-8 payload `version + LF + bundle_url + LF + lowercase(bundle_sha256)` using SHA-256

The ZIP must contain only one root file named `GuardianAgent.ps1`, up to 100 KB uncompressed, and the total ZIP must be no more than 2 MB. See [full compatibility document](compatibility-v3.md).

## Trust bootstrap (not done yet)

1. Generate the publishing key **locally** using `scripts/Initialize-GuardianSigning.ps1`. Never upload the private key or DPAPI file.
2. Review and pin the public XML on the local Agent using a trusted local setup process.
3. Publish a signed manifesto and matching ZIP as official GitHub Release assets.
4. Verify the signing, download, version, update, and rollback tests using a disposable lab before activating installation.

## Blocking issues before unattended installation

The installed v3.0 does **not** fully reject older/same versions and does **not** implement automated rollback if a new Agent fails. Accordingly, signing tools alone **do not make unattended installation safe**. Until these features and tests are implemented, keep remote installation disabled.

Never distribute database backups, credentials, environment secrets, private keys, personal data, or production configuration via this repository.
