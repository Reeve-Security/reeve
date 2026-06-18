# Jamf Pro Template

Use this template to build a macOS PKG for Jamf Pro.

## Files

- `postinstall.sh`: package postinstall script.
- `com.reeve.scan.plist`: launchd schedule installed by `postinstall.sh`.

## Customization

Set these Jamf policy parameters or replace them before packaging:

- `$4`: Reeve binary URL (must be https).
- `$5`: signed `surfaces.yaml` URL.
- `$6`: `surfaces.yaml.sigstore.json` URL.
- `$7`: signer identity regexp.
- `$8`: Reeve binary Sigstore bundle URL (`aibom-cli.sigstore.json`).
- `$9`: signer OIDC issuer regexp.

The binary is signature-verified before it is made executable. The
postinstall downloads the binary and its Sigstore bundle (`$8`) to a
temporary path, runs `cosign verify-blob` against the signer identity
(`$7`) and OIDC issuer (`$9`), and only then moves it to
`/usr/local/bin/aibom-cli`. This fails closed: if `cosign` is missing or
verification fails, the install aborts non-zero and installs nothing.
`cosign` must be present on the endpoint.

## Expected endpoint layout

- Binary: `/usr/local/bin/aibom-cli`
- Config: `/Library/Application Support/Reeve/surfaces.yaml`
- Bundle: `/Library/Application Support/Reeve/surfaces.yaml.sigstore.json`
- Output: `/var/db/reeve/scans`
- Schedule: `/Library/LaunchDaemons/com.reeve.scan.plist`

## Packaging flow

1. Put `postinstall.sh` in the PKG scripts directory.
2. Include `com.reeve.scan.plist` in the package payload or let the
   postinstall write it.
3. Upload PKG to Jamf Pro.
4. Create a policy scoped to test Macs first.
5. Set parameters 4-9.
6. Run policy, then check `/var/log/reeve-install.log`.
