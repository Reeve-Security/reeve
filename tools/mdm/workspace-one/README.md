# Workspace ONE Template

Reference template for Workspace ONE app deployment.

## Files

- `install.sh`: macOS / Linux shell installer.
- `assignment.json`: example assignment metadata to adapt in Workspace ONE.

## Customization

Replace these values before publishing the app:

- `REEVE_BINARY_URL` (must be https)
- `REEVE_BINARY_BUNDLE_URL` for the binary's `aibom-cli.sigstore.json`
- `REEVE_SURFACE_CONFIG_URL`
- `REEVE_SURFACE_CONFIG_BUNDLE_URL` for `surfaces.yaml.sigstore.json`
- `REEVE_SIGNER_IDENTITY_REGEXP`
- `REEVE_SIGNER_ISSUER_REGEXP` (signer OIDC issuer regexp)

The binary is signature-verified before it is made executable. The script
downloads the binary and its Sigstore bundle to a temporary path, runs
`cosign verify-blob` against the signer identity and OIDC issuer, and only
then installs it to `/usr/local/bin/aibom-cli`. This fails closed: if
`cosign` is missing, the URL is not https, or verification fails, the
install aborts non-zero and installs nothing. `cosign` must be present on
the endpoint.

For Windows fleets, use the Intune PowerShell script as the base and
wrap it as a Workspace ONE Windows app.
