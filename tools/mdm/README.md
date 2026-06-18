# Reeve MDM Templates

Reference templates for shipping Reeve through endpoint-management tools.
Each template assumes these deployer-owned inputs:

- `REEVE_BINARY_URL`: https URL for the Reeve binary or package.
- `REEVE_BINARY_BUNDLE_URL`: URL for the binary's Sigstore bundle
  (`aibom-cli.sigstore.json`).
- `REEVE_SURFACE_CONFIG_URL`: URL for `surfaces.yaml`.
- `REEVE_SURFACE_CONFIG_BUNDLE_URL`: URL for `surfaces.yaml.sigstore.json`.
- `REEVE_SIGNER_IDENTITY_REGEXP`: OIDC identity regexp allowed to sign.
- `REEVE_SIGNER_ISSUER_REGEXP`: OIDC issuer regexp the signing certificate
  must match.

The Jamf template passes these as positional arguments rather than
environment variables (binary bundle URL is `$8`, issuer regexp is `$9`).

Templates verify the binary before it is made executable, place the signed
surface config at the system path, and schedule a recurring scan with
`--require-signed-config`.

The binary is signature-verified before execution and fails closed: each
template downloads the binary and its Sigstore bundle to a temporary path,
runs `cosign verify-blob` against the signer identity and OIDC issuer, and
only then installs it. If `cosign` is missing, the URL is not https, or
verification fails, the install aborts non-zero and installs nothing.
`cosign` must be present on the endpoint.

These templates verify the signed surface config (`--require-signed-config`);
they do not sign scan output (`--skip-sign`). Endpoint and fleet output
signing are tracked post-launch.

| Platform | Path | Status |
|---|---|---|
| Jamf Pro | `tools/mdm/jamf/` | Reference PKG payload + postinstall |
| Microsoft Intune | `tools/mdm/intune/` | Reference Windows PowerShell + macOS shell |
| Workspace ONE | `tools/mdm/workspace-one/` | Reference install script + assignment notes |

These are starting points, not vendor-certified packages.
