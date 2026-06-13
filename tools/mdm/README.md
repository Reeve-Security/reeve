# Reeve MDM Templates

Reference templates for shipping Reeve through endpoint-management tools.
Each template assumes four deployer-owned inputs:

- `REEVE_BINARY_URL`: URL for the verified Reeve binary or package.
- `REEVE_SURFACE_CONFIG_URL`: URL for `surfaces.yaml`.
- `REEVE_SURFACE_CONFIG_BUNDLE_URL`: URL for `surfaces.yaml.sigstore.json`.
- `REEVE_SIGNER_IDENTITY_REGEXP`: OIDC identity regexp allowed to sign the config.

Templates install the binary, place the signed surface config at the
system path, and schedule a recurring scan with
`--require-signed-config`.

These templates verify the signed surface config (`--require-signed-config`);
they do not sign scan output (`--skip-sign`). Endpoint and fleet output
signing are tracked post-launch.

| Platform | Path | Status |
|---|---|---|
| Jamf Pro | `tools/mdm/jamf/` | Reference PKG payload + postinstall |
| Microsoft Intune | `tools/mdm/intune/` | Reference Windows PowerShell + macOS shell |
| Workspace ONE | `tools/mdm/workspace-one/` | Reference install script + assignment notes |

These are starting points, not vendor-certified packages.
