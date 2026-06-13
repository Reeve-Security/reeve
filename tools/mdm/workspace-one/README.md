# Workspace ONE Template

Reference template for Workspace ONE app deployment.

## Files

- `install.sh`: macOS / Linux shell installer.
- `assignment.json`: example assignment metadata to adapt in Workspace ONE.

## Customization

Replace these values before publishing the app:

- `REEVE_BINARY_URL`
- `REEVE_SURFACE_CONFIG_URL`
- `REEVE_SURFACE_CONFIG_BUNDLE_URL` for `surfaces.yaml.sigstore.json`
- `REEVE_SIGNER_IDENTITY_REGEXP`

For Windows fleets, use the Intune PowerShell script as the base and
wrap it as a Workspace ONE Windows app.
