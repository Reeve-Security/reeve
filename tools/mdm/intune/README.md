# Microsoft Intune Template

Reference template for Intune-managed Windows endpoints and macOS LOB
packages.

## Files

- `install-windows.ps1`: Windows install + Scheduled Task.
- `install-macos.sh`: macOS install + launchd schedule for Intune LOB PKG.

## Windows customization

Set these Intune Win32 app install command parameters:

```powershell
powershell.exe -ExecutionPolicy Bypass -File install-windows.ps1 `
  -BinaryUrl "https://example.com/aibom-cli.exe" `
  -ConfigUrl "https://example.com/surfaces.yaml" `
  -BundleUrl "https://example.com/surfaces.yaml.sigstore.json" `
  -SignerIdentityRegexp "^repo:mycorp/reeve-config:.*$" `
  -BinaryBundleUrl "https://example.com/aibom-cli.sigstore.json" `
  -SignerIssuerRegexp "^https://token.actions.githubusercontent.com$"
```

The binary is signature-verified before it is made executable. The script
downloads the binary and its Sigstore bundle (`-BinaryBundleUrl`) to
`$env:TEMP`, runs `cosign.exe verify-blob` against the signer identity and
OIDC issuer (`-SignerIssuerRegexp`), and only then moves it into
`C:\Program Files\Reeve\aibom-cli.exe`. This fails closed: if `cosign` is
missing, the URL is not https, or verification fails, the script throws and
installs nothing. `cosign` must be on the endpoint `PATH`.

## macOS customization

Package `install-macos.sh` into the LOB app and pass the six variables
(now including `REEVE_BINARY_BUNDLE_URL` and `REEVE_SIGNER_ISSUER_REGEXP`)
as environment values or pre-render them during packaging. The macOS script
verifies the binary with `cosign verify-blob` before installing it, the
same fail-closed behavior as the Windows script.

## Detection rule

Use file exists:

- Windows: `C:\Program Files\Reeve\aibom-cli.exe`
- macOS: `/usr/local/bin/aibom-cli`
