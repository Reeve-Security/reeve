# Group Policy Template

Reference path for Windows domain shops without Intune.

## Files

- `install-reeve.ps1`: installs Reeve, signed config, and Scheduled Task.

## Usage

1. Host the Reeve Windows binary, its Sigstore bundle
   (`aibom-cli.sigstore.json`), `surfaces.yaml`, and
   `surfaces.yaml.sigstore.json` on an internal HTTPS file server.
2. Create a Group Policy Object.
3. Add a startup script invoking `install-reeve.ps1` with the required
   parameters.
4. Scope first to a test OU.

Example startup command:

```powershell
powershell.exe -ExecutionPolicy Bypass -File \\fileserver\reeve\install-reeve.ps1 `
  -BinaryUrl "https://files.example/aibom-cli.exe" `
  -ConfigUrl "https://files.example/surfaces.yaml" `
  -BundleUrl "https://files.example/surfaces.yaml.sigstore.json" `
  -SignerIdentityRegexp "^repo:mycorp/reeve-config:.*$" `
  -BinaryBundleUrl "https://files.example/aibom-cli.sigstore.json" `
  -SignerIssuerRegexp "^https://token.actions.githubusercontent.com$"
```

The binary is signature-verified before it is made executable. The script
downloads the binary and its Sigstore bundle (`-BinaryBundleUrl`) to
`$env:TEMP`, runs `cosign.exe verify-blob` against the signer identity and
OIDC issuer (`-SignerIssuerRegexp`), and only then moves it into place. This
fails closed: if `cosign` is missing, the URL is not https, or verification
fails, the script throws and installs nothing. `cosign` must be on the
endpoint `PATH`.
