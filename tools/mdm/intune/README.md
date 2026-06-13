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
  -SignerIdentityRegexp "^repo:mycorp/reeve-config:.*$"
```

## macOS customization

Package `install-macos.sh` into the LOB app and pass the four variables
as environment values or pre-render them during packaging.

## Detection rule

Use file exists:

- Windows: `C:\Program Files\Reeve\aibom-cli.exe`
- macOS: `/usr/local/bin/aibom-cli`
