# Deployment Template Validation

This file records what the repository can prove automatically and what
still needs a real endpoint before a vendor package is called certified.

## CI validation

`python3 scripts/check-deploy-templates.py` verifies:

- all required MDM and no-MDM template files exist;
- every install script uses `--require-signed-config`;
- every install script references `surfaces.yaml.sigstore.json`;
- every install script pins a signer identity regexp;
- shell scripts pass `bash -n`, plus `shellcheck` when available;
- PowerShell scripts parse under `pwsh` when available;
- the Ansible template includes a systemd timer; and
- the curl-install template performs an endpoint-style install into a
  temporary root, writes the binary, signed surface config, signature
  bundle, systemd service, systemd timer, and runs signed-config
  verification through a stubbed `aibom-cli`.

The endpoint-style install uses:

- `REEVE_INSTALL_ROOT` to redirect `/usr/local`, `/etc`, and `/var`
  writes into a temporary directory; and
- `REEVE_SKIP_SCHEDULER=1` to avoid mutating host `systemd` or
  `launchd` state.

These test hooks are for validation only. Production installs should not
set either variable.

## Manual endpoint validation

Validate the templates on a disposable endpoint: run the curl-install
template against real system paths, then confirm the deployed binary
scans and verifies as documented in the repository README.

Before claiming a vendor package is certified for a customer deployment,
run one real endpoint test per package family:

1. Build or fetch the signed Reeve release artifact.
2. Host `surfaces.yaml` and `surfaces.yaml.sigstore.json` at deployer
   controlled URLs.
3. Install through the target channel:
   - Jamf PKG for macOS;
   - Intune Win32 app or macOS LOB package;
   - Workspace ONE app assignment;
   - curl-install on a clean Linux or macOS VM;
   - Group Policy startup script on a Windows domain VM.
4. Confirm the endpoint has:
   - Reeve binary at the documented system path;
   - `surfaces.yaml` and `surfaces.yaml.sigstore.json` at the
     OS-specific system config path;
   - scheduled scan registered in the OS scheduler; and
   - `aibom-cli scope list --require-signed-config
     --signer-identity-regexp <customer-regexp>` exits zero.
5. Trigger one scheduled scan and confirm output lands in the configured
   scan directory.

Record endpoint OS, package channel, Reeve version, signer regexp, and
scan output path in the PR or release note that certifies the template.
