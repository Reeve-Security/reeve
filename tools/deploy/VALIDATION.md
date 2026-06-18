# Deployment Template Validation

This file records what the repository can prove automatically and what
still needs a real endpoint before a vendor package is called certified.

## CI validation

`python3 scripts/check-deploy-templates.py` verifies:

- all required MDM and no-MDM template files exist;
- every install script uses `--require-signed-config`;
- every install script references `surfaces.yaml.sigstore.json`;
- every install script pins a signer identity regexp;
- every install script verifies the binary with `cosign verify-blob` and
  pins an OIDC issuer regexp (`certificate-oidc-issuer-regexp`);
- shell scripts pass `bash -n`, plus `shellcheck` when available;
- PowerShell scripts parse under `pwsh` when available;
- the Ansible template includes a systemd timer and a `cosign verify-blob`
  step with an OIDC issuer regexp; and
- the curl-install template performs an endpoint-style install into a
  temporary root, verifies the binary through a stubbed `cosign`, writes the
  binary, signed surface config, signature bundle, systemd service, systemd
  timer, and runs signed-config verification through a stubbed `aibom-cli`.

## Binary signature verification (GHSA-9cmp-5q9w-hw7r)

Every install template now cryptographically verifies the Reeve binary
before it is made executable, and fails closed. Each template:

1. rejects a non-`https://` binary URL;
2. downloads the binary and its Sigstore bundle to a temporary path;
3. runs `cosign verify-blob` on the binary against the pinned signer
   identity (`REEVE_SIGNER_IDENTITY_REGEXP`) and OIDC issuer
   (`REEVE_SIGNER_ISSUER_REGEXP`); and
4. only on success moves the binary into its final path and sets mode 0755.

If `cosign` is missing, the binary bundle URL is unset, or verification
returns non-zero, the install aborts non-zero and no binary is installed.
The two new required inputs are `REEVE_BINARY_BUNDLE_URL` and
`REEVE_SIGNER_ISSUER_REGEXP` (the Jamf `postinstall.sh` takes them as
positional arguments 8 and 9; the PowerShell templates take them as
`-BinaryBundleUrl` and `-SignerIssuerRegexp`; the Ansible playbook takes
them as `reeve_binary_bundle_url` and `reeve_signer_issuer_regexp`).

A hermetic test at `tools/deploy/curl-install/tests/verify_binary_test.sh`
proves the fail-closed behavior: with an attacker controlling both the
binary URL and the bundle URL, the installer aborts non-zero and installs
nothing.

The endpoint-style install uses:

- `REEVE_INSTALL_ROOT` to redirect `/usr/local`, `/etc`, and `/var`
  writes into a temporary directory;
- `REEVE_SKIP_SCHEDULER=1` to avoid mutating host `systemd` or
  `launchd` state; and
- `REEVE_ALLOW_INSECURE_URL=1` to allow `file://` or localhost http
  fixtures past the https-only check. This relaxes only the URL scheme
  check; `cosign verify-blob` still runs and must pass.

These test hooks are for validation only. Production installs should not
set any of them.

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
