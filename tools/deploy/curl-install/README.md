# Curl Install Template

For small teams without MDM. Host three files in S3, GCS, Azure Blob, or
another customer-controlled HTTPS location:

- Reeve binary
- `surfaces.yaml`
- `surfaces.yaml.sigstore.json`

Then run:

```bash
REEVE_BINARY_URL="https://example.com/aibom-cli" \
REEVE_SURFACE_CONFIG_URL="https://example.com/surfaces.yaml" \
REEVE_SURFACE_CONFIG_BUNDLE_URL="https://example.com/surfaces.yaml.sigstore.json" \
REEVE_SIGNER_IDENTITY_REGEXP="^repo:mycorp/reeve-config:.*$" \
sudo -E ./install.sh
```

The script supports macOS launchd and Linux systemd timers.

Endpoints using `--require-signed-config` must have `cosign` available on
the scheduler runtime path. The template sets that runtime path to:

```text
/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

## macOS quarantine note

Reeve macOS binaries are Sigstore-signed release artifacts. Apple
Developer ID signing and notarization are tracked in issue #147 and are
not yet wired into releases. Managed installs that copy the binary from a
trusted object store may not attach a quarantine attribute; browser or
Finder downloads often do.

If macOS blocks a verified binary on first run, remove the quarantine
attribute after verifying the release artifact:

```bash
sudo xattr -d com.apple.quarantine /usr/local/bin/aibom-cli 2>/dev/null || true
```

For CI and local template validation only, the script also accepts:

- `REEVE_INSTALL_ROOT`: prefix for system paths, so validation can write
  into a temporary endpoint root instead of `/usr/local`, `/etc`,
  `/Library`, or `/var`.
- `REEVE_SKIP_SCHEDULER=1`: write scheduler files but do not register
  them with `systemd` or `launchd`.

Production installs should not set either variable.
