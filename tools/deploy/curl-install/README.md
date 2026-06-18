# Curl Install Template

For small teams without MDM. Host four files in S3, GCS, Azure Blob, or
another customer-controlled HTTPS location:

- Reeve binary
- the binary's Sigstore bundle (`aibom-cli.sigstore.json`)
- `surfaces.yaml`
- `surfaces.yaml.sigstore.json`

Then run:

```bash
REEVE_BINARY_URL="https://example.com/aibom-cli" \
REEVE_BINARY_BUNDLE_URL="https://example.com/aibom-cli.sigstore.json" \
REEVE_SURFACE_CONFIG_URL="https://example.com/surfaces.yaml" \
REEVE_SURFACE_CONFIG_BUNDLE_URL="https://example.com/surfaces.yaml.sigstore.json" \
REEVE_SIGNER_IDENTITY_REGEXP="^repo:mycorp/reeve-config:.*$" \
REEVE_SIGNER_ISSUER_REGEXP="^https://token.actions.githubusercontent.com$" \
sudo -E ./install.sh
```

The script supports macOS launchd and Linux systemd timers.

## Binary is signature-verified before execution (fail-closed)

The binary is now cryptographically verified before it is made executable.
Before installing, the script:

1. rejects a `REEVE_BINARY_URL` that is not `https://`;
2. downloads the binary and its Sigstore bundle to a temporary path;
3. runs `cosign verify-blob` on the downloaded binary against
   `REEVE_SIGNER_IDENTITY_REGEXP` and `REEVE_SIGNER_ISSUER_REGEXP`; and
4. only on success moves the binary into `/usr/local/bin/aibom-cli` and sets
   mode 0755.

This fails closed. If `cosign` is missing from `PATH`, if
`REEVE_BINARY_BUNDLE_URL` is unset, or if verification returns non-zero, the
install aborts non-zero and no binary is installed. Same-origin checksums are
not used: the binary's signature bundle is verified against a signer identity
and OIDC issuer you pin, so an attacker who controls the binary URL cannot
also forge an acceptable signature.

The new required environment variables are:

- `REEVE_BINARY_BUNDLE_URL`: URL for the binary's Sigstore bundle, the
  per-binary analogue of `surfaces.yaml.sigstore.json`.
- `REEVE_SIGNER_ISSUER_REGEXP`: regexp the signing certificate's OIDC issuer
  must match (for GitHub Actions signing this is
  `^https://token.actions.githubusercontent.com$`).

`cosign` must be on `PATH` at install time, in addition to the scheduler
runtime path described below. The template sets that runtime path to:

```text
/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

## macOS quarantine note

Reeve macOS binaries are Sigstore-signed release artifacts. Managed
installs that copy the binary from a trusted object store may not attach
a quarantine attribute; browser or Finder downloads often do.

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
- `REEVE_ALLOW_INSECURE_URL=1`: relax the https-only check on
  `REEVE_BINARY_URL` so a hermetic local test can serve fixtures over a
  localhost http server or `file://`. This relaxes only the URL scheme
  check. It never bypasses signature verification: `cosign verify-blob`
  still runs and must pass.

Production installs should not set any of these variables.

The hermetic binary-verification test lives at
`tools/deploy/curl-install/tests/verify_binary_test.sh`. It serves a tampered
binary plus an attacker-crafted bundle from localhost, stubs `cosign`, and
asserts the installer aborts non-zero and installs nothing when verification
fails, and succeeds when it passes.
