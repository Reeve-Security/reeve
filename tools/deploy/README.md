# Reeve No-MDM Deployment Templates

Reference templates for teams without a full MDM.

| Pattern | Path | OS |
|---|---|---|
| Curl install + signed object-store config | `tools/deploy/curl-install/` | macOS, Linux |
| Ansible playbook | `tools/deploy/ansible/` | macOS, Linux, limited Windows |
| Group Policy install | `tools/deploy/group-policy/` | Windows domain endpoints |

All templates verify the Reeve binary before it is made executable, place
signed custom-surface config plus `surfaces.yaml.sigstore.json` at the
system path, and schedule scans with `--require-signed-config` against the
configured signer identity.

The binary is signature-verified and fails closed. Each template downloads
the binary and its Sigstore bundle (`REEVE_BINARY_BUNDLE_URL`) to a
temporary path, runs `cosign verify-blob` against the signer identity
(`REEVE_SIGNER_IDENTITY_REGEXP`) and OIDC issuer
(`REEVE_SIGNER_ISSUER_REGEXP`), and only then installs it. If `cosign` is
missing, the binary URL is not https, or verification fails, the install
aborts non-zero and installs nothing. Same-origin checksums are not used:
an attacker who controls the binary URL cannot forge an acceptable
signature.

These templates verify the signed surface config (`--require-signed-config`);
they do not sign scan output (`--skip-sign`). Endpoint and fleet output
signing are tracked post-launch.

Validation contract: [`tools/deploy/VALIDATION.md`](VALIDATION.md).
