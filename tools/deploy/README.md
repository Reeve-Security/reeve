# Reeve No-MDM Deployment Templates

Reference templates for teams without a full MDM.

| Pattern | Path | OS |
|---|---|---|
| Curl install + signed object-store config | `tools/deploy/curl-install/` | macOS, Linux |
| Ansible playbook | `tools/deploy/ansible/` | macOS, Linux, limited Windows |
| Group Policy install | `tools/deploy/group-policy/` | Windows domain endpoints |

All templates install Reeve, place signed custom-surface config plus
`surfaces.yaml.sigstore.json` at the system path, and schedule scans
with `--require-signed-config` against the configured signer identity.

These templates verify the signed surface config (`--require-signed-config`);
they do not sign scan output (`--skip-sign`). Endpoint and fleet output
signing are tracked post-launch.

Validation contract: [`tools/deploy/VALIDATION.md`](VALIDATION.md).
