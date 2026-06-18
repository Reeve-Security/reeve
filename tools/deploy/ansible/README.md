# Ansible Template

Use `reeve.yml` as a starting playbook for small fleets.

Required variables:

- `reeve_binary_url` (must be https)
- `reeve_binary_bundle_url` for the binary's `aibom-cli.sigstore.json`
- `reeve_surface_config_url`
- `reeve_surface_config_bundle_url`
- `reeve_signer_identity_regexp`
- `reeve_signer_issuer_regexp` (signer OIDC issuer regexp)

Example:

```bash
ansible-playbook -i inventory.ini tools/deploy/ansible/reeve.yml \
  -e reeve_binary_url=https://example.com/aibom-cli \
  -e reeve_binary_bundle_url=https://example.com/aibom-cli.sigstore.json \
  -e reeve_surface_config_url=https://example.com/surfaces.yaml \
  -e reeve_surface_config_bundle_url=https://example.com/surfaces.yaml.sigstore.json \
  -e 'reeve_signer_identity_regexp=^repo:mycorp/reeve-config:.*$' \
  -e 'reeve_signer_issuer_regexp=^https://token.actions.githubusercontent.com$'
```

The binary is signature-verified before it is installed. The playbook
downloads the binary and its Sigstore bundle to a temporary directory, runs
`cosign verify-blob` against the signer identity and OIDC issuer, and only
on success copies the binary into `/usr/local/bin/aibom-cli` with mode 0755.
This fails closed: if `cosign` is missing, the URL is not https, or
verification returns non-zero, the play fails and installs nothing. `cosign`
must be present on the managed host.
