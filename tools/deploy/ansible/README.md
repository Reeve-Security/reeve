# Ansible Template

Use `reeve.yml` as a starting playbook for small fleets.

Required variables:

- `reeve_binary_url`
- `reeve_surface_config_url`
- `reeve_surface_config_bundle_url`
- `reeve_signer_identity_regexp`

Example:

```bash
ansible-playbook -i inventory.ini tools/deploy/ansible/reeve.yml \
  -e reeve_binary_url=https://example.com/aibom-cli \
  -e reeve_surface_config_url=https://example.com/surfaces.yaml \
  -e reeve_surface_config_bundle_url=https://example.com/surfaces.yaml.sigstore.json \
  -e 'reeve_signer_identity_regexp=^repo:mycorp/reeve-config:.*$'
```
