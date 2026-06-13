# Phase 1 VPS validation

This lab validates issue #62 on a clean Ubuntu VPS. It proves the
deployment path, not just the binary:

- signed Reeve release archive verifies with cosign;
- signed `surfaces.yaml` verifies with Reeve;
- `tools/deploy/curl-install/install.sh` writes system paths;
- `reeve-scan.timer` is installed and enabled;
- a real scan writes an AIBOM under `/var/lib/reeve/scans`; and
- evidence is fetched back to the local workstation.

## ELI15

Phase 0 was "can Reeve run on a fresh server?"

Phase 1 is "can a customer install Reeve the way our deployment docs say,
with signed config and a daily scheduler?"

This directory is the robot for Phase 1.

## One-time founder setup

Install local tools:

```bash
brew install opentofu ansible gh
```

Create a Hetzner Cloud API token:

1. Hetzner Cloud Console.
2. Security.
3. API Tokens.
4. Generate token with read/write access.
5. Store it in your password manager.

Export it before running Terraform:

```bash
export HCLOUD_TOKEN=hcc_xxxxxxxxxxxxxxxxxxxxxx
```

Make sure Terraform's `ssh_key_name` value matches a key already registered
in Hetzner Cloud, and that your SSH agent can use the matching private key.

```bash
ssh-add -l
```

## Build the input artifacts

Download the signed release archive and bundle to a tag-scoped private local
directory:

```bash
mkdir -p private/phase1-input/v0.2.0
gh release download v0.2.0 \
  --repo Reeve-Security/reeve \
  --pattern 'aibom-cli-x86_64-unknown-linux-gnu.tar.xz*' \
  --dir private/phase1-input/v0.2.0
```

Create the surface config:

```bash
cat > private/phase1-input/v0.2.0/surfaces.yaml <<'YAML'
surfaces:
  - name: phase1-custom-agent
    paths:
      - .phase1-agent/mcp.json
    format: json
    roots:
      - [mcpServers]
YAML
```

Sign `surfaces.yaml` with GitHub Actions OIDC:

```bash
CONFIG_B64="$(base64 < private/phase1-input/v0.2.0/surfaces.yaml | tr -d '\n')"
gh workflow run sign-surface-config.yml \
  --repo Reeve-Security/reeve \
  -f config_base64="$CONFIG_B64" \
  -f artifact_name=phase1-surface-config
gh run watch --repo Reeve-Security/reeve
```

Download the workflow artifact from GitHub and place these files in
`private/phase1-input/v0.2.0/`:

- `surfaces.yaml`
- `surfaces.yaml.sigstore.json`

The signer identity regexp for this workflow is:

```text
^https://github.com/Reeve-Security/reeve/.github/workflows/sign-surface-config.yml@refs/heads/main$
```

## Run Phase 1

Recommended path:

```bash
cd tools/lab/test-vps
./run.sh v0.2.0
```

The runner downloads the release archive, signs `surfaces.yaml` through
GitHub Actions, provisions the VPS, runs Ansible, and leaves the VPS
running for inspection. Destroy it when done:

```bash
./destroy.sh
```

Manual path:

Provision the VPS:

```bash
cd tools/lab/test-vps/terraform
tofu init
tofu apply -auto-approve
```

Create Ansible inventory:

```bash
cd ../ansible
printf '[reeve_vps]\n%s ansible_user=root\n' \
  "$(cd ../terraform && tofu output -raw vps_ip)" > inventory.yml
```

Run validation:

```bash
ansible-playbook -i inventory.yml phase1-validate.yml \
  -e reeve_release_archive_path=../../../../private/phase1-input/v0.2.0/aibom-cli-x86_64-unknown-linux-gnu.tar.xz \
  -e reeve_release_bundle_path=../../../../private/phase1-input/v0.2.0/aibom-cli-x86_64-unknown-linux-gnu.tar.xz.bundle \
  -e surface_config_path=../../../../private/phase1-input/v0.2.0/surfaces.yaml \
  -e surface_config_bundle_path=../../../../private/phase1-input/v0.2.0/surfaces.yaml.sigstore.json \
  -e surface_signer_identity_regexp='^https://github.com/Reeve-Security/reeve/.github/workflows/sign-surface-config.yml@refs/heads/main$'
```

Evidence lands in `tools/lab/test-vps/ansible/evidence/`.

## Run fleet profiles

`run-fleet.sh` uses `ansible/fleet-matrix.yml` to run a named disposable
profile. It provisions one Hetzner VPS, composes the shared Ansible roles,
stores evidence under `private/fleet-<date>/<profile>/`, and destroys the VPS
unless `KEEP_VPS=1` is set.

```bash
cd tools/lab/test-vps
./run-fleet.sh --list
./run-fleet.sh empty-ubuntu-24 v0.2.1
./run-fleet.sh claude-code-approvals-ubuntu-22 v0.2.1
./run-fleet.sh all v0.2.1
```

The VPS matrix covers Linux profiles only. macOS validation uses Tart on Apple
hardware and is tracked separately in #99. The fleet driver appends pass rows
to `private/fleet-<date>/SUMMARY.md`.

Destroy the VPS:

```bash
cd ../terraform
tofu destroy -auto-approve
```

## What closes #62

Paste the Ansible recap plus evidence file list into #62. Include:

- VPS OS (`Ubuntu 24.04`);
- Reeve version;
- release archive `cosign verify-blob` success;
- `scope list --require-signed-config` success;
- `reeve-scan.timer` enabled/active;
- scan output path; and
- fetched AIBOM path.
