#!/usr/bin/env bash
#
# Reeve Phase 1 VPS validation — one-shot runner.
#
# Provisions a Hetzner VPS, downloads the signed Reeve release, signs
# surfaces.yaml via the GitHub Actions workflow, runs the validation
# playbook, and pulls evidence back to the local workstation.
#
# Leaves the VPS running so you can inspect manually if needed.
# Run ./destroy.sh when done.
#
# Prerequisites:
#   - brew install opentofu ansible gh
#   - gh auth login
#   - HCLOUD_TOKEN exported
#   - Terraform ssh_key_name points to a Hetzner-registered key your SSH agent can use
#
# Usage:
#   ./run.sh [release_tag]
# Defaults to v0.2.0 if no tag supplied.

set -euo pipefail

# Resolve script directory so this works from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

RELEASE_TAG="${1:-v0.2.0}"
INPUT_DIR="${REPO_ROOT}/private/phase1-input/${RELEASE_TAG}"
ARCHIVE="aibom-cli-x86_64-unknown-linux-gnu.tar.xz"
SIGNER_REGEX='^https://github.com/Reeve-Security/reeve/.github/workflows/sign-surface-config.yml@refs/heads/main$'

log() {
    printf '\n\033[1;36m==> %s\033[0m\n' "$*"
}

err() {
    printf '\n\033[1;31m!! %s\033[0m\n' "$*" >&2
    exit 1
}

# --- pre-flight checks ------------------------------------------------------

log "Pre-flight: checking required tools and credentials"

for cmd in tofu ansible-playbook gh; do
    command -v "$cmd" >/dev/null 2>&1 || err "missing: $cmd (install with: brew install opentofu ansible gh)"
done

[[ -n "${HCLOUD_TOKEN:-}" ]] || err "HCLOUD_TOKEN not set; export it or source ~/.zshrc"

gh auth status >/dev/null 2>&1 || err "gh CLI not authenticated; run: gh auth login"

log "Pre-flight passed"

# --- step C: download signed release ---------------------------------------

log "Downloading Reeve release ${RELEASE_TAG}"

mkdir -p "${INPUT_DIR}"

if [[ -f "${INPUT_DIR}/${ARCHIVE}" && -f "${INPUT_DIR}/${ARCHIVE}.bundle" ]]; then
    log "Release already downloaded; skipping"
else
    gh release download "${RELEASE_TAG}" \
        --repo Reeve-Security/reeve \
        --pattern "${ARCHIVE}*" \
        --dir "${INPUT_DIR}"
fi

# --- step D: author surfaces.yaml ------------------------------------------

log "Authoring surfaces.yaml"

if [[ ! -f "${INPUT_DIR}/surfaces.yaml" ]]; then
    cat > "${INPUT_DIR}/surfaces.yaml" <<'YAML'
surfaces:
  - name: phase1-custom-agent
    paths:
      - .phase1-agent/mcp.json
    format: json
    roots:
      - [mcpServers]
YAML
fi

# --- step E: trigger signing workflow --------------------------------------

log "Triggering surfaces.yaml signing workflow"

CONFIG_B64="$(base64 < "${INPUT_DIR}/surfaces.yaml" | tr -d '\n')"

gh workflow run sign-surface-config.yml \
    --repo Reeve-Security/reeve \
    -f "config_base64=${CONFIG_B64}" \
    -f artifact_name=phase1-surface-config

log "Waiting up to 5 seconds for the workflow run to register"
sleep 5

log "Watching the signing workflow until it completes"
SIGN_RUN_ID="$(gh run list --repo Reeve-Security/reeve \
    --workflow sign-surface-config.yml \
    --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run watch "${SIGN_RUN_ID}" --repo Reeve-Security/reeve --exit-status

# --- step F: download signed bundle ----------------------------------------

log "Downloading the signed surfaces.yaml bundle"

RUN_ID="$(gh run list --repo Reeve-Security/reeve \
    --workflow sign-surface-config.yml \
    --limit 1 --json databaseId --jq '.[0].databaseId')"

# gh run download places the artifact in a subdir matching the artifact name.
gh run download "${RUN_ID}" --repo Reeve-Security/reeve --dir "${INPUT_DIR}"

# Flatten the artifact subdirectory if present.
if [[ -d "${INPUT_DIR}/phase1-surface-config" ]]; then
    mv "${INPUT_DIR}/phase1-surface-config/"* "${INPUT_DIR}/" 2>/dev/null || true
    rmdir "${INPUT_DIR}/phase1-surface-config" 2>/dev/null || true
fi

[[ -f "${INPUT_DIR}/surfaces.yaml.sigstore.json" ]] || err "signature bundle missing after artifact download"

log "Inputs ready in ${INPUT_DIR}:"
ls -la "${INPUT_DIR}"

# --- step G: provision VPS via OpenTofu -----------------------------------

log "Provisioning Hetzner VPS via OpenTofu"

cd "${SCRIPT_DIR}/terraform"

if [[ ! -d .terraform ]]; then
    tofu init
fi

tofu apply -auto-approve

VPS_IP="$(tofu output -raw vps_ip)"
log "VPS provisioned at ${VPS_IP}"

# --- step H: build Ansible inventory ---------------------------------------

log "Writing Ansible inventory"

cd "${SCRIPT_DIR}/ansible"

printf '[reeve_vps]\n%s ansible_user=root\n' "${VPS_IP}" > inventory.yml

# --- step I: run validation playbook --------------------------------------

log "Running Ansible validation playbook (this is the long step)"

# Wait briefly for SSH to come up before Ansible tries to connect.
log "Waiting up to 60 seconds for SSH to become available on ${VPS_IP}"
for _ in {1..60}; do
    if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=2 \
           -o BatchMode=yes "root@${VPS_IP}" true 2>/dev/null; then
        log "SSH is up"
        break
    fi
    sleep 1
done

ansible-playbook -i inventory.yml phase1-validate.yml \
    -e "reeve_release_archive_path=${INPUT_DIR}/${ARCHIVE}" \
    -e "reeve_release_bundle_path=${INPUT_DIR}/${ARCHIVE}.bundle" \
    -e "surface_config_path=${INPUT_DIR}/surfaces.yaml" \
    -e "surface_config_bundle_path=${INPUT_DIR}/surfaces.yaml.sigstore.json" \
    -e "surface_signer_identity_regexp=${SIGNER_REGEX}"

# --- step J: report evidence -----------------------------------------------

log "Validation complete"
log "Evidence files:"
ls -la "${SCRIPT_DIR}/ansible/evidence/" || true

log "VPS still running at ${VPS_IP} so you can SSH in manually if needed:"
echo "    ssh root@${VPS_IP}"
echo
log "When you're done, tear down with:"
echo "    ${SCRIPT_DIR}/destroy.sh"
echo
log "Cost so far: ~\$0.05. Cost per month if you forget to destroy: ~€4.51."
