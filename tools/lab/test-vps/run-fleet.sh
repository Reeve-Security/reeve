#!/usr/bin/env bash
#
# Reeve disposable VPS fleet driver.
#
# Usage:
#   ./run-fleet.sh <profile-name> [release_tag]
#   ./run-fleet.sh all [release_tag]
#   ./run-fleet.sh --list
#
# Profiles live in ansible/fleet-matrix.yml. The file is JSON-compatible YAML
# so this script can parse it with Python's standard library.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
MATRIX_PATH="${SCRIPT_DIR}/ansible/fleet-matrix.yml"

PROFILE_NAME="${1:-}"
RELEASE_TAG="${2:-v0.2.1}"
INPUT_DIR="${REPO_ROOT}/private/phase1-input/${RELEASE_TAG}"
FLEET_DATE="$(date -u +%Y%m%d)"
EVIDENCE_ROOT="${REPO_ROOT}/private/fleet-${FLEET_DATE}"
ARCHIVE="aibom-cli-x86_64-unknown-linux-gnu.tar.xz"
SIGNER_REGEX='^https://github.com/Reeve-Security/reeve/.github/workflows/sign-surface-config.yml@refs/heads/main$'

log() {
    printf '\n\033[1;36m==> %s\033[0m\n' "$*"
}

err() {
    printf '\n\033[1;31m!! %s\033[0m\n' "$*" >&2
    exit 1
}

profile_json() {
    python3 - "$MATRIX_PATH" "$PROFILE_NAME" <<'PY'
import json
import pathlib
import sys

matrix = json.loads(pathlib.Path(sys.argv[1]).read_text())
name = sys.argv[2]
for profile in matrix:
    if profile["name"] == name:
        print(json.dumps(profile))
        raise SystemExit(0)
raise SystemExit(f"unknown fleet profile: {name}")
PY
}

profile_names() {
    python3 - "$MATRIX_PATH" <<'PY'
import json
import pathlib
import sys

for profile in json.loads(pathlib.Path(sys.argv[1]).read_text()):
    print(profile["name"])
PY
}

profile_field() {
    python3 - "$1" "$2" <<'PY'
import json
import sys

profile = json.loads(sys.argv[1])
field = sys.argv[2]
value = profile[field]
if isinstance(value, str):
    print(value)
else:
    print(json.dumps(value))
PY
}

destroy_vps() {
    if [[ "${KEEP_VPS:-0}" == "1" ]]; then
        log "KEEP_VPS=1 set; leaving VPS running for inspection"
        return
    fi
    log "Destroying VPS for ${PROFILE_NAME}"
    (
        cd "${SCRIPT_DIR}/terraform"
        tofu destroy -auto-approve >/dev/null
    )
}

[[ -n "${PROFILE_NAME}" ]] || err "usage: ./run-fleet.sh <profile-name>|all|--list [release_tag]"

if [[ "${PROFILE_NAME}" == "--list" ]]; then
    profile_names
    exit 0
fi

if [[ "${PROFILE_NAME}" == "all" ]]; then
    status=0
    for profile in $(profile_names); do
        if ! "${SCRIPT_DIR}/run-fleet.sh" "${profile}" "${RELEASE_TAG}"; then
            status=1
            break
        fi
    done
    exit "${status}"
fi

for cmd in tofu ansible-playbook gh python3; do
    command -v "$cmd" >/dev/null 2>&1 || err "missing: $cmd"
done

[[ -n "${HCLOUD_TOKEN:-}" ]] || err "HCLOUD_TOKEN not set"
gh auth status >/dev/null 2>&1 || err "gh CLI not authenticated; run: gh auth login"

PROFILE_JSON="$(profile_json)"
IMAGE="$(profile_field "${PROFILE_JSON}" image)"
SERVER_TYPE="$(profile_field "${PROFILE_JSON}" server_type)"
LOCATION="$(profile_field "${PROFILE_JSON}" location)"
AGENTS_JSON="$(profile_field "${PROFILE_JSON}" agents)"
EXPECTED_JSON="$(profile_field "${PROFILE_JSON}" expected_aibom)"
EVIDENCE_DIR="${EVIDENCE_ROOT}/${PROFILE_NAME}"
VARS_FILE="${EVIDENCE_DIR}/profile-vars.json"

log "Preparing input artifacts for ${RELEASE_TAG}"
mkdir -p "${INPUT_DIR}" "${EVIDENCE_DIR}"

if [[ ! -f "${INPUT_DIR}/${ARCHIVE}" || ! -f "${INPUT_DIR}/${ARCHIVE}.bundle" ]]; then
    gh release download "${RELEASE_TAG}" \
        --repo Reeve-Security/reeve \
        --pattern "${ARCHIVE}*" \
        --dir "${INPUT_DIR}"
fi

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

if [[ ! -f "${INPUT_DIR}/surfaces.yaml.sigstore.json" ]]; then
    log "Signing surfaces.yaml through GitHub Actions"
    CONFIG_B64="$(base64 < "${INPUT_DIR}/surfaces.yaml" | tr -d '\n')"
    gh workflow run sign-surface-config.yml \
        --repo Reeve-Security/reeve \
        -f "config_base64=${CONFIG_B64}" \
        -f artifact_name=phase1-surface-config
    sleep 5
    SIGN_RUN_ID="$(gh run list --repo Reeve-Security/reeve \
        --workflow sign-surface-config.yml \
        --limit 1 --json databaseId --jq '.[0].databaseId')"
    gh run watch "${SIGN_RUN_ID}" --repo Reeve-Security/reeve --exit-status
    gh run download "${SIGN_RUN_ID}" --repo Reeve-Security/reeve --dir "${INPUT_DIR}"
    if [[ -d "${INPUT_DIR}/phase1-surface-config" ]]; then
        mv "${INPUT_DIR}/phase1-surface-config/"* "${INPUT_DIR}/" 2>/dev/null || true
        rmdir "${INPUT_DIR}/phase1-surface-config" 2>/dev/null || true
    fi
fi

[[ -f "${INPUT_DIR}/surfaces.yaml.sigstore.json" ]] || err "missing signed surface config bundle"

log "Provisioning ${PROFILE_NAME}: image=${IMAGE} server_type=${SERVER_TYPE} location=${LOCATION}"
cd "${SCRIPT_DIR}/terraform"
if [[ ! -d .terraform ]]; then
    tofu init
fi
trap destroy_vps EXIT
tofu apply -auto-approve \
    -var "server_name=reeve-${PROFILE_NAME}" \
    -var "image=${IMAGE}" \
    -var "server_type=${SERVER_TYPE}" \
    -var "location=${LOCATION}"

VPS_IP="$(tofu output -raw vps_ip)"
ssh-keygen -R "${VPS_IP}" >/dev/null 2>&1 || true
log "Writing Ansible inventory for ${VPS_IP}"
cd "${SCRIPT_DIR}/ansible"
printf '[reeve_vps]\n%s ansible_user=root\n' "${VPS_IP}" > inventory.yml

log "Waiting up to 60 seconds for SSH"
for _ in {1..60}; do
    if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=2 \
           -o BatchMode=yes "root@${VPS_IP}" true 2>/dev/null; then
        break
    fi
    sleep 1
done

python3 - "${VARS_FILE}" "${PROFILE_NAME}" "${AGENTS_JSON}" "${EXPECTED_JSON}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(json.dumps({
    "profile_name": sys.argv[2],
    "profile_agents": json.loads(sys.argv[3]),
    "expected_aibom": json.loads(sys.argv[4]),
}, indent=2))
PY

log "Running fleet profile ${PROFILE_NAME}"
ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i inventory.yml fleet-profile.yml \
    -e "@${VARS_FILE}" \
    -e "reeve_release_archive_path=${INPUT_DIR}/${ARCHIVE}" \
    -e "reeve_release_bundle_path=${INPUT_DIR}/${ARCHIVE}.bundle" \
    -e "surface_config_path=${INPUT_DIR}/surfaces.yaml" \
    -e "surface_config_bundle_path=${INPUT_DIR}/surfaces.yaml.sigstore.json" \
    -e "surface_signer_identity_regexp=${SIGNER_REGEX}" \
    -e "evidence_dir=${EVIDENCE_DIR}"

SUMMARY_PATH="${EVIDENCE_ROOT}/SUMMARY.md"
if [[ ! -f "${SUMMARY_PATH}" ]]; then
    cat > "${SUMMARY_PATH}" <<'MD'
# Reeve VPS Fleet Evidence

| Profile | Image | Agents | Status | Evidence |
|---|---|---|---|---|
MD
fi
SUMMARY_ROW="$(printf '| %s | %s | %s | PASS | %s |\n' \
    "${PROFILE_NAME}" "${IMAGE}" "${AGENTS_JSON}" "${EVIDENCE_DIR}")"
TMP_SUMMARY_PATH="$(mktemp "${SUMMARY_PATH}.XXXXXX")"
awk -v profile="${PROFILE_NAME}" -v row="${SUMMARY_ROW}" '
    BEGIN { replaced = 0 }
    index($0, "| " profile " |") == 1 {
        if (!replaced) {
            print row
            replaced = 1
        }
        next
    }
    { print }
    END {
        if (!replaced) {
            print row
        }
    }
' "${SUMMARY_PATH}" > "${TMP_SUMMARY_PATH}"
mv "${TMP_SUMMARY_PATH}" "${SUMMARY_PATH}"

log "Fleet profile complete. Evidence: ${EVIDENCE_DIR}"
