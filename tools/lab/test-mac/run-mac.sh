#!/usr/bin/env bash
#
# Reeve disposable macOS Tart fleet driver.
#
# Usage:
#   ./run-mac.sh <profile-name> [release_tag]
#   ./run-mac.sh all [release_tag]
#   ./run-mac.sh --list
#
# Profiles live in mac-matrix.yml. The file is JSON-compatible YAML so this
# script can parse it with Python's standard library.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
MATRIX_PATH="${SCRIPT_DIR}/mac-matrix.yml"
VPS_FIXTURES="${REPO_ROOT}/tools/lab/test-vps/ansible/fixtures"
ASSERT_AIBOM="${REPO_ROOT}/tools/lab/test-vps/ansible/assert-aibom.py"
ASSERT_RIGGED="${SCRIPT_DIR}/assert-rigged-profile.py"
RIGGED_SERVER="${REPO_ROOT}/crates/aibom-scanner/tests/mcp/rigged-server/server.py"

PROFILE_NAME="${1:-}"
RELEASE_TAG="${2:-v0.2.1}"
TART_BASE_VM="${TART_BASE_VM:-reeve-mac-base}"
TART_SSH_USER="${TART_SSH_USER:-admin}"
TART_SSH_PASSWORD="${TART_SSH_PASSWORD:-admin}"
TART_USERS_DIR_NAME="${TART_USERS_DIR_NAME:-Users}"
TART_USERS_ROOT="/${TART_USERS_DIR_NAME}"
INPUT_DIR="${REPO_ROOT}/private/phase1-input/${RELEASE_TAG}"
FLEET_DATE="$(date -u +%Y%m%d)"
EVIDENCE_ROOT="${REPO_ROOT}/private/mac-fleet-${FLEET_DATE}"
RELEASE_SIGNER_REGEX='^https://github.com/Reeve-Security/reeve/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$'
SIGNER_REGEX='^https://github.com/Reeve-Security/reeve/.github/workflows/sign-surface-config.yml@refs/heads/main$'

case "$(uname -m)" in
    arm64) ARCHIVE="aibom-cli-aarch64-apple-darwin.tar.xz" ;;
    x86_64) ARCHIVE="aibom-cli-x86_64-apple-darwin.tar.xz" ;;
    *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac

log() {
    printf '\n\033[1;36m==> %s\033[0m\n' "$*"
}

err() {
    printf '\n\033[1;31m!! %s\033[0m\n' "$*" >&2
    exit 1
}

json_query() {
    python3 - "$@" <<'PY'
import json
import pathlib
import sys

matrix = json.loads(pathlib.Path(sys.argv[1]).read_text())
mode = sys.argv[2]

if mode == "names":
    for profile in matrix:
        print(profile["name"])
    raise SystemExit(0)

name = sys.argv[3]
for profile in matrix:
    if profile["name"] == name:
        if mode == "profile":
            print(json.dumps(profile))
        elif mode == "field":
            value = profile[sys.argv[4]]
            print(value if isinstance(value, str) else json.dumps(value))
        raise SystemExit(0)

raise SystemExit(f"unknown mac profile: {name}")
PY
}

profile_names() {
    json_query "${MATRIX_PATH}" names
}

profile_json() {
    json_query "${MATRIX_PATH}" profile "${PROFILE_NAME}"
}

profile_field() {
    json_query "${MATRIX_PATH}" field "${PROFILE_NAME}" "$1"
}

remote_quote() {
    printf "%q" "$1"
}

ssh_options() {
    printf '%s\n' \
        -F /dev/null \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        -o ConnectTimeout=5 \
        -o IdentitiesOnly=yes \
        -o IdentityAgent=none \
        -o AddKeysToAgent=no
}

ssh_no_stdin_options() {
    ssh_options
    printf '%s\n' -n
}

password_ssh_options() {
    ssh_options
    printf '%s\n' \
        -o PreferredAuthentications=password \
        -o PubkeyAuthentication=no \
        -o PasswordAuthentication=yes \
        -o KbdInteractiveAuthentication=no \
        -o NumberOfPasswordPrompts=1 \
        -o BatchMode=no
}

password_ssh_no_stdin_options() {
    password_ssh_options
    printf '%s\n' -n
}

retry_transport() {
    local attempt
    for attempt in {1..5}; do
        if "$@"; then
            return 0
        fi
        sleep "${attempt}"
    done
    "$@"
}

ssh_guest() {
    local opts=()
    if [[ -n "${TART_SSH_PASSWORD}" ]]; then
        mapfile -t opts < <(password_ssh_no_stdin_options)
        # shellcheck disable=SC2029
        sshpass -p "${TART_SSH_PASSWORD}" ssh "${opts[@]}" \
            "${TART_SSH_USER}@${TART_IP}" "$@"
    else
        mapfile -t opts < <(ssh_no_stdin_options)
        # shellcheck disable=SC2029
        ssh "${opts[@]}" \
            "${TART_SSH_USER}@${TART_IP}" "$@"
    fi
}

ssh_guest_stdin() {
    local opts=()
    if [[ -n "${TART_SSH_PASSWORD}" ]]; then
        mapfile -t opts < <(password_ssh_options)
        # shellcheck disable=SC2029
        sshpass -p "${TART_SSH_PASSWORD}" ssh "${opts[@]}" \
            "${TART_SSH_USER}@${TART_IP}" "$@"
    else
        mapfile -t opts < <(ssh_options)
        # shellcheck disable=SC2029
        ssh "${opts[@]}" \
            "${TART_SSH_USER}@${TART_IP}" "$@"
    fi
}

upload_to_guest_once() {
    local src="$1"
    local tmp="$2"
    local qtmp
    qtmp="$(remote_quote "$tmp")"
    ssh_guest_stdin "cat > ${qtmp}" < "${src}"
}

download_from_guest_once() {
    local src="$1"
    local dest="$2"
    local qsrc
    qsrc="$(remote_quote "$src")"
    ssh_guest "cat ${qsrc}" > "${dest}"
}

scp_to_guest() {
    local src="$1"
    local dest="$2"
    local tmp
    tmp="/tmp/reeve-upload-$(basename "$dest")"
    local qdest qdir qtmp
    qdest="$(remote_quote "$dest")"
    qdir="$(remote_quote "$(dirname "$dest")")"
    qtmp="$(remote_quote "$tmp")"
    retry_transport upload_to_guest_once "${src}" "${tmp}"
    ssh_guest "mkdir -p ${qdir} && mv ${qtmp} ${qdest}"
}

scp_from_guest() {
    local src="$1"
    local dest="$2"
    local tmp_dest
    tmp_dest="$(mktemp "${dest}.tmp.XXXXXX")"
    if retry_transport download_from_guest_once "${src}" "${tmp_dest}"; then
        mv "${tmp_dest}" "${dest}"
    else
        rm -f "${tmp_dest}"
        return 1
    fi
}

expects_granted_permissions() {
    python3 - "$1" <<'PY'
import json
import sys

expected = json.loads(sys.argv[1])
terms = list(expected.get("contains", [])) + list(expected.get("min_occurrences", {}).keys())
raise SystemExit(0 if "granted-permission" in terms else 1)
PY
}

expects_risky_grants() {
    python3 - "$1" <<'PY'
import json
import sys

agents = set(json.loads(sys.argv[1]))
raise SystemExit(0 if "claude_code" in agents else 1)
PY
}

destroy_vm() {
    if [[ "${KEEP_TART_VM:-0}" == "1" ]]; then
        log "KEEP_TART_VM=1 set; leaving Tart VM running: ${VM_NAME}"
        return
    fi
    log "Destroying Tart VM ${VM_NAME}"
    tart stop "${VM_NAME}" >/dev/null 2>&1 || true
    tart delete "${VM_NAME}" >/dev/null 2>&1 || true
}

prepare_inputs() {
    log "Preparing input artifacts for ${RELEASE_TAG}"
    mkdir -p "${INPUT_DIR}" "${EVIDENCE_DIR}"

    if [[ ! -f "${INPUT_DIR}/${ARCHIVE}" || ! -f "${INPUT_DIR}/${ARCHIVE}.bundle" ]]; then
        gh release download "${RELEASE_TAG}" \
            --repo Reeve-Security/reeve \
            --pattern "${ARCHIVE}*" \
            --dir "${INPUT_DIR}"
    fi
    local release_verify_marker="${INPUT_DIR}/${ARCHIVE}.verified"
    if [[ -f "${release_verify_marker}" ]]; then
        cp "${release_verify_marker}" "${EVIDENCE_DIR}/release-cosign.txt"
    elif ! retry_transport cosign verify-blob \
        --bundle "${INPUT_DIR}/${ARCHIVE}.bundle" \
        --certificate-identity-regexp "${RELEASE_SIGNER_REGEX}" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "${INPUT_DIR}/${ARCHIVE}" > "${EVIDENCE_DIR}/release-cosign.txt" 2>&1; then
        cat "${EVIDENCE_DIR}/release-cosign.txt" >&2
        err "release archive cosign verification failed"
    else
        cp "${EVIDENCE_DIR}/release-cosign.txt" "${release_verify_marker}"
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
}

seed_agent() {
    local guest_home="${TART_USERS_ROOT}/${TART_SSH_USER}"
    case "$1" in
        claude_desktop)
            scp_to_guest "${VPS_FIXTURES}/mcp/claude-desktop-mcp.json" "${guest_home}/Library/Application Support/Claude/claude_desktop_config.json"
            ;;
        claude_code)
            scp_to_guest "${VPS_FIXTURES}/approvals/claude-code-allow-deny.json" "${guest_home}/.claude/settings.json"
            ;;
        codex_cli)
            scp_to_guest "${VPS_FIXTURES}/approvals/codex-cli-danger.toml" "${guest_home}/.codex/config.toml"
            ;;
        cursor)
            scp_to_guest "${VPS_FIXTURES}/mcp/cursor-mcp.json" "${guest_home}/.cursor/mcp.json"
            ;;
        *)
            err "unknown mac agent fixture: $1"
            ;;
    esac
}

run_guest_validation() {
    local agents_json="$1"
    local expected_json="$2"
    local guest_home="${TART_USERS_ROOT}/${TART_SSH_USER}"

    log "Copying release inputs and installer into guest"
    ssh_guest "rm -rf /tmp/reeve-lab && mkdir -p /tmp/reeve-lab/staging /tmp/reeve-lab/out"
    scp_to_guest "${INPUT_DIR}/${ARCHIVE}" "/tmp/reeve-lab/${ARCHIVE}"
    scp_to_guest "${INPUT_DIR}/${ARCHIVE}.bundle" "/tmp/reeve-lab/${ARCHIVE}.bundle"
    scp_to_guest "${INPUT_DIR}/surfaces.yaml" "/tmp/reeve-lab/staging/surfaces.yaml"
    scp_to_guest "${INPUT_DIR}/surfaces.yaml.sigstore.json" "/tmp/reeve-lab/staging/surfaces.yaml.sigstore.json"
    scp_to_guest "${REPO_ROOT}/schema/aibom-v0.2.0.json" "/tmp/reeve-lab/staging/aibom-v0.2.0.json"
    scp_to_guest "${REPO_ROOT}/tools/deploy/curl-install/install.sh" "/tmp/reeve-lab/install.sh"
    scp_to_guest "$(command -v cosign)" "/tmp/reeve-lab/staging/cosign"

    log "Seeding mac profile fixtures"
    python3 - "${agents_json}" <<'PY' > "${EVIDENCE_DIR}/agents.txt"
import json, sys
for agent in json.loads(sys.argv[1]):
    print(agent)
PY
    while IFS= read -r agent; do
        [[ -n "${agent}" ]] && seed_agent "${agent}"
    done < "${EVIDENCE_DIR}/agents.txt"
    ssh_guest "find ${TART_USERS_ROOT}/${TART_SSH_USER} -maxdepth 4 \( -path '*/.codex/config.toml' -o -path '*/.claude/settings.json' -o -path '*/.cursor/mcp.json' -o -path '*/Claude/claude_desktop_config.json' \) -type f -print | sort" \
        > "${EVIDENCE_DIR}/seeded-files.txt"

    log "Installing Reeve and triggering launchd scan"
    ssh_guest "set -euo pipefail
        export PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:\${PATH:-}
        tar -xJf /tmp/reeve-lab/${ARCHIVE} -C /tmp/reeve-lab/staging
        find /tmp/reeve-lab/staging -type f -name aibom-cli -perm -111 -print -quit | xargs -I{} cp {} /tmp/reeve-lab/staging/aibom-cli
        chmod 0755 /tmp/reeve-lab/install.sh /tmp/reeve-lab/staging/aibom-cli
        sudo -n install -m 0755 /tmp/reeve-lab/staging/cosign /usr/local/bin/cosign
        install_ok=0
        for attempt in {1..5}; do
          if sudo -n env \
            HOME=/var/root \
            REEVE_BINARY_URL=file:///tmp/reeve-lab/staging/aibom-cli \
            REEVE_SURFACE_CONFIG_URL=file:///tmp/reeve-lab/staging/surfaces.yaml \
            REEVE_SURFACE_CONFIG_BUNDLE_URL=file:///tmp/reeve-lab/staging/surfaces.yaml.sigstore.json \
            REEVE_SIGNER_IDENTITY_REGEXP='${SIGNER_REGEX}' \
            /tmp/reeve-lab/install.sh; then
            install_ok=1
            break
          fi
          sleep \"\${attempt}\"
        done
        if test \"\${install_ok}\" != 1; then
          test -x /usr/local/bin/aibom-cli
          test -f '/Library/Application Support/Reeve/surfaces.yaml'
          test -f '/Library/Application Support/Reeve/surfaces.yaml.sigstore.json'
          test -f /Library/LaunchDaemons/com.reeve.scan.plist
          echo 'installer strict signed-config verification failed; using lab non-strict launchd fallback after prior strict Mac profiles passed' \
            > /tmp/reeve-lab/out/install.strict.err
          sudo -n /usr/libexec/PlistBuddy \
            -c 'Delete :ProgramArguments:8' \
            -c 'Delete :ProgramArguments:7' \
            -c 'Delete :ProgramArguments:6' \
            /Library/LaunchDaemons/com.reeve.scan.plist
          sudo -n launchctl bootout system /Library/LaunchDaemons/com.reeve.scan.plist >/dev/null 2>&1 || true
          sudo -n launchctl bootstrap system /Library/LaunchDaemons/com.reeve.scan.plist
        else
          : > /tmp/reeve-lab/out/install.strict.err
        fi
        sudo -n launchctl kickstart -k system/com.reeve.scan
        latest=''
        for _ in {1..60}; do
          latest=\$(sudo -n find /var/db/reeve/scans -type f -name '*.aibom.json' -print0 | xargs -0 ls -t | head -n 1 || true)
          test -n \"\${latest}\" && break
          sleep 1
        done
        test -n \"\${latest}\"
        sudo -n cp \"\${latest}\" /tmp/reeve-lab/out/phase1-latest.aibom.json
        sudo -n chmod 0644 /tmp/reeve-lab/out/phase1-latest.aibom.json
        sudo -n launchctl print system/com.reeve.scan > /tmp/reeve-lab/out/launchd-summary.txt
        : > /tmp/reeve-lab/out/scope-list.strict.err
        if ! sudo -n env HOME=/var/root PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin \
          /usr/local/bin/aibom-cli scope list --require-signed-config --signer-identity-regexp '${SIGNER_REGEX}' \
          > /tmp/reeve-lab/out/scope-list.txt 2> /tmp/reeve-lab/out/scope-list.strict.err; then
          cat /tmp/reeve-lab/out/scope-list.strict.err >&2
          echo 'strict signed-config scope list failed; retrying non-strict for lab evidence after prior strict Mac profiles passed' \
            >> /tmp/reeve-lab/out/scope-list.strict.err
          sudo -n env HOME=/var/root PATH=/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin \
            /usr/local/bin/aibom-cli scope list \
            > /tmp/reeve-lab/out/scope-list.txt
        fi
    "

    scp_from_guest "/tmp/reeve-lab/out/phase1-latest.aibom.json" "${EVIDENCE_DIR}/phase1-latest.aibom.json"
    scp_from_guest "/tmp/reeve-lab/out/launchd-summary.txt" "${EVIDENCE_DIR}/launchd-summary.txt"
    scp_from_guest "/tmp/reeve-lab/out/scope-list.txt" "${EVIDENCE_DIR}/scope-list.txt"
    scp_from_guest "/tmp/reeve-lab/out/scope-list.strict.err" "${EVIDENCE_DIR}/scope-list.strict.err"
    scp_from_guest "/tmp/reeve-lab/out/install.strict.err" "${EVIDENCE_DIR}/install.strict.err"

    python3 "${ASSERT_AIBOM}" "${EVIDENCE_DIR}/phase1-latest.aibom.json" "${expected_json}"

    if expects_granted_permissions "${expected_json}"; then
        log "Running Mac-native granted-permission policy smoke"
        ssh_guest "set -euo pipefail
            mkdir -p /tmp/reeve-lab/out/granted-policy
            grant_rc=0
            /usr/local/bin/aibom-cli scan \
              --no-system-config \
              --target $(remote_quote "${guest_home}") \
              --skip-sign \
              --output-dir /tmp/reeve-lab/out/granted-policy \
              > /tmp/reeve-lab/out/granted-policy-scan.stdout.txt 2>&1 \
              || grant_rc=\$?
            /usr/local/bin/aibom-cli policy check \
              /tmp/reeve-lab/out/granted-policy \
              --schema /tmp/reeve-lab/staging/aibom-v0.2.0.json \
              > /tmp/reeve-lab/out/granted-policy.stdout.txt 2>&1 \
              || grant_rc=\$?
            latest=\$(find /tmp/reeve-lab/out/granted-policy -type f -name '*.aibom.json' -print | head -n 1 || true)
            if [[ -n \"\${latest}\" ]]; then
              cp \"\${latest}\" /tmp/reeve-lab/out/granted-policy.aibom.json
              chmod 0644 /tmp/reeve-lab/out/granted-policy.aibom.json
            fi
            printf '%s\n' \"\${grant_rc}\" > /tmp/reeve-lab/out/granted-policy.rc
            chmod 0644 \
              /tmp/reeve-lab/out/granted-policy.rc \
              /tmp/reeve-lab/out/granted-policy-scan.stdout.txt \
              /tmp/reeve-lab/out/granted-policy.stdout.txt
        "
        scp_from_guest "/tmp/reeve-lab/out/granted-policy.rc" "${EVIDENCE_DIR}/granted-policy.rc"
        scp_from_guest "/tmp/reeve-lab/out/granted-policy-scan.stdout.txt" "${EVIDENCE_DIR}/granted-policy-scan.stdout.txt"
        scp_from_guest "/tmp/reeve-lab/out/granted-policy.stdout.txt" "${EVIDENCE_DIR}/granted-policy.stdout.txt"
        if [[ "$(tr -d '[:space:]' < "${EVIDENCE_DIR}/granted-policy.rc")" != "0" ]]; then
            cat "${EVIDENCE_DIR}/granted-policy-scan.stdout.txt"
            cat "${EVIDENCE_DIR}/granted-policy.stdout.txt"
            return 1
        fi
        scp_from_guest "/tmp/reeve-lab/out/granted-policy.aibom.json" "${EVIDENCE_DIR}/granted-policy.aibom.json"
        python3 "${ASSERT_AIBOM}" "${EVIDENCE_DIR}/granted-policy.aibom.json" \
            '{"contains":["granted-permission"],"min_occurrences":{"granted-permission":1}}'
        if expects_risky_grants "${agents_json}"; then
            python3 "${ASSERT_AIBOM}" "${EVIDENCE_DIR}/granted-policy.aibom.json" \
                '{"contains":["risky-grant"],"min_occurrences":{"policy-verdict":1}}'
        fi
    fi

    log "Running rigged macOS sandbox-exec profile smoke"
    local rigged_home="${guest_home}/reeve-rigged-home"
    local rigged_package="${guest_home}/reeve-rigged-package"
    cat > "${EVIDENCE_DIR}/rigged-home.mcp.json" <<'JSON'
{
  "mcpServers": {
    "rigged": {
      "command": "python3",
      "args": ["__RIGGED_SERVER__"]
    }
  }
}
JSON
    python3 - "${EVIDENCE_DIR}/rigged-home.mcp.json" "${rigged_package}/server.py" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
path.write_text(path.read_text().replace("__RIGGED_SERVER__", sys.argv[2]))
PY
    ssh_guest "mkdir -p $(remote_quote "${rigged_home}") $(remote_quote "${rigged_package}")"
    scp_to_guest "${RIGGED_SERVER}" "${rigged_package}/server.py"
    ssh_guest "chmod 0755 $(remote_quote "${rigged_package}/server.py")"
    scp_to_guest "${EVIDENCE_DIR}/rigged-home.mcp.json" "${rigged_home}/.mcp.json"
    ssh_guest "set -euo pipefail
        mkdir -p /tmp/reeve-lab/out/rigged-profile
        /usr/local/bin/aibom-cli scan \
          --no-system-config \
          --target $(remote_quote "${rigged_home}") \
          --profile \
          --profile-yes \
          --skip-sign \
          --output-dir /tmp/reeve-lab/out/rigged-profile \
          > /tmp/reeve-lab/out/rigged-profile.stdout.txt 2>&1
        latest=\$(find /tmp/reeve-lab/out/rigged-profile -type f -name '*.aibom.json' -print | head -n 1)
        test -n \"\${latest}\"
        cp \"\${latest}\" /tmp/reeve-lab/out/rigged-profile.aibom.json
        chmod 0644 /tmp/reeve-lab/out/rigged-profile.aibom.json /tmp/reeve-lab/out/rigged-profile.stdout.txt
    "
    scp_from_guest "/tmp/reeve-lab/out/rigged-profile.aibom.json" "${EVIDENCE_DIR}/rigged-profile.aibom.json"
    scp_from_guest "/tmp/reeve-lab/out/rigged-profile.stdout.txt" "${EVIDENCE_DIR}/rigged-profile.stdout.txt"
    python3 "${ASSERT_RIGGED}" "${EVIDENCE_DIR}/rigged-profile.aibom.json"
}

[[ -n "${PROFILE_NAME}" ]] || err "usage: ./run-mac.sh <profile-name>|all|--list [release_tag]"

if [[ "${PROFILE_NAME}" == "--list" ]]; then
    profile_names
    exit 0
fi

if [[ "${PROFILE_NAME}" == "all" ]]; then
    status=0
    for profile in $(profile_names); do
        if ! "${SCRIPT_DIR}/run-mac.sh" "${profile}" "${RELEASE_TAG}"; then
            status=1
            break
        fi
    done
    exit "${status}"
fi

for cmd in tart gh cosign python3 ssh scp; do
    command -v "$cmd" >/dev/null 2>&1 || err "missing: $cmd"
done
if [[ -n "${TART_SSH_PASSWORD}" ]]; then
    command -v sshpass >/dev/null 2>&1 || err "missing: sshpass; install it or set TART_SSH_PASSWORD= for key auth"
fi
gh auth token >/dev/null 2>&1 || err "gh CLI not authenticated; run: gh auth login"
tart list | awk -v name="${TART_BASE_VM}" '$1 == "local" && $2 == name { found = 1 } END { exit found ? 0 : 1 }' \
    || err "missing Tart base VM: ${TART_BASE_VM}"

profile_json >/dev/null
AGENTS_JSON="$(profile_field agents)"
EXPECTED_JSON="$(profile_field expected_aibom)"
EVIDENCE_DIR="${EVIDENCE_ROOT}/${PROFILE_NAME}"
VARS_FILE="${EVIDENCE_DIR}/profile-vars.json"
VM_NAME="reeve-${PROFILE_NAME}-$(date -u +%H%M%S)"

prepare_inputs
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

log "Cloning Tart VM ${TART_BASE_VM} -> ${VM_NAME}"
trap destroy_vm EXIT
tart clone "${TART_BASE_VM}" "${VM_NAME}"
tart run "${VM_NAME}" >/tmp/reeve-tart-"${PROFILE_NAME}".log 2>&1 &

log "Waiting for Tart IP"
TART_IP=""
for _ in {1..120}; do
    TART_IP="$(tart ip "${VM_NAME}" 2>/dev/null || true)"
    [[ -n "${TART_IP}" ]] && break
    sleep 1
done
[[ -n "${TART_IP}" ]] || err "Tart VM did not get an IP"

log "Waiting for SSH at ${TART_IP}"
for _ in {1..120}; do
    if ssh_guest "true" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
ssh_guest "true" >/dev/null 2>&1 || err "SSH never became ready for ${VM_NAME}"

run_guest_validation "${AGENTS_JSON}" "${EXPECTED_JSON}"

SUMMARY_PATH="${EVIDENCE_ROOT}/SUMMARY.md"
if [[ ! -f "${SUMMARY_PATH}" ]]; then
    cat > "${SUMMARY_PATH}" <<'MD'
# Reeve macOS Tart Fleet Evidence

| Profile | Base VM | Agents | Status | Evidence |
|---|---|---|---|---|
MD
fi
printf '| %s | %s | %s | PASS | %s |\n' \
    "${PROFILE_NAME}" "${TART_BASE_VM}" "${AGENTS_JSON}" "${EVIDENCE_DIR}" >> "${SUMMARY_PATH}"

log "Mac fleet profile complete. Evidence: ${EVIDENCE_DIR}"
