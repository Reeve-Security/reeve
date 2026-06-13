#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${REEVE_DEMO_OUT:-${ROOT}/target/reeve-demo}"
SCAN_TARGET="${OUT}/target"
SCAN_OUT="${OUT}/scan"
DELTA_OUT="${OUT}/declared-observed-delta"
FIXTURE_ROOT="${ROOT}/demo/fixtures/default"
DELTA_FIXTURE="${ROOT}/schema/examples/fixtures/positive/03-undeclared-egress-delta"

log() { printf '\n==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

case "${OUT}" in
  "${ROOT}/target/"*|/tmp/reeve-demo*) ;;
  *) fail "refusing to write demo output outside repo target/ or /tmp: ${OUT}" ;;
esac

require_cmd python3

AIBOM_BIN="${REEVE_AIBOM_BIN:-}"
if [ -z "${AIBOM_BIN}" ]; then
  require_cmd cargo
  log "building aibom-cli"
  (cd "${ROOT}" && cargo build --quiet -p aibom-cli)
  AIBOM_BIN="${ROOT}/target/debug/aibom-cli"
fi
[ -x "${AIBOM_BIN}" ] || fail "aibom-cli not executable: ${AIBOM_BIN}"

log "preparing fixture target"
rm -rf "${OUT}"
mkdir -p \
  "${SCAN_TARGET}/.claude" \
  "${SCAN_TARGET}/.codex" \
  "${SCAN_TARGET}/.cursor" \
  "${SCAN_OUT}" \
  "${DELTA_OUT}"
cp "${FIXTURE_ROOT}/claude/settings.json" "${SCAN_TARGET}/.claude/settings.json"
cp "${FIXTURE_ROOT}/codex/config.toml" "${SCAN_TARGET}/.codex/config.toml"
cp "${FIXTURE_ROOT}/cursor/mcp.json" "${SCAN_TARGET}/.cursor/mcp.json"

export REEVE_SIGN_MODE=fixture
export REEVE_COSIGN_BIN="/nonexistent/reeve-demo-cosign"

log "scanning fixture target with policies"
"${AIBOM_BIN}" scan \
  --target "${SCAN_TARGET}" \
  --output-dir "${SCAN_OUT}" \
  --sign-mode fixture \
  --policy-check \
  --no-profile \
  --no-system-config \
  | tee "${OUT}/scan.stdout"

CDX_PATH="$(ls "${SCAN_OUT}"/*.cdx.json)"
AIBOM_PATH="$(ls "${SCAN_OUT}"/*.aibom.json)"
BUNDLE_PATH="$(ls "${SCAN_OUT}"/*.sigstore.fixture.json)"

log "validating generated artifacts"
"${AIBOM_BIN}" validate-artifacts \
  --cdx "${CDX_PATH}" \
  --aibom "${AIBOM_PATH}" \
  --bundle "${BUNDLE_PATH}" \
  | tee "${OUT}/validate-artifacts.stdout"

log "verifying fixture bundle structure"
"${AIBOM_BIN}" verify "${SCAN_OUT}" | tee "${OUT}/verify.stdout"

log "checking declared-vs-observed policy fixture"
cp "${DELTA_FIXTURE}"/*.cdx.json "${DELTA_OUT}/"
cp "${DELTA_FIXTURE}"/*.aibom.json "${DELTA_OUT}/"
cp "${DELTA_FIXTURE}"/*.sigstore.fixture.json "${DELTA_OUT}/"
"${AIBOM_BIN}" policy check "${DELTA_OUT}" | tee "${OUT}/delta-policy.stdout"
DELTA_AIBOM="$(ls "${DELTA_OUT}"/*.aibom.json)"

log "summary"
python3 - "${AIBOM_PATH}" "${DELTA_AIBOM}" <<'PY'
import json
import sys

scan = json.load(open(sys.argv[1]))
delta = json.load(open(sys.argv[2]))

def root(doc):
    return doc.get("aibom", {})

def cap_key(cap):
    return (
        cap.get("id", ""),
        json.dumps(cap.get("qualifiers", {}), sort_keys=True, separators=(",", ":")),
    )

def fmt_cap(cap):
    qualifiers = cap.get("qualifiers") or {}
    if qualifiers:
        q = ", ".join(f"{k}={v}" for k, v in sorted(qualifiers.items()))
        return f"{cap.get('id')}({q})"
    return str(cap.get("id"))

scan_root = root(scan)
components = scan_root.get("components", [])
print(f"scan.components={len(components)}")
for component in components:
    caps = component.get("capabilities", {})
    declared = caps.get("declared") or []
    observed = caps.get("observed") or []
    granted = caps.get("granted") or []
    print(
        f"- {component.get('bom-ref')}: "
        f"declared={len(declared)} observed={len(observed)} granted={len(granted)}"
    )
    for grant in granted[:4]:
        print(f"  grant={fmt_cap(grant)}")

verdicts = scan_root.get("policyVerdicts") or []
if verdicts:
    print("scan.policyVerdicts:")
    for verdict in verdicts:
        status = str(verdict.get("status", "")).upper()
        policy = verdict.get("policyId", "")
        message = verdict.get("message") or verdict.get("justification") or ""
        print(f"- {status} {policy} {message}".rstrip())

print("declaredObservedDelta:")
for component in root(delta).get("components", []):
    caps = component.get("capabilities", {})
    declared = {cap_key(cap): cap for cap in caps.get("declared") or []}
    observed = {cap_key(cap): cap for cap in caps.get("observed") or []}
    for key in sorted(observed.keys() - declared.keys()):
        print(f"- observed-only {component.get('bom-ref')}: {fmt_cap(observed[key])}")

delta_verdicts = root(delta).get("policyVerdicts") or []
if delta_verdicts:
    print("delta.policyVerdicts:")
    for verdict in delta_verdicts:
        status = str(verdict.get("status", "")).upper()
        policy = verdict.get("policyId", "")
        message = verdict.get("message") or verdict.get("justification") or ""
        print(f"- {status} {policy} {message}".rstrip())
PY

log "done: ${OUT}"
