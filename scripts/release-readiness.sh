#!/usr/bin/env bash
#
# scripts/release-readiness.sh
#
# Reproducible v0.1 release-readiness runner.
#
# Exercises the public CLI surface that the release pipeline depends on:
#   1. fixture-mode scan against the committed CLI scan target
#   2. verify on the generated scan directory
#   3. validate-artifacts on the scan triplet
#   4. validate the contract-test fixture set
#   5. policy check on a fixture with a known DENY verdict
#
# All steps run with --sign-mode fixture so the runner has no network or
# cosign dependency. Live Sigstore/Rekor acceptance is a separate release gate.
#
# Invariants asserted here match the "expected outputs" recorded in
# scripts/release-readiness.expected.txt. Update both together when the
# output shape intentionally changes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXPECTED_FILE="${REPO_ROOT}/scripts/release-readiness.expected.txt"
SCHEMA="${REPO_ROOT}/schema/aibom-v0.1.0.json"
FIXTURES_DIR="${REPO_ROOT}/schema/fixtures/aibom-v0.1.0"
SCAN_TARGET="${REPO_ROOT}/crates/aibom-cli/tests/data/cli-scan-target"
POLICY_FIXTURE="${FIXTURES_DIR}/positive/03-undeclared-egress-delta"

WORK_DIR="$(mktemp -d -t reeve-readiness-XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

log() { printf '==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}
require_opa() {
  if [ -n "${OPA_BIN:-}" ]; then
    [ -x "${OPA_BIN}" ] || fail "OPA_BIN is set but not executable: ${OPA_BIN}"
    return
  fi
  require_cmd opa
}

require_cmd python3

AIBOM_BIN="${REEVE_AIBOM_BIN:-}"
if [ -z "${AIBOM_BIN}" ]; then
  require_cmd cargo
  require_opa
  log "building aibom-cli (release profile)"
  ( cd "${REPO_ROOT}" && cargo build --release -p aibom-cli --quiet )
  AIBOM_BIN="${REPO_ROOT}/target/release/aibom-cli"
fi
[ -x "${AIBOM_BIN}" ] || fail "aibom-cli binary not executable: ${AIBOM_BIN}"

# Force fixture mode regardless of ambient env. This runner is the
# deterministic demo/readiness gate, not the live-signing gate.
export REEVE_SIGN_MODE=fixture
# Make sure an accidental live cosign on PATH can never be invoked by the
# readiness runner.
export REEVE_COSIGN_BIN="/nonexistent/reeve-readiness-cosign"

SCAN_OUT="${WORK_DIR}/scan"
mkdir -p "${SCAN_OUT}"

log "step 1/5: scan ${SCAN_TARGET} --sign-mode fixture"
"${AIBOM_BIN}" scan \
  --target "${SCAN_TARGET}" \
  --output-dir "${SCAN_OUT}" \
  --sign-mode fixture \
  > "${WORK_DIR}/scan.stdout"

CDX_PATH="$(ls "${SCAN_OUT}"/*.cdx.json)"
AIBOM_PATH="$(ls "${SCAN_OUT}"/*.aibom.json)"
BUNDLE_PATH="$(ls "${SCAN_OUT}"/*.sigstore.fixture.json)"

[ -f "${CDX_PATH}" ] || fail "scan did not produce a CycloneDX document"
[ -f "${AIBOM_PATH}" ] || fail "scan did not produce an AIBOM sidecar"
[ -f "${BUNDLE_PATH}" ] || fail "scan did not produce a fixture Sigstore bundle"

# Invariants: two MCP providers (fixture-true, fixture-cat), schemaVersion
# 0.1.0, bundle carries the fixture marker.
python3 - "$CDX_PATH" "$AIBOM_PATH" "$BUNDLE_PATH" <<'PY'
import json, sys
cdx = json.load(open(sys.argv[1]))
aibom = json.load(open(sys.argv[2]))
bundle = json.load(open(sys.argv[3]))
assert cdx.get("bomFormat") == "CycloneDX", cdx.get("bomFormat")
assert len(cdx.get("components", [])) == 2, len(cdx.get("components", []))
assert aibom["aibom"]["schemaVersion"] == "0.1.0", aibom["aibom"]["schemaVersion"]
assert len(aibom["aibom"]["components"]) == 2, len(aibom["aibom"]["components"])
assert "_fixture_note" in bundle["verificationMaterial"], list(bundle["verificationMaterial"].keys())
cdx_names = sorted(c["name"] for c in cdx["components"])
assert cdx_names == ["cat", "true"], cdx_names
bom_refs = sorted(c["bom-ref"] for c in aibom["aibom"]["components"])
assert bom_refs == ["pkg:npm/cat", "pkg:npm/true"], bom_refs
print("scan-invariants ok")
PY

log "step 2/5: verify generated scan directory"
"${AIBOM_BIN}" verify "${SCAN_OUT}" --schema "${SCHEMA}" \
  | tee "${WORK_DIR}/verify.stdout" \
  | grep -q "^PASS artifacts$" \
  || fail "verify did not emit PASS"

log "step 3/5: validate-artifacts on scan triplet"
"${AIBOM_BIN}" validate-artifacts \
  --cdx "${CDX_PATH}" \
  --aibom "${AIBOM_PATH}" \
  --bundle "${BUNDLE_PATH}" \
  --schema "${SCHEMA}" \
  | tee "${WORK_DIR}/validate-artifacts.stdout" \
  | grep -q "^PASS artifacts$" \
  || fail "validate-artifacts did not emit PASS"

log "step 4/5: validate fixture set (${FIXTURES_DIR})"
EXPECTED_FIXTURE_COUNT="$(
  find "${FIXTURES_DIR}" -mindepth 3 -maxdepth 3 -name manifest.json -type f | wc -l | tr -d ' '
)"
[ "${EXPECTED_FIXTURE_COUNT}" -gt 0 ] \
  || fail "fixture set is empty or path is wrong: ${FIXTURES_DIR}"
"${AIBOM_BIN}" validate "${FIXTURES_DIR}" --schema "${SCHEMA}" \
  | tee "${WORK_DIR}/validate-fixtures.stdout" \
  | grep -q "^${EXPECTED_FIXTURE_COUNT} fixtures checked, 0 failures$" \
  || fail "fixture set did not report ${EXPECTED_FIXTURE_COUNT} fixtures / 0 failures"

log "step 5/5: policy check on 03-undeclared-egress-delta (expect DENY)"
POLICY_OUT="${WORK_DIR}/policy"
mkdir -p "${POLICY_OUT}"
cp "${POLICY_FIXTURE}"/*.cdx.json "${POLICY_OUT}/"
cp "${POLICY_FIXTURE}"/*.aibom.json "${POLICY_OUT}/"
cp "${POLICY_FIXTURE}"/*.sigstore.fixture.json "${POLICY_OUT}/"

"${AIBOM_BIN}" policy check "${POLICY_OUT}" --schema "${SCHEMA}" \
  | tee "${WORK_DIR}/policy.stdout" \
  | grep -q "^DENY declared-observed-capability-match " \
  || fail "policy check did not emit expected DENY on fixture 03"

# Re-validate the rewritten policy triplet: policy check mutates the
# sidecar in place and must leave the triplet schema-valid and
# cryptographically self-consistent (bundle digests updated).
POLICY_CDX="$(ls "${POLICY_OUT}"/*.cdx.json)"
POLICY_AIBOM="$(ls "${POLICY_OUT}"/*.aibom.json)"
POLICY_BUNDLE="$(ls "${POLICY_OUT}"/*.sigstore.fixture.json)"
"${AIBOM_BIN}" validate-artifacts \
  --cdx "${POLICY_CDX}" \
  --aibom "${POLICY_AIBOM}" \
  --bundle "${POLICY_BUNDLE}" \
  --schema "${SCHEMA}" \
  > "${WORK_DIR}/policy-revalidate.stdout"
grep -q "^PASS artifacts$" "${WORK_DIR}/policy-revalidate.stdout" \
  || fail "post-policy-check validate-artifacts did not emit PASS"

# Compose a deterministic summary (no scanIds, no timestamps) and diff it
# against the committed expected snapshot.
SUMMARY="${WORK_DIR}/summary.txt"
python3 - "$CDX_PATH" "$AIBOM_PATH" "$POLICY_AIBOM" > "${SUMMARY}" <<'PY'
import json, sys
cdx = json.load(open(sys.argv[1]))
aibom = json.load(open(sys.argv[2]))
policy = json.load(open(sys.argv[3]))
cdx_names = sorted(c["name"] for c in cdx["components"])
bom_refs = sorted(c["bom-ref"] for c in aibom["aibom"]["components"])
verdicts = sorted(
    (v["policyId"], v["status"]) for v in policy["aibom"]["policyVerdicts"]
)
print("aibom.schemaVersion=" + aibom["aibom"]["schemaVersion"])
print("aibom.componentCount=" + str(len(aibom["aibom"]["components"])))
print("aibom.bomRefs=" + ",".join(bom_refs))
print("cdx.componentNames=" + ",".join(cdx_names))
for pid, status in verdicts:
    print(f"policy.verdict={pid}:{status}")
PY

if [ ! -f "${EXPECTED_FILE}" ]; then
  fail "expected snapshot missing: ${EXPECTED_FILE}"
fi

if ! diff -u "${EXPECTED_FILE}" "${SUMMARY}"; then
  fail "release-readiness summary does not match ${EXPECTED_FILE}"
fi

log "release-readiness OK"
