#!/usr/bin/env bash
#
# Hermetic test for GHSA-9cmp-5q9w-hw7r: the curl-install template must
# cryptographically verify the Reeve binary before it is made executable, and
# must FAIL CLOSED (abort non-zero, install nothing) when verification fails,
# even when the attacker controls BOTH the binary URL and the bundle URL.
#
# This test uses no network and no real cosign. It serves a tampered binary
# plus an attacker-crafted bundle from a localhost http server, and stubs
# `cosign` on PATH:
#   - negative path: stub cosign returns non-zero (verification fails on the
#     tampered artifact) -> install.sh must exit non-zero and NOT create the
#     final binary.
#   - positive path: stub cosign returns zero -> install.sh succeeds and the
#     final binary exists.
#
# Because the installer now enforces https-only on REEVE_BINARY_URL, the test
# sets the documented test-only escape hatch REEVE_ALLOW_INSECURE_URL=1 so a
# localhost http server can be used. That flag relaxes ONLY the scheme check;
# cosign verify-blob still runs and must pass, which is exactly what this test
# exercises.
#
# Exits non-zero on any assertion failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="${SCRIPT_DIR}/../install.sh"

if [[ ! -f "${INSTALL_SH}" ]]; then
  echo "FAIL: cannot find install.sh at ${INSTALL_SH}" >&2
  exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/reeve-verify-test.XXXXXX")"
SERVER_PID=""
cleanup() {
  if [[ -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK}"
}
trap cleanup EXIT

# Remote object store served over http (simulating an attacker who controls
# the binary host and the bundle host: both are served from the same dir).
REMOTE="${WORK}/remote"
mkdir -p "${REMOTE}"

# Tampered binary (attacker payload) plus an attacker-crafted bundle.
cat >"${REMOTE}/aibom-cli" <<'EOF'
#!/usr/bin/env bash
# When run as the installed binary the stub records its args and behaves like a
# minimal aibom-cli so the positive path can complete.
set -euo pipefail
printf '%s\n' "$*" >> "${REEVE_STUB_LOG:?missing REEVE_STUB_LOG}"
case "$*" in
  *"scope list"*"--require-signed-config"*"--signer-identity-regexp"*) exit 0 ;;
  *) echo "unexpected aibom-cli args: $*" >&2; exit 2 ;;
esac
EOF
chmod 0755 "${REMOTE}/aibom-cli"
printf '%s\n' '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","attacker":"crafted"}' >"${REMOTE}/aibom-cli.sigstore.json"
printf '%s\n' 'version: 1' 'surfaces: []' >"${REMOTE}/surfaces.yaml"
printf '%s\n' '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}' >"${REMOTE}/surfaces.yaml.sigstore.json"

# Start a localhost http server rooted at the remote object store.
PORT=8731
python3 -m http.server "${PORT}" --bind 127.0.0.1 --directory "${REMOTE}" >/dev/null 2>&1 &
SERVER_PID="$!"

# Wait for the server to accept connections.
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:${PORT}/aibom-cli" -o /dev/null 2>/dev/null; then
    break
  fi
  sleep 0.1
done

BASE="http://127.0.0.1:${PORT}"

run_install() {
  # $1 = path to a directory containing the `cosign` stub to put first on PATH.
  local cosign_dir="$1" root="$2" stublog="$3"
  # install.sh prepends REEVE_RUNTIME_PATH onto PATH, so the cosign stub must
  # be injected via REEVE_RUNTIME_PATH (first) to win over any real cosign on
  # the host. This keeps the test hermetic: no real cosign is invoked.
  PATH="${cosign_dir}:${PATH}" \
  REEVE_RUNTIME_PATH="${cosign_dir}:/usr/bin:/bin:/usr/sbin:/sbin" \
  REEVE_BINARY_URL="${BASE}/aibom-cli" \
  REEVE_BINARY_BUNDLE_URL="${BASE}/aibom-cli.sigstore.json" \
  REEVE_SURFACE_CONFIG_URL="${BASE}/surfaces.yaml" \
  REEVE_SURFACE_CONFIG_BUNDLE_URL="${BASE}/surfaces.yaml.sigstore.json" \
  REEVE_SIGNER_IDENTITY_REGEXP='^https://github.com/Reeve-Security/reeve/.*$' \
  REEVE_SIGNER_ISSUER_REGEXP='^https://token.actions.githubusercontent.com$' \
  REEVE_INSTALL_ROOT="${root}" \
  REEVE_SKIP_SCHEDULER="1" \
  REEVE_ALLOW_INSECURE_URL="1" \
  REEVE_STUB_LOG="${stublog}" \
    bash "${INSTALL_SH}"
}

# ---------------------------------------------------------------------------
# Negative path: cosign verification FAILS on the tampered artifact.
# ---------------------------------------------------------------------------
COSIGN_FAIL_DIR="${WORK}/cosign-fail"
mkdir -p "${COSIGN_FAIL_DIR}"
cat >"${COSIGN_FAIL_DIR}/cosign" <<'EOF'
#!/usr/bin/env bash
# Simulates cosign rejecting the tampered binary / attacker bundle.
echo "cosign: signature verification failed" >&2
exit 1
EOF
chmod 0755 "${COSIGN_FAIL_DIR}/cosign"

NEG_ROOT="${WORK}/endpoint-neg"
mkdir -p "${NEG_ROOT}"
NEG_LOG="${WORK}/neg-stub.log"
: >"${NEG_LOG}"

set +e
run_install "${COSIGN_FAIL_DIR}" "${NEG_ROOT}" "${NEG_LOG}" >/dev/null 2>&1
NEG_RC=$?
set -e

NEG_BIN="${NEG_ROOT}/usr/local/bin/aibom-cli"

if [[ "${NEG_RC}" -eq 0 ]]; then
  echo "FAIL: installer exited 0 when binary signature verification failed (should abort)" >&2
  exit 1
fi
if [[ -e "${NEG_BIN}" ]]; then
  echo "FAIL: tampered binary was installed to ${NEG_BIN} despite verification failure" >&2
  exit 1
fi
echo "PASS negative: installer aborted (rc=${NEG_RC}) and did not install the tampered binary"

# ---------------------------------------------------------------------------
# Positive path: cosign verification SUCCEEDS.
# ---------------------------------------------------------------------------
COSIGN_OK_DIR="${WORK}/cosign-ok"
mkdir -p "${COSIGN_OK_DIR}"
cat >"${COSIGN_OK_DIR}/cosign" <<'EOF'
#!/usr/bin/env bash
# Simulates cosign accepting the binary.
exit 0
EOF
chmod 0755 "${COSIGN_OK_DIR}/cosign"

POS_ROOT="${WORK}/endpoint-pos"
mkdir -p "${POS_ROOT}"
POS_LOG="${WORK}/pos-stub.log"
: >"${POS_LOG}"

set +e
run_install "${COSIGN_OK_DIR}" "${POS_ROOT}" "${POS_LOG}" >/dev/null 2>&1
POS_RC=$?
set -e

POS_BIN="${POS_ROOT}/usr/local/bin/aibom-cli"

if [[ "${POS_RC}" -ne 0 ]]; then
  echo "FAIL: installer exited ${POS_RC} when binary signature verification succeeded" >&2
  exit 1
fi
if [[ ! -e "${POS_BIN}" ]]; then
  echo "FAIL: verified binary was not installed to ${POS_BIN}" >&2
  exit 1
fi
if [[ ! -x "${POS_BIN}" ]]; then
  echo "FAIL: installed binary at ${POS_BIN} is not executable" >&2
  exit 1
fi
echo "PASS positive: verified binary installed to ${POS_BIN}"

echo "ALL TESTS PASSED"
