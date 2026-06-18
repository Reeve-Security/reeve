#!/usr/bin/env bash
#
# Reeve release gate: verify-only check that a specific main commit is safe to
# tag and publish as vX.Y.Z. It does NOT rerun the full local merge gate by
# default; main CI already proved this SHA, so it consumes that proof remotely.
# It never creates a tag; on success it prints the exact tag command for a human.
#
# usage:
#   scripts/release-gate.sh <X.Y.Z>            verify release readiness (default)
#   scripts/release-gate.sh <X.Y.Z> --local    also re-run scripts/merge-gate.sh locally
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

VERSION="${1:-}"
LOCAL=0
shift || true
while [ $# -gt 0 ]; do
  case "$1" in
    --local) LOCAL=1; shift ;;
    *) echo "release-gate: unknown argument: $1" >&2; exit 2 ;;
  esac
done

if ! printf '%s' "${VERSION}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "usage: release-gate.sh <X.Y.Z> [--local]" >&2
  exit 2
fi

TAG="v${VERSION}"
REQUIRED_CHECKS=("check (ubuntu)" "check (macos)" "windows release smoke" "gitleaks")

fail() { echo ""; echo "release-gate: FAIL: $*" >&2; exit 1; }
step() { echo ""; echo "==> $1"; }

step "optional: local merge gate"
if [ "${LOCAL}" -eq 1 ]; then
  bash scripts/merge-gate.sh || fail "local merge gate failed"
else
  echo "    skipped (default); main CI is the proof, see below"
fi

step "on main, clean working tree, synced with origin/main"
branch="$(git rev-parse --abbrev-ref HEAD)"
[ "${branch}" = "main" ] || fail "not on main (on ${branch})"
[ -z "$(git status --porcelain)" ] || fail "working tree not clean"
git fetch origin main --quiet
local_head="$(git rev-parse HEAD)"
remote_head="$(git rev-parse origin/main)"
[ "${local_head}" = "${remote_head}" ] || fail "local main ${local_head} != origin/main ${remote_head}; sync first"
echo "    ok: ${local_head}"

step "version matches Cargo.toml workspace version"
cargo_version="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
[ "${cargo_version}" = "${VERSION}" ] || fail "requested ${VERSION} != Cargo.toml ${cargo_version}"
echo "    ok: ${VERSION}"

step "tag ${TAG} does not already exist (local + remote)"
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  fail "tag ${TAG} already exists locally"
fi
if git ls-remote --tags origin "${TAG}" | grep -q "refs/tags/${TAG}"; then
  fail "tag ${TAG} already exists on remote"
fi
echo "    ok: ${TAG} is free"

step "Cargo.lock pins workspace crates to ${VERSION}"
for crate in aibom-core aibom-cli aibom-scanner aibom-signer aibom-validator aibom-policy; do
  locked="$(awk -v c="\"${crate}\"" '
    $1=="name" && $3==c {found=1; next}
    found && $1=="version" {gsub(/"/,"",$3); print $3; exit}
  ' Cargo.lock)"
  [ "${locked}" = "${VERSION}" ] || fail "Cargo.lock ${crate} pinned at '${locked}', expected ${VERSION} (run cargo build)"
done
echo "    ok: all workspace crates at ${VERSION}"

step "policy bundle exists for ${VERSION} and reproduces"
for ext in wasm json provenance.json; do
  f="crates/aibom-policy/bundles/${VERSION}.${ext}"
  [ -f "${f}" ] || fail "missing policy bundle file ${f} (run scripts/build-policy-bundle.sh --write)"
done
bash scripts/build-policy-bundle.sh --check || fail "policy bundle reproducibility check"
echo "    ok: bundle present + reproducible"

step "current HEAD has required CI checks green"
slug="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
runs_json="$(gh api "repos/${slug}/commits/${local_head}/check-runs" --paginate 2>/dev/null || true)"
[ -n "${runs_json}" ] || fail "could not read check-runs for ${local_head}"
for name in "${REQUIRED_CHECKS[@]}"; do
  conclusion="$(printf '%s' "${runs_json}" | python3 -c "
import sys, json
runs = json.load(sys.stdin).get('check_runs', [])
matches = [r for r in runs if r['name'] == sys.argv[1]]
if not matches:
    print('MISSING'); raise SystemExit
# newest run for this check name
matches.sort(key=lambda r: r.get('started_at') or '', reverse=True)
print(matches[0].get('conclusion') or 'pending')
" "${name}")"
  [ "${conclusion}" = "success" ] || fail "required check '${name}' for HEAD is '${conclusion}' (need success)"
  echo "    ok: ${name}"
done

echo ""
echo "release-gate: PASS. ${TAG} is ready to cut from ${local_head}."
echo "release-gate: this gate never tags. To release, a human runs:"
echo ""
echo "    git tag -a ${TAG} -m \"Release ${TAG}\" ${local_head}"
echo "    git push origin ${TAG}"
echo ""
echo "release-gate: that tag fires release.yml + live-sigstore-acceptance.yml."
