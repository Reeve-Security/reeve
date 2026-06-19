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

step "requested version matches Cargo.toml workspace version"
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

# Cargo.lock pins, README verify-download examples, and policy bundle presence
# for the Cargo.toml version are the version sync set; that logic lives in one
# place (check-version-consistency.py), not duplicated here.
step "version sync set consistency"
python3 scripts/check-version-consistency.py || fail "version consistency contract"

step "policy bundle reproduces for ${VERSION}"
bash scripts/build-policy-bundle.sh --check || fail "policy bundle reproducibility check"
echo "    ok: bundle reproducible"

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

# v0.3.10 shipped a cosign-signing regression because live-sigstore-acceptance
# only runs on a tag (or a labeled PR), so the signing change was never exercised
# by the live Sigstore path until AFTER the tag. If anything in the signing /
# release-sensitive surface changed since the last release, REQUIRE a successful
# live-sigstore-acceptance run for THIS exact HEAD before allowing the tag.
step "live-sigstore-acceptance required when signing/release-sensitive paths changed"
last_tag="$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)"
if [ -n "${last_tag}" ]; then
  changed_files="$(git diff --name-only "${last_tag}..HEAD")"
  echo "    last release tag: ${last_tag}"
else
  # No prior release tag: treat the whole tree as changed, so the live run is
  # required for the first release rather than silently skipped.
  changed_files="$(git ls-files)"
  echo "    no prior release tag; treating all tracked files as changed"
fi

if printf '%s\n' "${changed_files}" | python3 scripts/release-sensitive-paths.py; then
  echo "    signing/release-sensitive paths changed; live-sigstore-acceptance required for HEAD"
  echo "    changed sensitive paths:"
  printf '%s\n' "${changed_files}" \
    | python3 -c "
import sys
from importlib import util
spec = util.spec_from_file_location('rsp', 'scripts/release-sensitive-paths.py')
mod = util.module_from_spec(spec); spec.loader.exec_module(mod)
for p in mod.matching_paths(sys.stdin.read().splitlines()):
    print('      - ' + p)
"
  sigstore_json="$(gh run list --repo "${slug}" \
    --workflow live-sigstore-acceptance.yml \
    --json headSha,conclusion,status,databaseId \
    --limit 50 2>/dev/null || true)"
  [ -n "${sigstore_json}" ] || fail "could not query live-sigstore-acceptance runs from ${slug}"
  sigstore_ok="$(printf '%s' "${sigstore_json}" | python3 -c "
import sys, json
head = sys.argv[1]
runs = json.load(sys.stdin)
ok = any(r.get('headSha') == head and r.get('conclusion') == 'success' for r in runs)
print('yes' if ok else 'no')
" "${local_head}")"
  if [ "${sigstore_ok}" != "yes" ]; then
    fail "signing/release-sensitive paths changed since ${last_tag:-<no prior tag>}; no successful live-sigstore-acceptance run found for HEAD ${local_head}. Trigger it (gh workflow run live-sigstore-acceptance.yml --ref ${branch}) and re-run release-gate."
  fi
  echo "    ok: successful live-sigstore-acceptance run found for HEAD ${local_head}"
else
  echo "    no signing/release-sensitive paths changed since ${last_tag:-<no prior tag>}; live-sigstore pre-run not required"
fi

echo ""
echo "release-gate: PASS. ${TAG} is ready to cut from ${local_head}."
echo "release-gate: this gate never tags. To release, a human runs:"
echo ""
echo "    git tag -a ${TAG} -m \"Release ${TAG}\" ${local_head}"
echo "    git push origin ${TAG}"
echo ""
echo "release-gate: that tag fires release.yml + live-sigstore-acceptance.yml."
