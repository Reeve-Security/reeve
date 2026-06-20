#!/usr/bin/env bash
#
# Reeve merge gate: the single source of truth for the local checks that must
# pass before code enters main. CI's `check` job calls this with --ci-local, so
# the check list lives in exactly one place. This script only ORCHESTRATES the
# existing repo checks; it never duplicates their logic.
#
# usage:
#   scripts/merge-gate.sh              run local checks, remind that remote CI is still required
#   scripts/merge-gate.sh --ci-local   run local checks only (used by the CI check job)
#   scripts/merge-gate.sh --pr <N>     run local checks, verify local HEAD == PR head SHA,
#                                      then require the named GitHub required checks to be green
#
# gitleaks and windows release smoke are separate CI jobs (cannot run on a Mac);
# they are covered by the --pr remote check, not by the local steps here.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

MODE="local" # local | ci-local
PR=""
REQUIRED_CHECKS=("check (ubuntu)" "check (macos)" "windows release smoke" "gitleaks")

usage() { sed -n '3,16p' "$0" >&2; }
fail() {
  echo "" >&2
  echo "merge-gate: FAIL: $*" >&2
  exit 1
}
step() {
  echo ""
  echo "==> $1"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --ci-local) MODE="ci-local"; shift ;;
    --pr) PR="${2:?--pr needs a PR number}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "merge-gate: unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# --- when checking a PR, fail fast on the wrong branch BEFORE local checks ---

if [ -n "${PR}" ]; then
  step "verify local HEAD == PR #${PR} head SHA"
  local_head="$(git rev-parse HEAD)"
  pr_head="$(gh pr view "${PR}" --json headRefOid -q .headRefOid)" || fail "could not read PR #${PR} head SHA"
  if [ "${local_head}" != "${pr_head}" ]; then
    fail "local HEAD ${local_head} != PR #${PR} head ${pr_head}; checkout/update the PR branch so local and GitHub checks prove the same commit"
  fi
  echo "    ok: ${local_head}"
fi

# --- local checks: call the real scripts/commands, in CI order ---------------

step "version sync set consistency"
python3 scripts/check-version-consistency.py || fail "version consistency contract"

step "cargo fmt --all -- --check"
cargo fmt --all -- --check || fail "rustfmt: run 'cargo fmt --all'"

step "cargo clippy --workspace --all-targets -- -D warnings"
cargo clippy --workspace --all-targets -- -D warnings || fail "clippy reported warnings"

step "cargo test --workspace"
cargo test --workspace || fail "tests failed"

step "policy bundle provenance + reproducibility"
python3 scripts/check-policy-bundle-provenance.py || fail "policy bundle provenance contract"
bash scripts/build-policy-bundle.sh --check || fail "policy bundle reproducibility"

step "fixture regenerator idempotency"
python3 scripts/regenerate-schema-fixtures.py || fail "fixture regenerator"
git diff --exit-code schema/fixtures/ || fail "fixtures drifted; commit the regenerated fixtures"

step "schema documentation contract"
python3 scripts/check-schema-docs.py || fail "schema docs out of sync"

step "deployment template contract"
python3 scripts/check-deploy-templates.py || fail "deploy templates"

step "workflow pinning + release permissions contract"
python3 scripts/check-workflow-pinning.py || fail "workflow pinning / release permissions"

step "private boundary contract"
python3 scripts/check-private-boundary.py || fail "private boundary"

step "tools OSS readiness contract"
python3 scripts/check-tools-oss-readiness.py || fail "tools OSS readiness"

step "no raw provider-secret literals in tracked source"
python3 scripts/check-no-raw-provider-secrets.py || fail "raw provider-secret literal in tracked source (#33)"

step "docs-only paths-ignore helper self-test"
python3 scripts/pr-docs-only.py --self-test || fail "pr-docs-only self-test (helper / ci.yml paths-ignore drift)"

step "release-sensitive-paths helper self-test"
python3 scripts/release-sensitive-paths.py --self-test || fail "release-sensitive-paths self-test (signing/release surface drift)"

step "no-raw-provider-secrets helper self-test"
python3 scripts/check-no-raw-provider-secrets.py --self-test || fail "check-no-raw-provider-secrets self-test (#33)"

step "release sensitive-data flags contract"
artifacts_dir="$(mktemp -d)"
stage_dir="$(mktemp -d)"
trap 'rm -rf "${artifacts_dir}" "${stage_dir}"' EXIT
archive_root="${stage_dir}/aibom-cli-x86_64-unknown-linux-gnu"
mkdir -p "${archive_root}"
if [ ! -x target/debug/aibom-cli ]; then
  cargo build -p aibom-cli || fail "could not build aibom-cli for the sensitive-data smoke"
fi
cp target/debug/aibom-cli "${archive_root}/aibom-cli"
chmod +x "${archive_root}/aibom-cli"
tar -C "${stage_dir}" -cJf "${artifacts_dir}/aibom-cli-x86_64-unknown-linux-gnu.tar.xz" \
  aibom-cli-x86_64-unknown-linux-gnu
python3 scripts/check-release-sensitive-data-flags.py "${artifacts_dir}" || fail "release sensitive-data flags"

step "release readiness runner"
bash scripts/release-readiness.sh || fail "release readiness"

step ".codex/ not tracked"
if [ -n "$(git ls-files .codex)" ]; then
  fail ".codex/ is tracked; it must be gitignored and untracked"
fi

echo ""
echo "merge-gate: local checks PASSED"

if [ "${MODE}" = "ci-local" ]; then
  exit 0
fi

if [ -z "${PR}" ]; then
  echo "merge-gate: reminder: remote CI (windows release smoke, gitleaks) must also be green before merge"
  exit 0
fi

# --- docs-only / paths-ignored escape hatch ----------------------------------
# A docs-only PR (every changed path matches ci.yml's pull_request paths-ignore)
# intentionally skips the heavy CI jobs, so the named required checks are absent
# by design, not by failure. Only when GitHub independently reports the PR as
# CLEAN do we treat the required-checks requirement as N/A. Normal PRs, and any
# docs-only PR that is NOT CLEAN, still go through the strict loop below.

step "classify PR #${PR} (docs-only paths-ignored?)"
changed_files="$(gh pr view "${PR}" --json files -q '.files[].path')" || fail "could not read changed files for PR #${PR}"
merge_state="$(gh pr view "${PR}" --json mergeStateStatus -q .mergeStateStatus)" || fail "could not read merge state for PR #${PR}"
if printf '%s\n' "${changed_files}" | python3 scripts/pr-docs-only.py && [ "${merge_state}" = "CLEAN" ]; then
  echo "    docs-only paths-ignored PR; heavy CI intentionally skipped by ci.yml paths-ignore; GitHub mergeable=CLEAN; required-checks requirement N/A"
  echo ""
  echo "merge-gate: PR #${PR} docs-only paths-ignored and CLEAN; local checks passed, required-checks N/A"
  exit 0
fi
echo "    not a docs-only+CLEAN PR (mergeStateStatus=${merge_state}); enforcing strict required checks"

# --- remote proof: named required checks green (HEAD==PR head verified above) -

step "verify required GitHub checks are green for PR #${PR}"
checks_json="$(gh pr checks "${PR}" --json name,bucket 2>/dev/null || true)"
[ -n "${checks_json}" ] || fail "could not read checks for PR #${PR}"
for name in "${REQUIRED_CHECKS[@]}"; do
  bucket="$(printf '%s' "${checks_json}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(next((c['bucket'] for c in d if c['name']==sys.argv[1]), 'MISSING'))" "${name}")"
  if [ "${bucket}" != "pass" ]; then
    fail "required check '${name}' is '${bucket}' (need pass)"
  fi
  echo "    ok: ${name}"
done
# Unrelated optional/skipped jobs do not block; only the named required checks gate.

echo ""
echo "merge-gate: PR #${PR} required checks green"
