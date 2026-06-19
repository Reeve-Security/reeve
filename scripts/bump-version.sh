#!/usr/bin/env bash
#
# Reeve version bump helper: move the whole version sync set from the current
# Cargo.toml workspace version to <X.Y.Z> in one repo-owned step. It only edits
# the known sync set (Cargo.toml, Cargo.lock, the README verify-download
# examples, and the policy bundle triplet) and fails loudly if anything outside
# that set changes. It never commits, tags, or pushes; a human does that after
# review. cli_e2e.rs tracks the version via env!("CARGO_PKG_VERSION") and is
# intentionally not touched here.
#
# usage:
#   scripts/bump-version.sh <X.Y.Z>
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

NEW="${1:-}"

fail() { echo "" >&2; echo "bump-version: FAIL: $*" >&2; exit 1; }
step() { echo ""; echo "==> $1"; }

if ! printf '%s' "${NEW}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "usage: bump-version.sh <X.Y.Z>" >&2
  exit 2
fi

step "require a clean working tree"
[ -z "$(git status --porcelain)" ] || fail "working tree not clean; commit or stash first"
echo "    ok: clean"

step "validate ${NEW} is numerically greater than current Cargo.toml version"
OLD="$(grep -m1 '^version = ' Cargo.toml | sed -E 's/version = "([^"]+)"/\1/')"
printf '%s' "${OLD}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || fail "current Cargo.toml version '${OLD}' is not X.Y.Z"

# Compare major,minor,patch as integers (never lexically: 0.3.10 > 0.3.9).
IFS='.' read -r old_major old_minor old_patch <<EOF
${OLD}
EOF
IFS='.' read -r new_major new_minor new_patch <<EOF
${NEW}
EOF
greater=0
if [ "${new_major}" -gt "${old_major}" ]; then
  greater=1
elif [ "${new_major}" -eq "${old_major}" ]; then
  if [ "${new_minor}" -gt "${old_minor}" ]; then
    greater=1
  elif [ "${new_minor}" -eq "${old_minor}" ] && [ "${new_patch}" -gt "${old_patch}" ]; then
    greater=1
  fi
fi
[ "${greater}" -eq 1 ] || fail "requested ${NEW} is not greater than current ${OLD}"
echo "    ok: ${OLD} -> ${NEW}"

step "set [workspace.package] version to ${NEW} in Cargo.toml"
python3 - "${NEW}" <<'PY'
import re, sys
from pathlib import Path

new = sys.argv[1]
path = Path("Cargo.toml")
lines = path.read_text().splitlines(keepends=True)
out = []
in_workspace_package = False
replaced = False
for line in lines:
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        in_workspace_package = stripped == "[workspace.package]"
    elif in_workspace_package and re.match(r'^version\s*=\s*"[^"]+"\s*$', stripped):
        line = re.sub(r'"[^"]+"', f'"{new}"', line, count=1)
        replaced = True
    out.append(line)
if not replaced:
    raise SystemExit("could not find [workspace.package] version in Cargo.toml")
path.write_text("".join(out))
PY
echo "    ok"

step "refresh Cargo.lock (cargo update -w)"
cargo update -w || fail "cargo update -w failed"

step "rewrite README verify-download examples ${OLD} -> ${NEW}"
python3 - "${OLD}" "${NEW}" <<'PY'
import sys
from pathlib import Path

old, new = sys.argv[1], sys.argv[2]
path = Path("README.md")
lines = path.read_text().splitlines(keepends=True)
forms = {f"TAG=v{old}": f"TAG=v{new}", f'$TAG = "v{old}"': f'$TAG = "v{new}"'}
seen = set()
out = []
for line in lines:
    stripped = line.rstrip("\n")
    if stripped in forms:
        line = line.replace(stripped, forms[stripped], 1)
        seen.add(stripped)
    out.append(line)
missing = set(forms) - seen
if missing:
    raise SystemExit(f"README.md missing expected verify-download lines: {sorted(missing)}")
path.write_text("".join(out))
PY
echo "    ok"

step "generate policy bundle for ${NEW}"
bash scripts/build-policy-bundle.sh --write || fail "policy bundle build"

step "verify only the known sync set changed"
allowed=(
  "Cargo.toml"
  "Cargo.lock"
  "README.md"
  "crates/aibom-policy/bundles/${NEW}.wasm"
  "crates/aibom-policy/bundles/${NEW}.json"
  "crates/aibom-policy/bundles/${NEW}.provenance.json"
)
unexpected=""
while IFS= read -r entry; do
  [ -n "${entry}" ] || continue
  path="${entry:3}"            # strip the two-char XY status + space
  path="${path#\"}"; path="${path%\"}"
  ok=0
  for a in "${allowed[@]}"; do
    [ "${path}" = "${a}" ] && ok=1 && break
  done
  [ "${ok}" -eq 1 ] || unexpected="${unexpected}${path}\n"
done < <(git status --porcelain)
if [ -n "${unexpected}" ]; then
  printf 'bump-version: FAIL: changes outside the version sync set:\n' >&2
  printf "${unexpected}" >&2
  fail "unexpected churn (likely from the policy bundle build); revert and investigate"
fi
echo "    ok: only Cargo.toml, Cargo.lock, README.md, and the ${NEW} bundle changed"

step "version sync set consistency"
python3 scripts/check-version-consistency.py || fail "version consistency contract"

echo ""
echo "bump-version: ${OLD} -> ${NEW} done. Working tree holds the bump only; nothing committed."
echo "bump-version: next, review the diff and run the merge gate:"
echo ""
echo "    bash scripts/merge-gate.sh"
echo ""
