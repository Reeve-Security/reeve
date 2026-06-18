#!/usr/bin/env bash
#
# Reeve advisory publish gate: verify-only check that a fixed public release
# exists and that the named advisories point at the correct fixed version,
# BEFORE a human publishes them. It never publishes anything.
#
# It reads the actual GitHub Release asset manifest; it does NOT hardcode a
# per-platform cargo-dist filename list. Advisory IDs are passed in as args so
# no GHSA IDs are baked into the repo.
#
# usage:
#   scripts/advisory-publish-gate.sh <X.Y.Z> [GHSA-... ...] [--allow-published]
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "${REPO_ROOT}"

VERSION=""
ALLOW_PUBLISHED=0
ADVISORIES=()
for arg in "$@"; do
  case "${arg}" in
    --allow-published) ALLOW_PUBLISHED=1 ;;
    GHSA-*) ADVISORIES+=("${arg}") ;;
    *)
      if [ -z "${VERSION}" ] && printf '%s' "${arg}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        VERSION="${arg}"
      else
        echo "advisory-publish-gate: unexpected argument: ${arg}" >&2; exit 2
      fi
      ;;
  esac
done

if [ -z "${VERSION}" ]; then
  echo "usage: advisory-publish-gate.sh <X.Y.Z> [GHSA-... ...] [--allow-published]" >&2
  exit 2
fi

TAG="v${VERSION}"
slug="$(gh repo view --json nameWithOwner -q .nameWithOwner)"

fail() { echo ""; echo "advisory-publish-gate: FAIL: $*" >&2; exit 1; }
warn() { echo "advisory-publish-gate: WARN: $*" >&2; }
step() { echo ""; echo "==> $1"; }

step "GitHub Release ${TAG} exists"
gh release view "${TAG}" --repo "${slug}" >/dev/null 2>&1 || fail "no GitHub Release ${TAG}"
echo "    ok"

step "release + live-sigstore workflow runs for ${TAG} succeeded"
tag_sha="$(gh api "repos/${slug}/git/ref/tags/${TAG}" --jq '.object.sha' 2>/dev/null || true)"
[ -n "${tag_sha}" ] || fail "could not resolve tag ${TAG} on remote"
# Annotated tags resolve to a tag object; dereference to the commit.
tag_type="$(gh api "repos/${slug}/git/tags/${tag_sha}" --jq '.object.sha' 2>/dev/null || true)"
commit_sha="${tag_type:-${tag_sha}}"
runs_json="$(gh api "repos/${slug}/actions/runs?head_sha=${commit_sha}&per_page=100" 2>/dev/null || true)"
[ -n "${runs_json}" ] || fail "could not read workflow runs for ${commit_sha}"
for wf in "Release" "live-sigstore"; do
  conclusion="$(printf '%s' "${runs_json}" | python3 -c "
import sys, json
runs = json.load(sys.stdin).get('workflow_runs', [])
m = [r for r in runs if sys.argv[1].lower() in (r.get('name') or '').lower()]
if not m:
    print('MISSING'); raise SystemExit
m.sort(key=lambda r: r.get('created_at') or '', reverse=True)
print(m[0].get('conclusion') or 'pending')
" "${wf}")"
  [ "${conclusion}" = "success" ] || fail "workflow matching '${wf}' for ${TAG} is '${conclusion}' (need success)"
  echo "    ok: ${wf}"
done

step "required artifacts present + every signed asset has a .bundle"
assets="$(gh release view "${TAG}" --repo "${slug}" --json assets -q '.assets[].name')"
[ -n "${assets}" ] || fail "release ${TAG} has no assets"
# minimum required artifacts: a source tarball and the policy wasm for this version
printf '%s\n' "${assets}" | grep -Eq 'source\.tar\.gz$' || fail "no source tarball asset"
printf '%s\n' "${assets}" | grep -qx "${VERSION}.wasm" || fail "missing policy bundle asset ${VERSION}.wasm"
echo "    ok: source tarball + ${VERSION}.wasm"
# every signable asset must have a matching <asset>.bundle in the manifest
missing_bundles=0
while IFS= read -r asset; do
  case "${asset}" in
    *.bundle) continue ;;
    *.tar.gz|*.tgz|*.tar.xz|*.zip|*.sh|*.wasm)
      if ! printf '%s\n' "${assets}" | grep -qx "${asset}.bundle"; then
        warn "no cosign bundle for signable asset: ${asset}"
        missing_bundles=1
      fi
      ;;
  esac
done <<< "${assets}"
[ "${missing_bundles}" -eq 0 ] || fail "one or more signable assets lack a .bundle"
echo "    ok: all signable assets have a .bundle"

step "advisories point at fixed version ${VERSION} and are still draft"
if [ "${#ADVISORIES[@]}" -eq 0 ]; then
  warn "no GHSA ids passed; skipping advisory checks (pass them as args to verify)"
else
  for ghsa in "${ADVISORIES[@]}"; do
    adv="$(gh api "repos/${slug}/security-advisories/${ghsa}" 2>/dev/null || true)"
    [ -n "${adv}" ] || fail "could not read advisory ${ghsa}"
    state="$(printf '%s' "${adv}" | python3 -c "import sys,json;print(json.load(sys.stdin).get('state',''))")"
    patched_ok="$(printf '%s' "${adv}" | python3 -c "
import sys, json
v = sys.argv[1]
d = json.load(sys.stdin)
print('yes' if any((x.get('patched_versions') or '')==v for x in d.get('vulnerabilities', [])) else 'no')
" "${VERSION}")"
    [ "${patched_ok}" = "yes" ] || fail "${ghsa} does not list patched_versions ${VERSION}"
    if [ "${state}" = "published" ]; then
      if [ "${ALLOW_PUBLISHED}" -eq 1 ]; then
        warn "${ghsa} already published (allowed by --allow-published)"
      else
        fail "${ghsa} is already published; this is a pre-publish gate (use --allow-published for audit mode)"
      fi
    elif [ "${state}" != "draft" ]; then
      warn "${ghsa} state is '${state}' (expected draft)"
    fi
    echo "    ok: ${ghsa} (state=${state}, patched=${VERSION})"
  done
fi

echo ""
echo "advisory-publish-gate: PASS. Release ${TAG} and advisories are ready."
echo "advisory-publish-gate: this gate never publishes. A human publishes each advisory in the GitHub UI."
