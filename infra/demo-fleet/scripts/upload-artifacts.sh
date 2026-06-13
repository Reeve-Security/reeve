#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: infra/demo-fleet/scripts/upload-artifacts.sh --source DIR --bucket BUCKET [options]

Validate and optionally upload a demo-fleet artifact tree to an S3-compatible
bucket such as Cloudflare R2. Default mode is local validation only: no network,
no cloud spend, no upload.

Options:
  --source DIR          Recording output root containing endpoints/ and fleet/
  --bucket NAME         S3/R2 bucket name. Or REEVE_DEMO_ARTIFACT_BUCKET.
  --prefix PREFIX       Destination prefix. Or REEVE_DEMO_ARTIFACT_PREFIX.
  --endpoint-url URL    S3-compatible endpoint URL. Or AWS_ENDPOINT_URL_S3.
  --execute             Run aws s3 sync. Without this, validate only.
  --allow-fixture       Allow fixture Sigstore bundles during --execute.
  -h, --help            Show this help.
USAGE
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

abspath() {
  local path="$1"
  case "${path}" in
    /*) printf '%s\n' "${path}" ;;
    *) printf '%s/%s\n' "$(pwd)" "${path}" ;;
  esac
}

SOURCE=""
BUCKET="${REEVE_DEMO_ARTIFACT_BUCKET:-}"
PREFIX="${REEVE_DEMO_ARTIFACT_PREFIX:-}"
ENDPOINT_URL="${AWS_ENDPOINT_URL_S3:-}"
EXECUTE=0
ALLOW_FIXTURE=0
AWS_BIN="${AWS_BIN:-aws}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source)
      SOURCE="${2:-}"
      shift 2
      ;;
    --bucket)
      BUCKET="${2:-}"
      shift 2
      ;;
    --prefix)
      PREFIX="${2:-}"
      shift 2
      ;;
    --endpoint-url)
      ENDPOINT_URL="${2:-}"
      shift 2
      ;;
    --execute)
      EXECUTE=1
      shift
      ;;
    --allow-fixture)
      ALLOW_FIXTURE=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "${SOURCE}" ]] || { usage >&2; exit 2; }
[[ -n "${BUCKET}" ]] || fail "--bucket or REEVE_DEMO_ARTIFACT_BUCKET required"

SOURCE="$(abspath "${SOURCE}")"
[[ -d "${SOURCE}" ]] || fail "source directory not found: ${SOURCE}"
[[ -d "${SOURCE}/endpoints" ]] || fail "missing endpoints/ directory under ${SOURCE}"
[[ -f "${SOURCE}/fleet/fleet-manifest.json" ]] || fail "missing fleet/fleet-manifest.json"
[[ -f "${SOURCE}/fleet/report.html" ]] || fail "missing fleet/report.html"

if [[ -f "${SOURCE}/fleet/fleet-manifest.sigstore.json" ]]; then
  MANIFEST_BUNDLE="${SOURCE}/fleet/fleet-manifest.sigstore.json"
elif [[ -f "${SOURCE}/fleet/fleet-manifest.sigstore.fixture.json" ]]; then
  MANIFEST_BUNDLE="${SOURCE}/fleet/fleet-manifest.sigstore.fixture.json"
else
  fail "missing fleet manifest Sigstore bundle"
fi

ENDPOINT_COUNT="$(find "${SOURCE}/endpoints" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d '[:space:]')"
[[ "${ENDPOINT_COUNT}" -gt 0 ]] || fail "no endpoint directories under ${SOURCE}/endpoints"

AIBOM_COUNT="$(find "${SOURCE}/endpoints" -type f -name '*.aibom.json' | wc -l | tr -d '[:space:]')"
CDX_COUNT="$(find "${SOURCE}/endpoints" -type f -name '*.cdx.json' | wc -l | tr -d '[:space:]')"
SIGSTORE_COUNT="$(find "${SOURCE}/endpoints" -type f \( -name '*.sigstore.json' -o -name '*.sigstore.fixture.json' \) | wc -l | tr -d '[:space:]')"
FILE_COUNT="$(find "${SOURCE}" -type f | wc -l | tr -d '[:space:]')"
FIXTURE_COUNT="$(find "${SOURCE}" -type f -name '*.sigstore.fixture.json' | wc -l | tr -d '[:space:]')"

[[ "${AIBOM_COUNT}" -gt 0 ]] || fail "no endpoint AIBOM artifacts found"
[[ "${CDX_COUNT}" -gt 0 ]] || fail "no endpoint CycloneDX artifacts found"
[[ "${SIGSTORE_COUNT}" -gt 0 ]] || fail "no endpoint Sigstore bundles found"

if [[ "${EXECUTE}" -eq 1 && "${FIXTURE_COUNT}" -gt 0 && "${ALLOW_FIXTURE}" -ne 1 ]]; then
  fail "fixture Sigstore bundles present; refuse upload without --allow-fixture"
fi

if [[ -z "${PREFIX}" ]]; then
  PREFIX="recording-$(date -u +%Y%m%dT%H%M%SZ)"
fi
PREFIX="${PREFIX#/}"
PREFIX="${PREFIX%/}"
DEST="s3://${BUCKET}/${PREFIX}/"

printf 'artifact upload validation PASS\n'
printf 'source: %s\n' "${SOURCE}"
printf 'destination: %s\n' "${DEST}"
printf 'endpoint dirs: %s\n' "${ENDPOINT_COUNT}"
printf 'files: %s\n' "${FILE_COUNT}"
printf 'aibom: %s cdx: %s sigstore: %s fixture-bundles: %s\n' \
  "${AIBOM_COUNT}" "${CDX_COUNT}" "${SIGSTORE_COUNT}" "${FIXTURE_COUNT}"
printf 'manifest bundle: %s\n' "${MANIFEST_BUNDLE}"

if [[ "${EXECUTE}" -ne 1 ]]; then
  printf 'upload skipped: pass --execute to run aws s3 sync\n'
  exit 0
fi

command -v "${AWS_BIN}" >/dev/null 2>&1 || fail "aws CLI not found: ${AWS_BIN}"

SYNC_ARGS=(s3 sync "${SOURCE}" "${DEST}" --only-show-errors)
if [[ -n "${ENDPOINT_URL}" ]]; then
  SYNC_ARGS+=(--endpoint-url "${ENDPOINT_URL}")
fi

"${AWS_BIN}" "${SYNC_ARGS[@]}"
printf 'upload complete: %s\n' "${DEST}"
