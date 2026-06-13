#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/reeve-demo-fleet-upload-test.XXXXXX")"
trap 'rm -rf "${WORKDIR}"' EXIT

SOURCE="${WORKDIR}/recording"
ENDPOINT="${SOURCE}/endpoints/eng-linux-02"
FLEET="${SOURCE}/fleet"
mkdir -p "${ENDPOINT}" "${FLEET}"

printf '{"aibom":{"scan":{"scanId":"eng-linux-02"}}}\n' >"${ENDPOINT}/scan-test.aibom.json"
printf '{"bomFormat":"CycloneDX"}\n' >"${ENDPOINT}/scan-test.cdx.json"
printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n' >"${ENDPOINT}/scan-test.sigstore.fixture.json"
printf '{"kind":"reeve-demo-fleet-manifest"}\n' >"${FLEET}/fleet-manifest.json"
printf '{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n' >"${FLEET}/fleet-manifest.sigstore.fixture.json"
printf '<!doctype html><title>fleet</title>\n' >"${FLEET}/report.html"

"${ROOT}/infra/demo-fleet/scripts/upload-artifacts.sh" \
  --source "${SOURCE}" \
  --bucket "reeve-demo-upload-test" \
  --prefix "recording-test" \
  >"${WORKDIR}/upload.stdout"

grep -q '^artifact upload validation PASS$' "${WORKDIR}/upload.stdout"
grep -q '^upload skipped: pass --execute to run aws s3 sync$' "${WORKDIR}/upload.stdout"
grep -q 'destination: s3://reeve-demo-upload-test/recording-test/' "${WORKDIR}/upload.stdout"

echo "demo fleet upload dry-run test PASS"
