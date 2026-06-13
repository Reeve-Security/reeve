#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/reeve-demo-fleet-local.XXXXXX")"
OUT="${WORKDIR}/out"

cd "${ROOT}"
mkdir -p "${OUT}"

plant_endpoint() {
  local endpoint_id="$1"
  local persona="$2"
  local evidence_slots="$3"
  local target="${WORKDIR}/homes/${endpoint_id}"
  local endpoint_out="${OUT}/endpoints/${endpoint_id}"

  mkdir -p "${target}/.cursor" \
    "${target}/.codex" \
    "${target}/.claude/projects/${endpoint_id}" \
    "${target}/.reeve-demo" \
    "${endpoint_out}"

  cat >"${target}/.cursor/mcp.json" <<'JSON'
{
  "mcpServers": {
    "demo-filesystem": {
      "command": "/usr/bin/true"
    }
  }
}
JSON

  cat >"${target}/.codex/config.toml" <<'TOML'
[mcp_servers.demo_filesystem]
command = "/usr/bin/true"
TOML

  if [[ ",${evidence_slots}," == *",SR,"* ]]; then
    cat >"${target}/.claude/projects/${endpoint_id}/session.jsonl" <<'JSONL'
{"role":"user","content":"Fixture only: AKIAIOSFODNN7EXAMPLE should be reported by class, never serialized raw."}
JSONL
  fi

  cat >"${target}/.reeve-demo/endpoint.json" <<JSON
{
  "endpointId": "${endpoint_id}",
  "persona": "${persona}",
  "evidenceSlots": "${evidence_slots}",
  "note": "Local dry run only. No exploit payloads."
}
JSON

  cargo run -q -p aibom-cli -- scan \
    --no-system-config \
    --target "${target}" \
    --output-dir "${endpoint_out}" \
    --sign-mode fixture \
    --include-conversation-metadata \
    --scan-conversation-secrets

  test -n "$(find "${endpoint_out}" -maxdepth 1 -name '*.aibom.json' -print -quit)"
  test -n "$(find "${endpoint_out}" -maxdepth 1 -name '*.cdx.json' -print -quit)"
  test -n "$(find "${endpoint_out}" -maxdepth 1 -name '*.sigstore.fixture.json' ! -name '*.sensitive-data.*' -print -quit)"
  test -n "$(find "${endpoint_out}" -maxdepth 1 -name '*.sensitive-data.json' -print -quit)"
  test -n "$(find "${endpoint_out}" -maxdepth 1 -name '*.sensitive-data.sigstore.fixture.json' -print -quit)"

  if [[ ",${evidence_slots}," == *",SR,"* ]]; then
    grep -R '"patternClass":"aws-access-key"' "${endpoint_out}"/*.sensitive-data.json >/dev/null
  fi
}

plant_endpoint "eng-linux-02" "engineering" "MR,TL,PO,SG"
plant_endpoint "eng-linux-06" "engineering" "MR,SR,SG"
plant_endpoint "fin-win-03" "finance" "MR,VV-01,SG"

FLEET_OUT="${OUT}/fleet"
mkdir -p "${FLEET_OUT}"

cargo run -q -p aibom-cli -- fleet-manifest \
  --evidence-dir "${OUT}" \
  --output "${FLEET_OUT}/fleet-manifest.json" \
  --bundle "${FLEET_OUT}/fleet-manifest.sigstore.fixture.json" \
  --recording-scope "local dry run" \
  --sign-mode fixture

cargo run -q -p aibom-cli -- fleet-report \
  --evidence-dir "${OUT}" \
  --output "${FLEET_OUT}/report.html" \
  --format html

test -s "${FLEET_OUT}/fleet-manifest.json"
test -s "${FLEET_OUT}/fleet-manifest.sigstore.fixture.json"
test -s "${FLEET_OUT}/report.html"
grep -q '"endpointId": "eng-linux-02"' "${FLEET_OUT}/fleet-manifest.json"
grep -q '"sha256":' "${FLEET_OUT}/fleet-manifest.json"

echo "demo fleet local dry run PASS"
echo "out: ${OUT}"
