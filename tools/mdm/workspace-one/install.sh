#!/usr/bin/env bash
set -euo pipefail

: "${REEVE_BINARY_URL:?missing REEVE_BINARY_URL}"
: "${REEVE_SURFACE_CONFIG_URL:?missing REEVE_SURFACE_CONFIG_URL}"
: "${REEVE_SURFACE_CONFIG_BUNDLE_URL:?missing REEVE_SURFACE_CONFIG_BUNDLE_URL}"
: "${REEVE_SIGNER_IDENTITY_REGEXP:?missing REEVE_SIGNER_IDENTITY_REGEXP}"

if [[ "$(uname -s)" == "Darwin" ]]; then
  CONFIG_DIR="/Library/Application Support/Reeve"
  SCAN_DIR="/var/db/reeve/scans"
else
  CONFIG_DIR="/etc/reeve"
  SCAN_DIR="/var/lib/reeve/scans"
fi

BIN="/usr/local/bin/aibom-cli"
install -d -m 0755 "$(dirname "${BIN}")" "${CONFIG_DIR}" "${SCAN_DIR}"
curl -fsSL "${REEVE_BINARY_URL}" -o "${BIN}"
chmod 0755 "${BIN}"
curl -fsSL "${REEVE_SURFACE_CONFIG_URL}" -o "${CONFIG_DIR}/surfaces.yaml"
curl -fsSL "${REEVE_SURFACE_CONFIG_BUNDLE_URL}" -o "${CONFIG_DIR}/surfaces.yaml.sigstore.json"

"${BIN}" scope list --require-signed-config --signer-identity-regexp "${REEVE_SIGNER_IDENTITY_REGEXP}" >/dev/null
