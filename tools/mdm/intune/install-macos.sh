#!/usr/bin/env bash
set -euo pipefail

: "${REEVE_BINARY_URL:?missing REEVE_BINARY_URL}"
: "${REEVE_SURFACE_CONFIG_URL:?missing REEVE_SURFACE_CONFIG_URL}"
: "${REEVE_SURFACE_CONFIG_BUNDLE_URL:?missing REEVE_SURFACE_CONFIG_BUNDLE_URL}"
: "${REEVE_SIGNER_IDENTITY_REGEXP:?missing REEVE_SIGNER_IDENTITY_REGEXP}"

CONFIG_DIR="/Library/Application Support/Reeve"
SCAN_DIR="/var/db/reeve/scans"
BIN="/usr/local/bin/aibom-cli"
PLIST="/Library/LaunchDaemons/com.reeve.scan.plist"

install -d -m 0755 "$(dirname "${BIN}")" "${CONFIG_DIR}" "${SCAN_DIR}"
curl -fsSL "${REEVE_BINARY_URL}" -o "${BIN}"
chmod 0755 "${BIN}"
curl -fsSL "${REEVE_SURFACE_CONFIG_URL}" -o "${CONFIG_DIR}/surfaces.yaml"
curl -fsSL "${REEVE_SURFACE_CONFIG_BUNDLE_URL}" -o "${CONFIG_DIR}/surfaces.yaml.sigstore.json"

cat >"${PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.reeve.scan</string>
<key>ProgramArguments</key><array>
<string>${BIN}</string><string>scan</string><string>--target</string><string>/Users</string>
<string>--output-dir</string><string>${SCAN_DIR}</string>
<string>--require-signed-config</string><string>--signer-identity-regexp</string><string>${REEVE_SIGNER_IDENTITY_REGEXP}</string>
<string>--skip-sign</string>
</array>
<key>StartCalendarInterval</key><dict><key>Hour</key><integer>2</integer><key>Minute</key><integer>17</integer></dict>
</dict></plist>
EOF

chmod 0644 "${PLIST}"
chown root:wheel "${PLIST}"
launchctl bootout system "${PLIST}" >/dev/null 2>&1 || true
launchctl bootstrap system "${PLIST}"
"${BIN}" scope list --require-signed-config --signer-identity-regexp "${REEVE_SIGNER_IDENTITY_REGEXP}" >/dev/null
