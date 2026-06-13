#!/usr/bin/env bash
set -euo pipefail

LOG="/var/log/reeve-install.log"
BIN_URL="${4:?missing Reeve binary URL}"
CONFIG_URL="${5:?missing surface config URL}"
BUNDLE_URL="${6:?missing surface config bundle URL}"
SIGNER_IDENTITY_REGEXP="${7:?missing signer identity regexp}"

CONFIG_DIR="/Library/Application Support/Reeve"
SCAN_DIR="/var/db/reeve/scans"
BIN="/usr/local/bin/aibom-cli"
PLIST="/Library/LaunchDaemons/com.reeve.scan.plist"

exec >>"${LOG}" 2>&1

install -d -m 0755 "$(dirname "${BIN}")"
install -d -m 0755 "${CONFIG_DIR}" "${SCAN_DIR}"

curl -fsSL "${BIN_URL}" -o "${BIN}"
chmod 0755 "${BIN}"

curl -fsSL "${CONFIG_URL}" -o "${CONFIG_DIR}/surfaces.yaml"
curl -fsSL "${BUNDLE_URL}" -o "${CONFIG_DIR}/surfaces.yaml.sigstore.json"
chmod 0644 "${CONFIG_DIR}/surfaces.yaml" "${CONFIG_DIR}/surfaces.yaml.sigstore.json"

cat >"${PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.reeve.scan</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BIN}</string>
    <string>scan</string>
    <string>--target</string>
    <string>/Users</string>
    <string>--output-dir</string>
    <string>${SCAN_DIR}</string>
    <string>--require-signed-config</string>
    <string>--signer-identity-regexp</string>
    <string>${SIGNER_IDENTITY_REGEXP}</string>
    <string>--skip-sign</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>2</integer>
    <key>Minute</key>
    <integer>17</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>/var/log/reeve-scan.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/reeve-scan.err</string>
</dict>
</plist>
EOF

chmod 0644 "${PLIST}"
chown root:wheel "${PLIST}"
launchctl bootout system "${PLIST}" >/dev/null 2>&1 || true
launchctl bootstrap system "${PLIST}"
launchctl enable system/com.reeve.scan

"${BIN}" scope list --require-signed-config --signer-identity-regexp "${SIGNER_IDENTITY_REGEXP}" >/dev/null
echo "Reeve Jamf install complete"
