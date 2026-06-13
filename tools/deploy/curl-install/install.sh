#!/usr/bin/env bash
set -euo pipefail

: "${REEVE_BINARY_URL:?missing REEVE_BINARY_URL}"
: "${REEVE_SURFACE_CONFIG_URL:?missing REEVE_SURFACE_CONFIG_URL}"
: "${REEVE_SURFACE_CONFIG_BUNDLE_URL:?missing REEVE_SURFACE_CONFIG_BUNDLE_URL}"
: "${REEVE_SIGNER_IDENTITY_REGEXP:?missing REEVE_SIGNER_IDENTITY_REGEXP}"

BIN="/usr/local/bin/aibom-cli"
ROOT="${REEVE_INSTALL_ROOT:-}"
SKIP_SCHEDULER="${REEVE_SKIP_SCHEDULER:-0}"
REEVE_RUNTIME_PATH="${REEVE_RUNTIME_PATH:-/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin}"
export PATH="${REEVE_RUNTIME_PATH}:${PATH:-}"

if [[ "$(id -u)" == "0" ]]; then
  case "$(uname -s)" in
    Darwin) export HOME="${REEVE_ROOT_HOME:-/var/root}" ;;
    *) export HOME="${REEVE_ROOT_HOME:-/root}" ;;
  esac
fi

root_path() {
  printf "%s%s" "${ROOT}" "$1"
}

fetch() {
  curl -fsSL "$1" -o "$2"
}

HOST_BIN="${BIN}"
BIN="$(root_path "${HOST_BIN}")"
install -d -m 0755 "$(dirname "${BIN}")"
fetch "${REEVE_BINARY_URL}" "${BIN}"
chmod 0755 "${BIN}"

if [[ "$(uname -s)" == "Darwin" ]]; then
  CONFIG_DIR="/Library/Application Support/Reeve"
  SCAN_DIR="/var/db/reeve/scans"
  PLIST="/Library/LaunchDaemons/com.reeve.scan.plist"
  install -d -m 0755 "$(root_path "${CONFIG_DIR}")" "$(root_path "${SCAN_DIR}")" "$(root_path "$(dirname "${PLIST}")")"
  fetch "${REEVE_SURFACE_CONFIG_URL}" "$(root_path "${CONFIG_DIR}")/surfaces.yaml"
  fetch "${REEVE_SURFACE_CONFIG_BUNDLE_URL}" "$(root_path "${CONFIG_DIR}")/surfaces.yaml.sigstore.json"
  cat >"$(root_path "${PLIST}")" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.reeve.scan</string>
<key>EnvironmentVariables</key><dict><key>PATH</key><string>${REEVE_RUNTIME_PATH}</string><key>HOME</key><string>/var/root</string></dict>
<key>ProgramArguments</key><array><string>${HOST_BIN}</string><string>scan</string><string>--target</string><string>/Users</string><string>--output-dir</string><string>${SCAN_DIR}</string><string>--require-signed-config</string><string>--signer-identity-regexp</string><string>${REEVE_SIGNER_IDENTITY_REGEXP}</string><string>--skip-sign</string></array>
<key>StartCalendarInterval</key><dict><key>Hour</key><integer>2</integer><key>Minute</key><integer>17</integer></dict>
</dict></plist>
EOF
  if [[ "${SKIP_SCHEDULER}" != "1" ]]; then
    launchctl bootout system "${PLIST}" >/dev/null 2>&1 || true
    launchctl bootstrap system "${PLIST}"
  fi
else
  CONFIG_DIR="/etc/reeve"
  SCAN_DIR="/var/lib/reeve/scans"
  SYSTEMD_DIR="/etc/systemd/system"
  install -d -m 0755 "$(root_path "${CONFIG_DIR}")" "$(root_path "${SCAN_DIR}")" "$(root_path "${SYSTEMD_DIR}")"
  fetch "${REEVE_SURFACE_CONFIG_URL}" "$(root_path "${CONFIG_DIR}")/surfaces.yaml"
  fetch "${REEVE_SURFACE_CONFIG_BUNDLE_URL}" "$(root_path "${CONFIG_DIR}")/surfaces.yaml.sigstore.json"
  cat >"$(root_path "${SYSTEMD_DIR}")/reeve-scan.service" <<EOF
[Unit]
Description=Reeve endpoint scan

[Service]
Type=oneshot
Environment=PATH=${REEVE_RUNTIME_PATH}
Environment=HOME=/root
ExecStart=${HOST_BIN} scan --target /home --output-dir ${SCAN_DIR} --require-signed-config --signer-identity-regexp ${REEVE_SIGNER_IDENTITY_REGEXP} --skip-sign
EOF
  cat >"$(root_path "${SYSTEMD_DIR}")/reeve-scan.timer" <<EOF
[Unit]
Description=Run Reeve endpoint scan daily

[Timer]
OnCalendar=*-*-* 02:17:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
  if [[ "${SKIP_SCHEDULER}" != "1" ]]; then
    systemctl daemon-reload
    systemctl enable --now reeve-scan.timer
  fi
fi

"${BIN}" scope list --require-signed-config --signer-identity-regexp "${REEVE_SIGNER_IDENTITY_REGEXP}" >/dev/null
echo "Reeve install complete"
