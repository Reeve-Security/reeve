#!/usr/bin/env bash
set -euo pipefail

LOG="/var/log/reeve-install.log"
BIN_URL="${4:?missing Reeve binary URL}"
CONFIG_URL="${5:?missing surface config URL}"
BUNDLE_URL="${6:?missing surface config bundle URL}"
SIGNER_IDENTITY_REGEXP="${7:?missing signer identity regexp}"
BINARY_BUNDLE_URL="${8:?missing Reeve binary signature bundle URL}"
SIGNER_ISSUER_REGEXP="${9:?missing signer OIDC issuer regexp}"

CONFIG_DIR="/Library/Application Support/Reeve"
SCAN_DIR="/var/db/reeve/scans"
BIN="/usr/local/bin/aibom-cli"
PLIST="/Library/LaunchDaemons/com.reeve.scan.plist"

exec >>"${LOG}" 2>&1

# verify_binary downloads the Reeve binary and its Sigstore bundle to temporary
# paths, cryptographically verifies the binary against the signer identity and
# OIDC issuer regexps, and only on success moves it into its final path with
# mode 0755. It fails closed: a missing cosign, a missing bundle, a non-https
# source, or a failed verification all abort the install with a non-zero exit.
#
# Args: $1 = binary source URL, $2 = bundle source URL, $3 = final binary path.
#
# REEVE_ALLOW_INSECURE_URL=1 relaxes the https-only check for hermetic local
# tests. It NEVER bypasses signature verification.
verify_binary() {
  local bin_url="$1" bundle_url="$2" final_bin="$3"

  if [[ "${REEVE_ALLOW_INSECURE_URL:-0}" != "1" ]]; then
    if [[ "${bin_url}" != https://* ]]; then
      echo "reeve: binary URL must be https://, refusing to install: ${bin_url}" >&2
      exit 1
    fi
  fi

  if ! command -v cosign >/dev/null 2>&1; then
    echo "reeve: cosign not found on PATH, refusing to install an unverified binary" >&2
    exit 1
  fi

  local tmp_dir tmp_bin tmp_bundle
  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/reeve-verify.XXXXXX")"
  trap 'rm -rf "${tmp_dir}"' RETURN
  tmp_bin="${tmp_dir}/aibom-cli"
  tmp_bundle="${tmp_dir}/aibom-cli.sigstore.json"

  curl -fsSL "${bin_url}" -o "${tmp_bin}"
  curl -fsSL "${bundle_url}" -o "${tmp_bundle}"

  if ! cosign verify-blob \
    --bundle "${tmp_bundle}" \
    --certificate-identity-regexp "${SIGNER_IDENTITY_REGEXP}" \
    --certificate-oidc-issuer-regexp "${SIGNER_ISSUER_REGEXP}" \
    "${tmp_bin}" >/dev/null 2>&1; then
    echo "reeve: cosign verify-blob failed for the downloaded binary, refusing to install" >&2
    exit 1
  fi

  install -d -m 0755 "$(dirname "${final_bin}")"
  mv -f "${tmp_bin}" "${final_bin}"
  chmod 0755 "${final_bin}"
}

install -d -m 0755 "$(dirname "${BIN}")"
install -d -m 0755 "${CONFIG_DIR}" "${SCAN_DIR}"

verify_binary "${BIN_URL}" "${BINARY_BUNDLE_URL}" "${BIN}"

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
