#!/usr/bin/env bash
set -euo pipefail

inventory="${1:-inventory.yml}"

ansible reeve_vps -i "${inventory}" -m shell -a '
set -euo pipefail
test -x /usr/local/bin/aibom-cli
test -f /etc/reeve/surfaces.yaml
test -f /etc/reeve/surfaces.yaml.sigstore.json
systemctl is-enabled reeve-scan.timer
systemctl is-active reeve-scan.timer
find /var/lib/reeve/scans -name "*.aibom.json" -type f | head -1 | grep -q .
'

echo "phase1 VPS verification OK"

