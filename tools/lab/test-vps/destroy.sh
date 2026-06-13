#!/usr/bin/env bash
#
# Tear down the Hetzner VPS provisioned by run.sh.
# Stops billing. Safe to run if no VPS exists.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "${SCRIPT_DIR}/terraform"

if [[ ! -f terraform.tfstate ]]; then
    echo "No VPS state found; nothing to destroy."
    exit 0
fi

echo "Destroying VPS via OpenTofu..."
tofu destroy -auto-approve

echo "Done. Billing stopped."
