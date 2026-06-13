#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: tools/lab/aggregate.sh <aibom-artifact-dir>

Walk <aibom-artifact-dir>, read *.aibom.json files, and print a Markdown
summary for lab demos. This is file-only lab tooling: no network, no DB, no
runtime service.
USAGE
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "$#" -ne 1 ]; then
  usage >&2
  exit 2
fi

INPUT_DIR="$1"
if [ ! -d "$INPUT_DIR" ]; then
  echo "lab aggregate input is not a directory: $INPUT_DIR" >&2
  exit 2
fi

python3 - "$INPUT_DIR" <<'PY'
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

root = Path(sys.argv[1])
MAX_AIBOM_BYTES = 20 * 1024 * 1024
files = sorted(
    path
    for path in root.rglob("*.aibom.json")
    if not path.is_symlink() and path.is_file() and path.stat().st_size <= MAX_AIBOM_BYTES
)

status_counts: Counter[str] = Counter()
policy_counts: Counter[str] = Counter()
adapter_counts: Counter[str] = Counter()
capability_counts: Counter[str] = Counter()
scan_ids: list[str] = []
read_errors: list[str] = []

for path in files:
    try:
        data = json.loads(path.read_text())
        aibom = data.get("aibom", {})
    except Exception as exc:  # noqa: BLE001 - CLI summary should report all bad files.
        read_errors.append(f"{path}: {exc}")
        continue

    scan = aibom.get("scan", {})
    scan_ids.append(str(scan.get("scanId") or path.parent.name or path.name))
    adapter = scan.get("adapter", {}).get("name") or "unknown"
    adapter_counts[str(adapter)] += 1

    for component in aibom.get("components", []):
        caps = component.get("capabilities", {})
        for bucket in ("declared", "observed"):
            for cap in caps.get(bucket, []):
                cap_id = cap.get("id") or "unknown"
                capability_counts[str(cap_id)] += 1

    for verdict in aibom.get("policyVerdicts", []):
        status = str(verdict.get("status") or "unknown").lower()
        policy = str(verdict.get("policyId") or "unknown")
        status_counts[status] += 1
        policy_counts[policy] += 1

print("# Reeve lab aggregate")
print()
print(f"Artifacts scanned: {len(files)}")
print(f"Readable AIBOMs: {len(files) - len(read_errors)}")
print(f"Read errors: {len(read_errors)}")
print()

print("## Policy verdicts")
if status_counts:
    for status, count in sorted(status_counts.items()):
        print(f"- {status}: {count}")
else:
    print("- none")
print()

print("## Policies with findings")
if policy_counts:
    for policy, count in sorted(policy_counts.items()):
        print(f"- {policy}: {count}")
else:
    print("- none")
print()

print("## Adapters")
for adapter, count in sorted(adapter_counts.items()):
    print(f"- {adapter}: {count}")
print()

print("## Top capabilities")
for cap_id, count in capability_counts.most_common(10):
    print(f"- {cap_id}: {count}")
if not capability_counts:
    print("- none")
print()

if read_errors:
    print("## Read errors")
    for error in read_errors:
        print(f"- {error}")
PY
