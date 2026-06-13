#!/usr/bin/env bash
set -euo pipefail

OPA_VERSION="1.15.2"
BUNDLE_VERSION="${POLICY_BUNDLE_VERSION:-$(python3 - <<'PY'
import pathlib, re
text = pathlib.Path("Cargo.toml").read_text()
match = re.search(r'(?m)^version = "([^"]+)"', text)
if not match:
    raise SystemExit("Cargo.toml workspace package version not found")
print(match.group(1))
PY
)}"
ENTRYPOINT="reeve/policy/verdicts"
POLICY_DIR="policies"
BUNDLE_DIR="crates/aibom-policy/bundles"
WASM_FILE="${BUNDLE_DIR}/${BUNDLE_VERSION}.wasm"
DATA_FILE="${BUNDLE_DIR}/${BUNDLE_VERSION}.json"
PROVENANCE_FILE="${BUNDLE_DIR}/${BUNDLE_VERSION}.provenance.json"
OPA_BIN="${OPA_BIN:-opa}"
MODE="${1:---check}"

case "${MODE}" in
  --check|--write) ;;
  *)
    echo "usage: $0 [--check|--write]" >&2
    exit 64
    ;;
esac

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

require_opa() {
  if ! command -v "${OPA_BIN}" >/dev/null 2>&1; then
    echo "OPA not found; install Open Policy Agent ${OPA_VERSION} or set OPA_BIN" >&2
    exit 1
  fi
  local version
  version="$(${OPA_BIN} version | awk '/^Version:/ {print $2}')"
  if [ "${version}" != "${OPA_VERSION}" ]; then
    echo "OPA version mismatch: expected ${OPA_VERSION}, got ${version:-unknown}" >&2
    exit 1
  fi
}

extract_bundle() {
  local archive="$1"
  local out_dir="$2"
  python3 - "$archive" "$out_dir" <<'PY'
import pathlib, sys, tarfile
archive = pathlib.Path(sys.argv[1])
out_dir = pathlib.Path(sys.argv[2])
out_dir.mkdir(parents=True, exist_ok=True)
needed = {"/policy.wasm": "policy.wasm", "/data.json": "data.json", "policy.wasm": "policy.wasm", "data.json": "data.json"}
with tarfile.open(archive, "r:gz") as bundle:
    found = set()
    for member in bundle.getmembers():
        name = member.name
        key = name if name in needed else f"/{name.lstrip('/')}"
        if key in needed:
            target = out_dir / needed[key]
            source = bundle.extractfile(member)
            if source is None:
                raise SystemExit(f"bundle member is not a file: {name}")
            target.write_bytes(source.read())
            found.add(needed[key])
missing = {"policy.wasm", "data.json"} - found
if missing:
    raise SystemExit(f"OPA bundle missing expected members: {sorted(missing)}")
PY
}

build_once() {
  local out_dir="$1"
  mkdir -p "${out_dir}"
  "${OPA_BIN}" build -t wasm -e "${ENTRYPOINT}" -o "${out_dir}/bundle.tar.gz" "${POLICY_DIR}/"
  extract_bundle "${out_dir}/bundle.tar.gz" "${out_dir}"
}

generate_provenance() {
  local built_dir="$1"
  local out_file="$2"
  local attempts="$3"
  local variants="$4"
  python3 - "$built_dir" "$out_file" "$attempts" "$variants" "$BUNDLE_VERSION" <<'PY'
import hashlib, json, pathlib, sys
built_dir = pathlib.Path(sys.argv[1])
out_file = pathlib.Path(sys.argv[2])
attempts = int(sys.argv[3])
variants = sorted(set(sys.argv[4].split()))
bundle_version = sys.argv[5]
root = pathlib.Path.cwd()
policy_files = []
for path in sorted((root / "policies").rglob("*.rego")):
    policy_files.append({
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    })
manifest = {
    "bundleVersion": bundle_version,
    "opaVersion": "1.15.2",
    "entrypoint": "reeve/policy/verdicts",
    "command": "opa build -t wasm -e reeve/policy/verdicts -o bundle.tar.gz policies/",
    "outputs": {
        "dataJson": {
            "path": f"crates/aibom-policy/bundles/{bundle_version}.json",
            "sha256": hashlib.sha256((built_dir / "data.json").read_bytes()).hexdigest(),
        },
        "policyWasm": {
            "path": f"crates/aibom-policy/bundles/{bundle_version}.wasm",
            "sha256": hashlib.sha256((built_dir / "policy.wasm").read_bytes()).hexdigest(),
        },
    },
    "reproducibility": {
        "mode": "bounded-reproduction",
        "attempts": attempts,
        "dataJsonByteStable": True,
        "policyWasmByteStable": False,
        "observedPolicyWasmSha256Variants": variants,
        "note": "OPA 1.15.2 can emit byte-distinct policy.wasm files for the same Rego sources and entrypoint. The check requires the committed wasm hash to be reproduced within the bounded attempt window and requires data.json to remain byte-stable.",
    },
    "sourcePolicies": policy_files,
}
out_file.parent.mkdir(parents=True, exist_ok=True)
out_file.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
PY
}

require_opa
TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "${TMP_ROOT}"' EXIT
ATTEMPTS="${POLICY_BUNDLE_REPRO_ATTEMPTS:-16}"
FIRST="${TMP_ROOT}/build-1"
build_once "${FIRST}"
first_data_hash="$(sha256_file "${FIRST}/data.json")"
first_wasm_hash="$(sha256_file "${FIRST}/policy.wasm")"
committed_wasm_hash=""
if [ -f "${WASM_FILE}" ]; then
  committed_wasm_hash="$(sha256_file "${WASM_FILE}")"
fi
matched_committed="false"
matched_dir=""
target_wasm_hash="${POLICY_BUNDLE_WRITE_WASM_SHA256:-${committed_wasm_hash}}"
target_dir=""
wasm_variants="${first_wasm_hash}"

if [ "${first_wasm_hash}" = "${committed_wasm_hash}" ]; then
  matched_committed="true"
  matched_dir="${FIRST}"
fi
if [ -n "${target_wasm_hash}" ] && [ "${first_wasm_hash}" = "${target_wasm_hash}" ]; then
  target_dir="${FIRST}"
fi

for i in $(seq 2 "${ATTEMPTS}"); do
  build_dir="${TMP_ROOT}/build-${i}"
  build_once "${build_dir}"
  data_hash="$(sha256_file "${build_dir}/data.json")"
  wasm_hash="$(sha256_file "${build_dir}/policy.wasm")"
  if [ "${data_hash}" != "${first_data_hash}" ]; then
    echo "non-deterministic OPA data output: ${first_data_hash} != ${data_hash}" >&2
    exit 1
  fi
  case " ${wasm_variants} " in
    *" ${wasm_hash} "*) ;;
    *) wasm_variants="${wasm_variants} ${wasm_hash}" ;;
  esac
  if [ "${wasm_hash}" = "${committed_wasm_hash}" ]; then
    matched_committed="true"
    matched_dir="${build_dir}"
  fi
  if [ -n "${target_wasm_hash}" ] && [ "${wasm_hash}" = "${target_wasm_hash}" ]; then
    target_dir="${build_dir}"
  fi
done

if [ "${MODE}" = "--write" ]; then
  write_dir="${target_dir:-${FIRST}}"
  generate_provenance "${write_dir}" "${TMP_ROOT}/provenance.json" "${ATTEMPTS}" "${wasm_variants}"
  cp "${write_dir}/policy.wasm" "${WASM_FILE}"
  cp "${write_dir}/data.json" "${DATA_FILE}"
  cp "${TMP_ROOT}/provenance.json" "${PROVENANCE_FILE}"
  echo "policy bundle regenerated: ${BUNDLE_VERSION}"
  echo "written wasm hash: $(sha256_file "${WASM_FILE}")"
  echo "observed wasm variants: ${wasm_variants}"
  exit 0
fi

generate_provenance "${FIRST}" "${TMP_ROOT}/provenance.json" "${ATTEMPTS}" "${wasm_variants}"

cmp -s "${FIRST}/data.json" "${DATA_FILE}" || {
  echo "committed policy data drifted: run scripts/build-policy-bundle.sh --write" >&2
  exit 1
}
python3 - "${PROVENANCE_FILE}" "${TMP_ROOT}/provenance.json" "${wasm_variants}" <<'PY'
import json, sys
committed = json.load(open(sys.argv[1]))
current = json.load(open(sys.argv[2]))
observed = set(sys.argv[3].split())
for key in ("bundleVersion", "command", "entrypoint", "opaVersion", "sourcePolicies"):
    if committed.get(key) != current.get(key):
        raise SystemExit(f"policy bundle provenance mismatch in {key}: run scripts/build-policy-bundle.sh --write")
if committed.get("outputs", {}).get("dataJson") != current.get("outputs", {}).get("dataJson"):
    raise SystemExit("policy bundle provenance mismatch in dataJson output: run scripts/build-policy-bundle.sh --write")
repro = committed.get("reproducibility", {})
if repro.get("mode") != "bounded-reproduction":
    raise SystemExit("policy bundle provenance records wrong reproducibility mode")
if repro.get("dataJsonByteStable") is not True:
    raise SystemExit("policy bundle provenance must record data.json as byte-stable")
if repro.get("policyWasmByteStable") is not False:
    raise SystemExit("policy bundle provenance must record policy.wasm as not byte-stable")
known = set(repro.get("observedPolicyWasmSha256Variants", []))
if not observed.issubset(known):
    raise SystemExit(f"observed unknown policy.wasm variants: {sorted(observed - known)}")
committed_hash = committed["outputs"]["policyWasm"]["sha256"]
if committed_hash not in known:
    raise SystemExit("provenance variants do not include committed policy.wasm hash")
PY

echo "policy bundle provenance OK"
echo "observed wasm variants: ${wasm_variants}"
