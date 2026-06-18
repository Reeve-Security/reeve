#!/usr/bin/env python3
"""Static contract checks for the committed policy bundle provenance pipeline."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_OPA_VERSION = "1.15.2"


def workspace_version() -> str:
    match = re.search(r'(?m)^version = "([^"]+)"', read("Cargo.toml"))
    if not match:
        raise SystemExit("Cargo.toml workspace package version not found")
    return match.group(1)


def read(path: str) -> str:
    return (ROOT / path).read_text()


def require(path: str, needle: str) -> None:
    text = read(path)
    if needle not in text:
        raise SystemExit(f"{path}: missing expected text: {needle}")


def sha256(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main() -> None:
    version = workspace_version()
    script = "scripts/build-policy-bundle.sh"
    require(script, f'OPA_VERSION="{EXPECTED_OPA_VERSION}"')
    require(script, "POLICY_BUNDLE_VERSION")
    require(script, "Cargo.toml workspace package version not found")
    require(script, 'build -t wasm -e "${ENTRYPOINT}"')
    require(script, 'ENTRYPOINT="reeve/policy/verdicts"')
    require(script, 'build_once "${FIRST}"')
    require(script, 'POLICY_BUNDLE_REPRO_ATTEMPTS')
    require(script, 'POLICY_BUNDLE_WRITE_WASM_SHA256')
    require(script, 'matched_committed')
    require(script, 'target_wasm_hash')
    require(script, 'observed wasm variants')
    require(script, 'rglob("*.rego")')
    require(script, 'observed.issubset(known)')
    require(script, 'OPA 1.15.2 can emit byte-distinct policy.wasm')
    require(script, '--write')
    require(script, '--check')

    # The check list is orchestrated by scripts/merge-gate.sh (single source of
    # truth); ci.yml delegates to it, and the gate runs the bundle reproducibility
    # check. The pinned OPA install stays in ci.yml.
    require(".github/workflows/ci.yml", "scripts/merge-gate.sh --ci-local")
    require("scripts/merge-gate.sh", "bash scripts/build-policy-bundle.sh --check")
    require(".github/workflows/ci.yml", f'OPA_VERSION="{EXPECTED_OPA_VERSION}"')
    require(".github/workflows/ci.yml", "opa_linux_amd64_static")
    require(".github/workflows/ci.yml", "a9d9481e463e7af8cb1a2cd7c3deb764f0327b3281c54e632546c2f425fc0824")

    require("crates/aibom-policy/Cargo.toml", "serde_json.workspace = true")
    require("crates/aibom-policy/build.rs", "policy_bundle_hashes(&provenance_src, &version)")
    require("crates/aibom-policy/build.rs", '"/outputs/policyWasm/sha256"')
    require("crates/aibom-policy/build.rs", '"/outputs/dataJson/sha256"')
    require("crates/aibom-policy/build.rs", "verify_hash(&wasm_src, &hashes.policy_wasm);")
    require("crates/aibom-policy/build.rs", "verify_hash(&data_src, &hashes.data_json);")
    require(".gitattributes", "crates/aibom-policy/bundles/*.json -text")
    require(".gitattributes", "crates/aibom-policy/bundles/*.wasm -text")

    provenance_path = ROOT / f"crates/aibom-policy/bundles/{version}.provenance.json"
    provenance = json.loads(provenance_path.read_text())
    if provenance["bundleVersion"] != version:
        raise SystemExit("provenance pins wrong bundle version")
    if provenance["opaVersion"] != EXPECTED_OPA_VERSION:
        raise SystemExit("provenance pins wrong OPA version")
    if provenance["entrypoint"] != "reeve/policy/verdicts":
        raise SystemExit("provenance pins wrong OPA entrypoint")
    if provenance["outputs"]["policyWasm"]["path"] != f"crates/aibom-policy/bundles/{version}.wasm":
        raise SystemExit("provenance wasm path does not match workspace version")
    if provenance["outputs"]["dataJson"]["path"] != f"crates/aibom-policy/bundles/{version}.json":
        raise SystemExit("provenance data path does not match workspace version")
    if provenance["outputs"]["policyWasm"]["sha256"] != sha256(f"crates/aibom-policy/bundles/{version}.wasm"):
        raise SystemExit("provenance wasm hash does not match committed wasm")
    if provenance["outputs"]["dataJson"]["sha256"] != sha256(f"crates/aibom-policy/bundles/{version}.json"):
        raise SystemExit("provenance data hash does not match committed data")
    reproducibility = provenance["reproducibility"]
    if reproducibility["mode"] != "bounded-reproduction":
        raise SystemExit("provenance records wrong reproducibility mode")
    if reproducibility["attempts"] < 2:
        raise SystemExit("provenance records too few reproduction attempts")
    if reproducibility["dataJsonByteStable"] is not True:
        raise SystemExit("provenance must record data.json as byte-stable")
    if reproducibility["policyWasmByteStable"] is not False:
        raise SystemExit("provenance must record policy.wasm as not byte-stable")
    variants = set(reproducibility["observedPolicyWasmSha256Variants"])
    if provenance["outputs"]["policyWasm"]["sha256"] not in variants:
        raise SystemExit("provenance variants do not include committed wasm hash")
    source_policy_paths = {entry["path"] for entry in provenance["sourcePolicies"]}
    expected_policy_paths = {path.relative_to(ROOT).as_posix() for path in sorted((ROOT / "policies").rglob("*.rego"))}
    if source_policy_paths != expected_policy_paths:
        missing = sorted(expected_policy_paths - source_policy_paths)
        extra = sorted(source_policy_paths - expected_policy_paths)
        raise SystemExit(f"provenance policy input mismatch; missing={missing} extra={extra}")
    for entry in provenance["sourcePolicies"]:
        if entry["sha256"] != sha256(entry["path"]):
            raise SystemExit(f"provenance hash mismatch for {entry['path']}")

    print("policy bundle provenance contract OK")


if __name__ == "__main__":
    main()
