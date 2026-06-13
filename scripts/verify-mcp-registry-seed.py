#!/usr/bin/env python3
"""Verify and summarize a Reeve MCP registry seed artifact."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
PREDICATE_TYPE = "https://aibom.example/attestation/mcp-registry-seed/v0.1"


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha256_bytes(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_fixture_bundle(bundle) -> bool:
    material = bundle.get("verificationMaterial", {})
    return "_fixture_note" in material


def decode_statement(bundle_path: Path, bundle):
    envelope = bundle.get("dsseEnvelope")
    require(isinstance(envelope, dict), f"{bundle_path}: missing dsseEnvelope")
    require(
        envelope.get("payloadType") == DSSE_PAYLOAD_TYPE,
        f"{bundle_path}: DSSE payloadType mismatch",
    )
    payload = envelope.get("payload")
    require(isinstance(payload, str), f"{bundle_path}: missing DSSE payload")
    try:
        statement_bytes = base64.b64decode(payload, validate=True)
        return json.loads(statement_bytes)
    except (ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"{bundle_path}: invalid DSSE statement payload: {exc}") from exc


def verify_statement(seed_path: Path, seed, bundle_path: Path, bundle, expected_source_url) -> None:
    statement = decode_statement(bundle_path, bundle)
    require(statement.get("_type") == IN_TOTO_STATEMENT_TYPE, "statement type mismatch")
    require(statement.get("predicateType") == PREDICATE_TYPE, "predicateType mismatch")

    subjects = statement.get("subject")
    require(isinstance(subjects, list) and len(subjects) == 1, "statement must have one subject")
    digest = subjects[0].get("digest", {}).get("sha256")
    expected_digest = sha256_bytes(seed_path)
    require(digest == expected_digest, "statement subject digest does not match seed bytes")

    predicate = statement.get("predicate", {})
    roles = predicate.get("artifactRoles", {})
    subject_name = subjects[0].get("name")
    require(roles.get(subject_name) == "mcp-registry-seed", "statement artifact role mismatch")

    if expected_source_url:
        require(seed.get("source", {}).get("url") == expected_source_url, "seed source URL mismatch")
        require(
            predicate.get("source", {}).get("url") == expected_source_url,
            "statement source URL mismatch",
        )


def verify_seed(seed_path: Path, seed) -> None:
    require(seed.get("kind") == "reeve-mcp-registry-seed", "seed kind mismatch")
    require(seed.get("schemaVersion") == "0.1.0", "seed schemaVersion mismatch")
    records = seed.get("records")
    require(isinstance(records, list) and records, "seed records must be a non-empty array")
    summary_records = seed.get("summary", {}).get("records")
    require(summary_records == len(records), "seed summary.records does not match records length")

    dedupe_keys = []
    for index, record in enumerate(records):
        key = record.get("dedupeKey")
        require(isinstance(key, str) and key, f"record {index}: missing dedupeKey")
        require(record.get("sourceRegistry") == "official-mcp-registry", f"record {index}: source mismatch")
        identity = record.get("canonicalIdentity")
        require(isinstance(identity, dict), f"record {index}: missing canonicalIdentity")
        require(identity.get("name"), f"record {index}: missing canonicalIdentity.name")
        require(identity.get("version"), f"record {index}: missing canonicalIdentity.version")
        dedupe_keys.append(key)
    require(len(set(dedupe_keys)) == len(dedupe_keys), "seed contains duplicate dedupeKey values")


def run_cosign(seed_path: Path, bundle_path: Path, identity_regexp: str, issuer: str) -> None:
    cmd = [
        "cosign",
        "verify-blob",
        "--bundle",
        str(bundle_path),
        "--certificate-identity-regexp",
        identity_regexp,
        "--certificate-oidc-issuer",
        issuer,
        str(seed_path),
    ]
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError as exc:
        raise SystemExit("cosign not found; install cosign or pass --allow-fixture for fixture bundles") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(f"cosign verify-blob failed with exit {exc.returncode}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--expected-source-url")
    parser.add_argument("--allow-fixture", action="store_true")
    parser.add_argument("--certificate-identity-regexp")
    parser.add_argument(
        "--certificate-oidc-issuer",
        default="https://token.actions.githubusercontent.com",
    )
    args = parser.parse_args()

    seed = read_json(args.seed)
    bundle = read_json(args.bundle)
    fixture = is_fixture_bundle(bundle)
    if fixture and not args.allow_fixture:
        raise SystemExit("fixture bundle refused; pass --allow-fixture only for local tests")
    if not fixture:
        require(
            args.certificate_identity_regexp,
            "real bundle requires --certificate-identity-regexp for cosign verification",
        )
        run_cosign(
            args.seed,
            args.bundle,
            args.certificate_identity_regexp,
            args.certificate_oidc_issuer,
        )

    verify_seed(args.seed, seed)
    verify_statement(args.seed, seed, args.bundle, bundle, args.expected_source_url)
    records = seed["summary"]["records"]
    active = seed["summary"].get("activeRecords", 0)
    latest = seed["summary"].get("latestRecords", 0)
    print(
        f"mcp registry seed OK records={records} active={active} latest={latest} "
        f"bundle={'fixture' if fixture else 'real'}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
