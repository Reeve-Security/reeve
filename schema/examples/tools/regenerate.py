#!/usr/bin/env python3
"""
Reeve AIBOM fixture regenerator (v0.1 bootstrap generator).

Reads each fixture's existing aibom.json, injects scan.scanner if missing,
emits JCS-canonical bytes per ADR-0003, updates the matching CycloneDX
externalReferences hash, rebuilds the Sigstore bundle Statement, and
refreshes canonical-bytes.sha256. Also creates fixture 28 for the
canonicalization.byte_drift case.

Deterministic. Standard library only. No network.

Run from anywhere:

    python3 schema/examples/tools/regenerate.py
"""

import json
import hashlib
import base64
import pathlib
import sys
from typing import Optional

SCANNER = {"name": "reeve", "version": "0.1.0"}
ROOT = pathlib.Path(__file__).resolve().parents[2] / "examples" / "fixtures"
SENSITIVE_DATA_ROOT = pathlib.Path(__file__).resolve().parents[2] / "examples" / "sensitive-data-report"
SECRET_RULE_PACK_ROOT = pathlib.Path(__file__).resolve().parents[2] / "examples" / "secret-rule-pack"

# ---------------------------------------------------------------------------
# Core helpers

def jcs_bytes(data) -> bytes:
    """JCS-canonical UTF-8 bytes.

    For Reeve payloads (strings, integers, booleans, null, objects, arrays;
    no floats, no high-codepoint unicode) this is equivalent to the formal
    RFC 8785 algorithm.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha512_hex(b: bytes) -> str:
    return hashlib.sha512(b).hexdigest()


def inject_scanner(aibom_data: dict) -> dict:
    """Ensure aibom.scan.scanner is present. Idempotent."""
    scan = aibom_data.get("aibom", {}).get("scan")
    if scan is not None:
        scan["scanner"] = SCANNER
    return aibom_data


def sigstore_bundle(payload_b64: str) -> dict:
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "_fixture_note": "placeholder; real Fulcio cert + Rekor v2 proof generated via cosign keyless in build-order step 4",
            "certificate": {"rawBytes": "FIXTURE_PLACEHOLDER_CERT_BYTES"},
            "tlogEntries": [
                {
                    "_fixture_note": "placeholder Rekor v2 dsse entry",
                    "logIndex": "0",
                    "logId": {"keyId": "FIXTURE_PLACEHOLDER"},
                    "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                    "integratedTime": "1745193600",
                    "inclusionPromise": {"signedEntryTimestamp": "FIXTURE_PLACEHOLDER"},
                    "inclusionProof": {
                        "_fixture_note": "placeholder inclusion proof",
                        "checkpoint": {"envelope": "FIXTURE_PLACEHOLDER"},
                        "hashes": [],
                        "logIndex": "0",
                        "rootHash": "FIXTURE_PLACEHOLDER",
                        "treeSize": "0",
                    },
                }
            ],
        },
        "dsseEnvelope": {
            "payload": payload_b64,
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"_fixture_note": "placeholder signature", "sig": "FIXTURE_PLACEHOLDER_SIGNATURE"}],
        },
    }


def build_statement(scan_id: str, aibom_sha256: str, cdx_sha256: str,
                    aibom_bytes: Optional[bytes] = None, cdx_bytes: Optional[bytes] = None,
                    variant: str = "valid") -> dict:
    """Build an in-toto Statement. Applies intentional defects per variant."""
    aibom_name = f"fixture-{scan_id}.aibom.json"
    cdx_name = f"fixture-{scan_id}.cdx.json"

    subjects = [
        {"digest": {"sha256": aibom_sha256}, "name": aibom_name},
        {"digest": {"sha256": cdx_sha256}, "name": cdx_name},
    ]
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": {
            "artifactRoles": {aibom_name: "aibom-sidecar", cdx_name: "cyclonedx"},
            "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
            "schemaVersion": "0.1.0",
        },
        "predicateType": "https://aibom.example/attestation/aibom/v0.1",
        "subject": subjects,
    }

    if variant == "wrong_predicateType":
        statement["predicateType"] = "https://slsa.dev/provenance/v1"
    elif variant == "three_subjects":
        statement["subject"] = subjects + [
            {
                "digest": {"sha256": "3" * 64},
                "name": f"fixture-{scan_id}.extra.json",
            }
        ]
    elif variant == "sha512_digest":
        assert aibom_bytes is not None and cdx_bytes is not None, "sha512 variant needs raw bytes"
        statement["subject"] = [
            {"digest": {"sha512": sha512_hex(aibom_bytes)}, "name": aibom_name},
            {"digest": {"sha512": sha512_hex(cdx_bytes)}, "name": cdx_name},
        ]
    elif variant != "valid":
        raise ValueError(f"unknown variant: {variant}")
    return statement


def b64_payload(statement: dict) -> str:
    return base64.b64encode(jcs_bytes(statement)).decode("ascii")


# ---------------------------------------------------------------------------
# Per-fixture configuration

# For the cdx_hash field:
#   "auto"  -> compute from the new aibom canonical bytes
#   "zeros" -> keep the all-zero intentional mismatch (fixture 17)
FIXTURES = [
    # Positives — full triplet regeneration
    {"path": "positive/01-minimal-stdio", "scan_id": "01", "has_cdx": True, "cdx_hash": "auto", "sigstore": "valid"},
    {"path": "positive/02-network-egress-match", "scan_id": "02", "has_cdx": True, "cdx_hash": "auto", "sigstore": "valid"},
    {"path": "positive/03-undeclared-egress-delta", "scan_id": "03", "has_cdx": True, "cdx_hash": "auto", "sigstore": "valid"},
    {"path": "positive/04-filesystem-prefix", "scan_id": "04", "has_cdx": True, "cdx_hash": "auto", "sigstore": "valid"},
    {"path": "positive/05-subprocess", "scan_id": "05", "has_cdx": True, "cdx_hash": "auto", "sigstore": "valid"},
    {"path": "positive/06-secret-read", "scan_id": "06", "has_cdx": True, "cdx_hash": "auto", "sigstore": "valid"},
    {"path": "positive/07-mcp-extension", "scan_id": "07", "has_cdx": True, "cdx_hash": "auto", "sigstore": "valid"},
    {"path": "positive/08-reverse-dns-extension", "scan_id": "08", "has_cdx": True, "cdx_hash": "auto", "sigstore": "valid"},
    {"path": "positive/09-multi-component-one-sidecar", "scan_id": "09", "has_cdx": True, "cdx_hash": "auto", "sigstore": "valid"},
    {"path": "positive/10-capability-merge", "scan_id": "10", "has_cdx": True, "cdx_hash": "auto", "sigstore": "valid"},

    # Negatives — aibom-only unless otherwise noted
    {"path": "negative/11-invalid-core-looking-id", "scan_id": "11", "has_cdx": False, "sigstore": None},
    {"path": "negative/12-invalid-single-label-extension", "scan_id": "12", "has_cdx": False, "sigstore": None},
    {"path": "negative/13-invalid-core-qualifier-key", "scan_id": "13", "has_cdx": False, "sigstore": None},
    {"path": "negative/14-invalid-empty-evidence", "scan_id": "14", "has_cdx": False, "sigstore": None},
    {"path": "negative/15-invalid-source-mismatch", "scan_id": "15", "has_cdx": False, "sigstore": None},
    {"path": "negative/16-invalid-duplicate-external-ref", "scan_id": "16", "has_cdx": True, "cdx_hash": "auto", "sigstore": None, "cdx_duplicate_external_refs": True},
    {"path": "negative/17-invalid-cdx-sidecar-hash", "scan_id": "17", "has_cdx": True, "cdx_hash": "zeros", "sigstore": None},
    {"path": "negative/18-invalid-version-mismatch", "scan_id": "18", "has_cdx": False, "sigstore": None, "force_schema_version": "9.9.9"},
    {"path": "negative/19-invalid-capability-extra-confidence", "scan_id": "19", "has_cdx": False, "sigstore": None},
    {"path": "negative/20-invalid-attestation-predicate-type", "scan_id": "20", "has_cdx": True, "cdx_hash": "auto", "sigstore": "wrong_predicateType"},
    {"path": "negative/21-invalid-attestation-subject-count", "scan_id": "21", "has_cdx": True, "cdx_hash": "auto", "sigstore": "three_subjects"},
    {"path": "negative/22-invalid-attestation-digest-alg", "scan_id": "22", "has_cdx": True, "cdx_hash": "auto", "sigstore": "sha512_digest"},
    {"path": "negative/23-invalid-bom-ref-duplicate", "scan_id": "23", "has_cdx": False, "sigstore": None},
    {"path": "negative/24-invalid-evidence-id-duplicate", "scan_id": "24", "has_cdx": False, "sigstore": None},
    {"path": "negative/25-invalid-capability-dangling-evidence", "scan_id": "25", "has_cdx": False, "sigstore": None},
    {"path": "negative/26-invalid-component-missing-in-cdx", "scan_id": "26", "has_cdx": True, "cdx_hash": "auto", "sigstore": None},
    {"path": "negative/27-invalid-cdx-url-mismatch", "scan_id": "27", "has_cdx": True, "cdx_hash": "auto", "sigstore": None, "cdx_url_override": "wrong-name.aibom.json"},
]


# ---------------------------------------------------------------------------
# Regeneration pass over existing fixtures

def regenerate(cfg):
    fix_dir = ROOT / cfg["path"]
    scan_id = cfg["scan_id"]
    aibom_path = fix_dir / f"fixture-{scan_id}.aibom.json"
    if not aibom_path.exists():
        print(f"  SKIP {cfg['path']} (no aibom.json)")
        return

    aibom = json.loads(aibom_path.read_bytes())

    # Scanner injection + optional schemaVersion override (for fixture 18)
    aibom = inject_scanner(aibom)
    if cfg.get("force_schema_version"):
        aibom["aibom"]["schemaVersion"] = cfg["force_schema_version"]

    # Emit canonical bytes + compute hash
    aibom_canon = jcs_bytes(aibom)
    aibom_path.write_bytes(aibom_canon)
    aibom_sha = sha256_hex(aibom_canon)

    # CycloneDX regeneration (if the fixture has one)
    cdx_sha = None
    cdx_canon = None
    if cfg.get("has_cdx"):
        cdx_path = fix_dir / f"fixture-{scan_id}.cdx.json"
        cdx = json.loads(cdx_path.read_bytes())

        new_hash = "0" * 64 if cfg["cdx_hash"] == "zeros" else aibom_sha
        for component in cdx["components"]:
            for ext_ref in component.get("externalReferences", []):
                if ext_ref.get("type") == "bom":
                    for h in ext_ref.get("hashes", []):
                        if h.get("alg") == "SHA-256":
                            h["content"] = new_hash
                    if cfg.get("cdx_url_override"):
                        ext_ref["url"] = cfg["cdx_url_override"]

        cdx_canon = jcs_bytes(cdx)
        cdx_path.write_bytes(cdx_canon)
        cdx_sha = sha256_hex(cdx_canon)

    # Sigstore bundle (if the fixture has one)
    if cfg.get("sigstore") is not None:
        assert cdx_sha is not None and cdx_canon is not None, "sigstore variant requires cdx"
        stmt = build_statement(scan_id, aibom_sha, cdx_sha,
                               aibom_bytes=aibom_canon, cdx_bytes=cdx_canon,
                               variant=cfg["sigstore"])
        bundle = sigstore_bundle(b64_payload(stmt))
        sig_path = fix_dir / f"fixture-{scan_id}.sigstore.fixture.json"
        # Sigstore bundles are emitted pretty for human review; their bytes
        # are not JCS-normative for v0.1. Only the encoded Statement payload
        # is structurally checked by the harness.
        sig_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n")

    # canonical-bytes.sha256 (positive fixtures only)
    cb_path = fix_dir / "canonical-bytes.sha256"
    if cb_path.exists():
        cb_path.write_text(aibom_sha + "\n")

    print(f"  OK   {cfg['path']} aibom={aibom_sha}"
          + (f" cdx={cdx_sha}" if cdx_sha else ""))


# ---------------------------------------------------------------------------
# Fixture 28: canonicalization.byte_drift

def create_fixture_28():
    fix_dir = ROOT / "negative" / "28-invalid-canonicalization-byte-drift"
    fix_dir.mkdir(parents=True, exist_ok=True)

    # Valid AIBOM content (shape mirrors fixture 01).
    aibom = {
        "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
        "aibom": {
            "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
            "components": [
                {
                    "bom-ref": "pkg:npm/%40modelcontextprotocol/server-filesystem@2.3.1",
                    "capabilities": {
                        "declared": [
                            {"evidence": ["ev-001"], "id": "fs:read", "qualifiers": {}, "source": "declared"}
                        ],
                        "observed": [
                            {"evidence": ["ev-002"], "id": "fs:read", "qualifiers": {}, "source": "observed"}
                        ],
                    },
                }
            ],
            "evidence": [
                {"id": "ev-001", "kind": "mcp-tools-list", "reference": "mcp://filesystem/tools/list#read_file"},
                {"id": "ev-002", "kind": "sandbox-syscall", "reference": "sandbox://trace/0/open#READ"},
            ],
            "scan": {
                "adapter": {"name": "mcp", "version": "0.1.0"},
                "scanId": "fixture-28",
                "scanner": SCANNER,
                "timestamp": "2026-04-21T00:00:00Z",
            },
            "schemaVersion": "0.1.0",
        },
    }

    # Deliberately NOT JCS-canonical: pretty-printed with 2-space indent and
    # default key order. Schema + semantic stages will pass; canonicalization
    # stage must reject because the bytes do not equal jcs_bytes(aibom).
    aibom_path = fix_dir / "fixture-28.aibom.json"
    pretty = json.dumps(aibom, indent=2, ensure_ascii=False) + "\n"
    aibom_path.write_text(pretty)

    manifest = {
        "name": "28-invalid-canonicalization-byte-drift",
        "kind": "negative",
        "expected": "schema-reject",
        "rejectStage": "canonicalization",
        "expectedErrorCode": "canonicalization.byte_drift",
        "rejectPointer": "",
        "invariants": ["Q3.h"],
        "description": (
            "Sidecar content is valid (passes schema-validation and "
            "semantic-validation) but the on-disk bytes are pretty-printed "
            "instead of JCS-canonical. Harness rejects at canonicalization "
            "stage when the file's raw bytes do not equal the output of the "
            "JCS canonicalizer for the parsed JSON value."
        ),
        "notes": (
            "The defect is purely at the byte-representation layer. Parsing "
            "the file yields a JSON value that would pass all other stages; "
            "re-serializing via JCS produces different bytes, which fails "
            "the equality check. This is the core invariant from ADR-0003's "
            "distribution rule: the sidecar artifact referenced from "
            "CycloneDX MUST be stored and distributed as JCS-canonical "
            "bytes. A human-readable pretty copy is allowed only as a "
            "derived view, never as the artifact."
        ),
    }
    (fix_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    )

    print(f"  OK   negative/28-invalid-canonicalization-byte-drift "
          f"(pretty-printed sidecar, {len(pretty)} bytes)")


# ---------------------------------------------------------------------------
# Policy fixtures 35-41

def write_positive_policy_fixture(spec: dict):
    fix_dir = ROOT / "policy" / spec["dir"]
    fix_dir.mkdir(parents=True, exist_ok=True)

    aibom_path = fix_dir / f"fixture-{spec['scan_id']}.aibom.json"
    cdx_path = fix_dir / f"fixture-{spec['scan_id']}.cdx.json"
    bundle_path = fix_dir / f"fixture-{spec['scan_id']}.sigstore.fixture.json"
    canonical_path = fix_dir / "canonical-bytes.sha256"
    manifest_path = fix_dir / "manifest.json"

    aibom_data = inject_scanner(spec["aibom"])
    aibom_canon = jcs_bytes(aibom_data)
    aibom_path.write_bytes(aibom_canon)
    aibom_sha = sha256_hex(aibom_canon)

    cdx_component = {
        "type": "application",
        "bom-ref": spec["component"]["bom-ref"],
        "name": spec["component_name"],
        "externalReferences": [{
            "type": "bom",
            "url": f"fixture-{spec['scan_id']}.aibom.json",
            "hashes": [{"alg": "SHA-256", "content": aibom_sha}],
        }],
    }
    cdx_component.update(spec.get("cdx_component", {}))

    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:fixture-{spec['scan_id']}",
        "version": 1,
        "metadata": {"timestamp": "2026-04-24T00:00:00Z"},
        "components": [cdx_component],
    }
    cdx_canon = jcs_bytes(cdx)
    cdx_path.write_bytes(cdx_canon)
    cdx_sha = sha256_hex(cdx_canon)

    stmt = build_statement(spec["scan_id"], aibom_sha, cdx_sha,
                           aibom_bytes=aibom_canon, cdx_bytes=cdx_canon,
                           variant="valid")
    bundle = sigstore_bundle(b64_payload(stmt))
    bundle_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n")

    canonical_path.write_text(aibom_sha + "\n")
    manifest_path.write_text(json.dumps(spec["manifest"], indent=2, ensure_ascii=False) + "\n")

    print(f"  OK   policy/{spec['dir']} aibom={aibom_sha} cdx={cdx_sha}")


def create_policy_fixtures():
    deny_component = {
        "bom-ref": "pkg:npm/%40modelcontextprotocol/server-fetch@1.2.0",
        "capabilities": {
            "declared": [
                {"evidence": ["ev-001"], "id": "net:egress", "qualifiers": {"host": "api.example.com", "port": 443, "scheme": "https"}, "source": "declared"}
            ],
            "observed": [
                {"evidence": ["ev-002"], "id": "net:egress", "qualifiers": {"host": "api.example.com", "port": 443, "scheme": "https"}, "source": "observed"},
                {"evidence": ["ev-003"], "id": "net:egress", "qualifiers": {"host": "api.untrusted.example", "port": 443, "scheme": "https"}, "source": "observed"}
            ],
        },
    }
    warn_component = {
        "bom-ref": "pkg:npm/launch-playwright-mcp@0.0.1",
        "capabilities": {
            "declared": [
                {"evidence": ["ev-001"], "id": "mcp:tool:call", "qualifiers": {"tool_name": "browser_navigate"}, "source": "declared"}
            ],
            "observed": [
                {"evidence": ["ev-002"], "id": "exec:subprocess", "qualifiers": {"cmd": "env"}, "source": "observed"}
            ],
        },
    }
    clean_component = {
        "bom-ref": "pkg:npm/%40modelcontextprotocol/server-filesystem@2.3.1",
        "capabilities": {
            "declared": [
                {"evidence": ["ev-001"], "id": "fs:read", "qualifiers": {}, "source": "declared"}
            ],
            "observed": [
                {"evidence": ["ev-002"], "id": "fs:read", "qualifiers": {}, "source": "observed"}
            ],
        },
    }
    untrusted_source_component = {
        "bom-ref": "pkg:npm-malicious/evil@1.0.0",
        "capabilities": clean_component["capabilities"],
    }
    downgrade_component = {
        "bom-ref": "pkg:npm/%40modelcontextprotocol/server-filesystem@2.2.0",
        "capabilities": clean_component["capabilities"],
    }

    fixtures = [
        {
            "dir": "35-policy-03-rule-a-deny",
            "scan_id": "35",
            "component_name": "@modelcontextprotocol/server-fetch",
            "component": deny_component,
            "aibom": {
                "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
                "aibom": {
                    "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
                    "components": [deny_component],
                    "evidence": [
                        {"id": "ev-001", "kind": "mcp-tools-list", "reference": "mcp://fetch/tools/list#http_get"},
                        {"id": "ev-002", "kind": "sandbox-network", "reference": "sandbox://trace/0/connect#api.example.com:443"},
                        {"id": "ev-003", "kind": "sandbox-network", "reference": "sandbox://trace/1/connect#api.untrusted.example:443"},
                        {"id": "ev-policy-000", "kind": "policy-verdict", "reference": "policy://fixture-35/declared-observed-capability-match/policy-03-rule-a-000"},
                    ],
                    "policyVerdicts": [{
                        "id": "policy-03-rule-a-000",
                        "policyId": "declared-observed-capability-match",
                        "bomRef": deny_component["bom-ref"],
                        "status": "deny",
                        "justification": "Observed undeclared core capabilities for pkg:npm/%40modelcontextprotocol/server-fetch@1.2.0: net:egress",
                        "references": ["/aibom/components/0/capabilities/declared", "/aibom/components/0/capabilities/observed"],
                        "evidence": ["ev-policy-000"],
                    }],
                    "scan": {
                        "adapter": {"name": "mcp", "version": "0.1.0"},
                        "scanId": "fixture-35",
                        "timestamp": "2026-04-24T00:00:00Z",
                    },
                    "schemaVersion": "0.1.0",
                },
            },
            "manifest": {
                "name": "35-policy-03-rule-a-deny",
                "kind": "positive",
                "expected": "schema-valid",
                "description": "Policy fixture: explicit core declaration plus observed extra core capability. Policy #3 Rule A emits deny and stores policyVerdicts plus policy-verdict evidence in sidecar.",
                "invariants": ["Q1.a", "Q2.e", "Q3.h", "Q5.ad"],
                "notes": "This fixture is post-policy-evaluation form. validate only checks structural/canonical correctness; policy tests assert verdict semantics.",
            },
        },
        {
            "dir": "36-policy-03-rule-b-warn",
            "scan_id": "36",
            "component_name": "launch-playwright-mcp",
            "component": warn_component,
            "aibom": {
                "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
                "aibom": {
                    "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
                    "components": [warn_component],
                    "evidence": [
                        {"id": "ev-001", "kind": "mcp-tools-list", "reference": "mcp://playwright/tools/list#browser_navigate"},
                        {"id": "ev-002", "kind": "sandbox-process", "reference": "sandbox://fixture-36/exec#env"},
                        {"id": "ev-policy-000", "kind": "policy-verdict", "reference": "policy://fixture-36/declared-observed-capability-match/policy-03-rule-b-000"},
                    ],
                    "policyVerdicts": [{
                        "id": "policy-03-rule-b-000",
                        "policyId": "declared-observed-capability-match",
                        "bomRef": warn_component["bom-ref"],
                        "status": "warn",
                        "justification": "Observed concrete core capabilities for pkg:npm/launch-playwright-mcp@0.0.1 but declarations are only mcp:* stubs: exec:subprocess",
                        "references": ["/aibom/components/0/capabilities/declared", "/aibom/components/0/capabilities/observed"],
                        "evidence": ["ev-policy-000"],
                    }],
                    "scan": {
                        "adapter": {"name": "mcp", "version": "0.1.0"},
                        "scanId": "fixture-36",
                        "timestamp": "2026-04-24T00:00:00Z",
                    },
                    "schemaVersion": "0.1.0",
                },
            },
            "manifest": {
                "name": "36-policy-03-rule-b-warn",
                "kind": "positive",
                "expected": "schema-valid",
                "description": "Policy fixture: declarations are only mcp:* stubs but observed core behavior includes exec:subprocess. Policy #3 Rule B emits warn.",
                "invariants": ["Q1.a", "Q2.e", "Q3.h", "Q5.ad"],
                "notes": "Models launch-playwright-mcp style stub declarations versus concrete observed behavior.",
            },
        },
        {
            "dir": "37-policy-clean-no-verdict",
            "scan_id": "37",
            "component_name": "@modelcontextprotocol/server-filesystem",
            "component": clean_component,
            "aibom": {
                "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
                "aibom": {
                    "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
                    "components": [clean_component],
                    "evidence": [
                        {"id": "ev-001", "kind": "mcp-tools-list", "reference": "mcp://filesystem/tools/list#read_file"},
                        {"id": "ev-002", "kind": "sandbox-syscall", "reference": "sandbox://trace/0/open#READ"},
                    ],
                    "policyVerdicts": [],
                    "scan": {
                        "adapter": {"name": "mcp", "version": "0.1.0"},
                        "scanId": "fixture-37",
                        "timestamp": "2026-04-24T00:00:00Z",
                    },
                    "schemaVersion": "0.1.0",
                },
            },
            "manifest": {
                "name": "37-policy-clean-no-verdict",
                "kind": "positive",
                "expected": "schema-valid",
                "description": "Policy fixture: declared and observed core capabilities match exactly. Post-policy sidecar carries empty policyVerdicts array.",
                "invariants": ["Q1.a", "Q2.e", "Q3.h", "Q5.ad"],
                "notes": "Clean case for policy-engine golden coverage.",
            },
        },
        {
            "dir": "38-policy-02-publisher-allowlist-deny",
            "scan_id": "38",
            "component_name": "@modelcontextprotocol/server-filesystem",
            "component": clean_component,
            "cdx_component": {"publisher": "Untrusted Claimed Publisher", "purl": clean_component["bom-ref"], "version": "2.3.1"},
            "aibom": {
                "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
                "aibom": {
                    "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
                    "components": [clean_component],
                    "evidence": [
                        {"id": "ev-001", "kind": "mcp-tools-list", "reference": "mcp://filesystem/tools/list#read_file"},
                        {"id": "ev-002", "kind": "sandbox-syscall", "reference": "sandbox://trace/0/open#READ"},
                        {"id": "ev-policy-000", "kind": "policy-verdict", "reference": "policy://fixture-38/publisher-allowlist/policy-02-subject-not-allowed"},
                    ],
                    "policyVerdicts": [{
                        "id": "policy-02-subject-not-allowed",
                        "policyId": "publisher-allowlist",
                        "status": "deny",
                        "justification": "Verified publisher subject is not in the configured allowlist: repo:evil/publisher:ref:refs/heads/main",
                        "references": ["/signature/subject", "/config/publisher_allowlist"],
                        "evidence": ["ev-policy-000"],
                    }],
                    "scan": {"adapter": {"name": "mcp", "version": "0.1.0"}, "scanId": "fixture-38", "timestamp": "2026-04-24T00:00:00Z"},
                    "schemaVersion": "0.1.0",
                },
            },
            "manifest": {
                "name": "38-policy-02-publisher-allowlist-deny",
                "kind": "positive",
                "expected": "schema-valid",
                "description": "Policy fixture: verified signature subject is outside configured publisher allowlist. Policy #2 emits deny.",
                "invariants": ["Q1.a", "Q2.e", "Q3.h", "Q5.ad"],
                "notes": "Claimed CycloneDX publisher is intentionally not trusted as publisher evidence.",
            },
        },
        {
            "dir": "39-policy-05-maximum-scan-age-deny",
            "scan_id": "39",
            "component_name": "@modelcontextprotocol/server-filesystem",
            "component": clean_component,
            "cdx_component": {"purl": clean_component["bom-ref"], "version": "2.3.1"},
            "aibom": {
                "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
                "aibom": {
                    "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
                    "components": [clean_component],
                    "evidence": [
                        {"id": "ev-001", "kind": "mcp-tools-list", "reference": "mcp://filesystem/tools/list#read_file"},
                        {"id": "ev-002", "kind": "sandbox-syscall", "reference": "sandbox://trace/0/open#READ"},
                        {"id": "ev-policy-000", "kind": "policy-verdict", "reference": "policy://fixture-39/maximum-scan-age/policy-05-scan-too-old"},
                    ],
                    "policyVerdicts": [{
                        "id": "policy-05-scan-too-old",
                        "policyId": "maximum-scan-age",
                        "status": "deny",
                        "justification": "AIBOM scan is older than configured maximum age: 172800 seconds > 86400 seconds",
                        "references": ["/aibom/scan/timestamp", "/config/max_scan_age_seconds", "/config/policy_time"],
                        "evidence": ["ev-policy-000"],
                    }],
                    "scan": {"adapter": {"name": "mcp", "version": "0.1.0"}, "scanId": "fixture-39", "timestamp": "2026-04-20T00:00:00Z"},
                    "schemaVersion": "0.1.0",
                },
            },
            "manifest": {
                "name": "39-policy-05-maximum-scan-age-deny",
                "kind": "positive",
                "expected": "schema-valid",
                "description": "Policy fixture: scan timestamp is older than configured maximum age. Policy #5 emits deny.",
                "invariants": ["Q1.a", "Q2.e", "Q3.h", "Q5.ad"],
                "notes": "Uses aibom.scan.timestamp, the canonical v0.1 scan timestamp field.",
            },
        },
        {
            "dir": "40-policy-08-trusted-package-source-deny",
            "scan_id": "40",
            "component_name": "evil",
            "component": untrusted_source_component,
            "cdx_component": {"purl": untrusted_source_component["bom-ref"], "version": "1.0.0"},
            "aibom": {
                "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
                "aibom": {
                    "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
                    "components": [untrusted_source_component],
                    "evidence": [
                        {"id": "ev-001", "kind": "mcp-tools-list", "reference": "mcp://evil/tools/list#read_file"},
                        {"id": "ev-002", "kind": "sandbox-syscall", "reference": "sandbox://trace/0/open#READ"},
                        {"id": "ev-policy-000", "kind": "policy-verdict", "reference": "policy://fixture-40/trusted-package-source/policy-08-000"},
                    ],
                    "policyVerdicts": [{
                        "id": "policy-08-000",
                        "policyId": "trusted-package-source",
                        "bomRef": untrusted_source_component["bom-ref"],
                        "status": "deny",
                        "justification": "Package source for pkg:npm-malicious/evil@1.0.0 is outside configured trusted sources",
                        "references": ["/aibom/components/0/bom-ref", "/config/trusted_package_sources"],
                        "evidence": ["ev-policy-000"],
                    }],
                    "scan": {"adapter": {"name": "mcp", "version": "0.1.0"}, "scanId": "fixture-40", "timestamp": "2026-04-24T00:00:00Z"},
                    "schemaVersion": "0.1.0",
                },
            },
            "manifest": {
                "name": "40-policy-08-trusted-package-source-deny",
                "kind": "positive",
                "expected": "schema-valid",
                "description": "Policy fixture: prefix-spoofed PURL type pkg:npm-malicious is not trusted by a pkg:npm source allowlist. Policy #8 emits deny.",
                "invariants": ["Q1.a", "Q2.e", "Q3.h", "Q5.ad"],
                "notes": "Policy compares normalized PURL source prefixes and avoids prefix-spoof matches.",
            },
        },
        {
            "dir": "41-policy-09-no-version-downgrade-deny",
            "scan_id": "41",
            "component_name": "@modelcontextprotocol/server-filesystem",
            "component": downgrade_component,
            "cdx_component": {"purl": downgrade_component["bom-ref"], "version": "2.2.0"},
            "aibom": {
                "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
                "aibom": {
                    "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
                    "components": [downgrade_component],
                    "evidence": [
                        {"id": "ev-001", "kind": "mcp-tools-list", "reference": "mcp://filesystem/tools/list#read_file"},
                        {"id": "ev-002", "kind": "sandbox-syscall", "reference": "sandbox://trace/0/open#READ"},
                        {"id": "ev-policy-000", "kind": "policy-verdict", "reference": "policy://fixture-41/no-version-downgrade/policy-09-000"},
                    ],
                    "policyVerdicts": [{
                        "id": "policy-09-000",
                        "policyId": "no-version-downgrade",
                        "bomRef": downgrade_component["bom-ref"],
                        "status": "deny",
                        "justification": "Package pkg:npm/%40modelcontextprotocol/server-filesystem version 2.2.0 is below configured minimum 2.3.1",
                        "references": ["/aibom/components/0/bom-ref", "/config/minimum_package_versions/pkg:npm/%40modelcontextprotocol/server-filesystem"],
                        "evidence": ["ev-policy-000"],
                    }],
                    "scan": {"adapter": {"name": "mcp", "version": "0.1.0"}, "scanId": "fixture-41", "timestamp": "2026-04-24T00:00:00Z"},
                    "schemaVersion": "0.1.0",
                },
            },
            "manifest": {
                "name": "41-policy-09-no-version-downgrade-deny",
                "kind": "positive",
                "expected": "schema-valid",
                "description": "Policy fixture: current package version is below configured minimum version floor. Policy #9 emits deny.",
                "invariants": ["Q1.a", "Q2.e", "Q3.h", "Q5.ad"],
                "notes": "Minimum-version key omits version segment from the PURL so historical state remains stable across scans.",
            },
        },

    ]

    for spec in fixtures:
        write_positive_policy_fixture(spec)


# ---------------------------------------------------------------------------
# Sensitive-data report fixtures

def normalize_sensitive_data_report_fixtures():
    print(f"Normalizing sensitive-data fixtures at {SENSITIVE_DATA_ROOT}")
    print()
    for path in sorted(SENSITIVE_DATA_ROOT.rglob("*.json")):
        data = json.loads(path.read_bytes())
        path.write_bytes(jcs_bytes(data))
        print(f"  OK   {path.relative_to(SENSITIVE_DATA_ROOT.parent)}")

def normalize_secret_rule_pack_fixtures():
    print(f"Normalizing secret-rule-pack fixtures at {SECRET_RULE_PACK_ROOT}")
    print()
    for path in sorted(SECRET_RULE_PACK_ROOT.rglob("*.json")):
        data = json.loads(path.read_bytes())
        path.write_bytes(jcs_bytes(data))
        print(f"  OK   {path.relative_to(SECRET_RULE_PACK_ROOT.parent)}")


# ---------------------------------------------------------------------------
# Entry point

def main():
    print(f"Regenerating fixtures at {ROOT}")
    print()
    for cfg in FIXTURES:
        regenerate(cfg)
    print()
    print("Creating fixture 28 ...")
    create_fixture_28()
    print()
    print("Creating policy fixtures 35-41 ...")
    create_policy_fixtures()
    print()
    normalize_sensitive_data_report_fixtures()
    print()
    normalize_secret_rule_pack_fixtures()
    print()
    print("Done.")


if __name__ == "__main__":
    main()
