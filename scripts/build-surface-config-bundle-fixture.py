#!/usr/bin/env python3
"""Build an offline fixture Sigstore bundle for a Reeve surface config.

This is for tests, demos, and documentation. Production bundles should be
created with cosign keyless signing and verified by Reeve via cosign.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path


PREDICATE_TYPE = "https://aibom.example/attestation/surface-config/v0.1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("config", type=Path)
    parser.add_argument("--signer-subject", required=True)
    parser.add_argument(
        "--signer-issuer", default="https://token.actions.githubusercontent.com"
    )
    args = parser.parse_args()

    config = args.config
    config_hash = sha256(config)
    statement = {
        "_type": STATEMENT_TYPE,
        "predicateType": PREDICATE_TYPE,
        "subject": [
            {"name": config.name, "digest": {"sha256": config_hash}},
        ],
        "predicate": {
            "artifactRole": "surface-config",
            "configFormat": "reeve-custom-surfaces-v0.1",
        },
    }
    payload = base64.b64encode(
        json.dumps(statement, separators=(",", ":"), sort_keys=True).encode()
    ).decode()
    bundle = {
        "mediaType": MEDIA_TYPE,
        "verificationMaterial": {
            "_fixture_note": "reeve surface-config fixture",
            "certificate": {
                "rawBytes": "FIXTURE_SURFACE_CONFIG_CERT",
                "oidcIssuer": args.signer_issuer,
                "oidcSubject": args.signer_subject,
            },
            "tlogEntries": [
                {
                    "_fixture_note": "placeholder Rekor v2 dsse entry",
                    "kindVersion": {"kind": "dsse", "version": "0.0.1"},
                }
            ],
        },
        "dsseEnvelope": {
            "payload": payload,
            "payloadType": PAYLOAD_TYPE,
            "signatures": [{"sig": "FIXTURE_SURFACE_CONFIG_SIGNATURE"}],
        },
    }
    bundle_path = config.with_name(f"{config.name}.sigstore.json")
    provenance_path = config.with_name("surfaces.provenance.json")
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    provenance = {
        "schemaVersion": "reeve-surface-config-provenance-v0.1",
        "config": {"path": config.name, "sha256": config_hash},
        "signature": {"path": bundle_path.name, "sha256": sha256(bundle_path)},
        "signer": {
            "oidcIssuer": args.signer_issuer,
            "oidcSubject": args.signer_subject,
        },
        "mode": "fixture",
    }
    provenance_path.write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    print(f"wrote {bundle_path}")
    print(f"wrote {provenance_path}")


if __name__ == "__main__":
    main()
