#!/usr/bin/env python3
"""Static contract checks for signed surface-config support."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(path: str, needle: str) -> None:
    haystack = (ROOT / path).read_text()
    if needle not in haystack:
        raise SystemExit(f"{path} missing required text: {needle}")


def main() -> None:
    require(".github/workflows/ci.yml", "surface config signing contract")
    require("crates/aibom-cli/src/main.rs", "require_signed_config")
    require("crates/aibom-cli/src/main.rs", "signer_identity_regexp")
    require("crates/aibom-cli/src/main.rs", "\"verify-blob\"")
    require(
        "crates/aibom-cli/src/main.rs",
        "REEVE_ACCEPT_FIXTURE_SURFACE_CONFIG_SIGNATURE",
    )
    require(
        "crates/aibom-cli/tests/cli_e2e.rs",
        "tampered_surface_config_signature_fails_hash_check",
    )
    require("scripts/build-surface-config-bundle-fixture.py", "surfaces.provenance.json")
    require("docs/decisions/README.md", "ADR-0013: System-wide surface configs")
    require("docs/decisions/0013-signed-surface-config-bundles.md", "fail closed")
    require("docs/signing.md", "Surface-config bundles")
    print("surface config signing contract OK")


if __name__ == "__main__":
    main()
