#!/usr/bin/env python3
"""Static guard for issue #11 native sigstore-rs deferral.

This is intentionally offline. It does not decide whether upstream sigstore-rs
is mature today; it ensures Reeve's migration gate stays documented and wired
into CI until an explicit follow-up issue replaces the cosign backend.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESEARCH = ROOT / "docs" / "research" / "sigstore-rs-maturity.md"
ADR = ROOT / "docs" / "decisions" / "0006-cosign-dependency-strategy.md"
SIGNING = ROOT / "docs" / "signing.md"
CI = ROOT / ".github" / "workflows" / "ci.yml"
DEPLOYMENT = ROOT / "docs" / "deployment-scenarios.md"

REQUIRED_RESEARCH_TERMS = [
    "Issue #11",
    "DSSE envelope",
    "in-toto Statement",
    "Bundle v0.3",
    "Rekor v2 dsse",
    "GitHub Actions OIDC",
    "Failure behavior",
    "fail closed",
    "cargo info sigstore",
    "Released version observed",
]

REQUIRED_ADR_TERMS = [
    "docs/research/sigstore-rs-maturity.md",
    "GitHub issue #11",
    "DSSE",
    "Rekor v2",
    "bundle v0.3",
]

REQUIRED_SIGNING_TERMS = [
    "Native sigstore-rs migration gate",
    "docs/research/sigstore-rs-maturity.md",
    "cosign",
]

STALE_PROMISES = [
    "task #17",
    "Until v0.1.x ships native sigstore-rs",
    "v0.1.x roadmap has a task",
    "This friction point disappears in v0.1.x",
]

STALE_SCAN_PATHS = [
    ADR,
    SIGNING,
    DEPLOYMENT,
]


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def read(path: Path) -> str:
    if not path.exists():
        fail(f"missing file: {path.relative_to(ROOT)}")
    return path.read_text()


def require(path: Path, terms: list[str]) -> None:
    text = read(path)
    missing = [term for term in terms if term not in text]
    if missing:
        fail(
            f"{path.relative_to(ROOT)} missing sigstore-rs migration terms:\n"
            + "\n".join(f"  - {term}" for term in missing)
        )


def reject_stale_promises(paths: list[Path]) -> None:
    hits: list[str] = []
    for path in paths:
        text = read(path)
        for term in STALE_PROMISES:
            if term in text:
                hits.append(f"{path.relative_to(ROOT)}: {term}")
    if hits:
        fail(
            "stale native sigstore-rs promise found; use issue #11 maturity gate instead:\n"
            + "\n".join(f"  - {hit}" for hit in hits)
        )


def main() -> None:
    require(RESEARCH, REQUIRED_RESEARCH_TERMS)
    require(ADR, REQUIRED_ADR_TERMS)
    require(SIGNING, REQUIRED_SIGNING_TERMS)
    require(CI, ["python3 scripts/check-sigstore-rs-deferral.py"])
    reject_stale_promises(STALE_SCAN_PATHS)
    print("sigstore-rs deferral contract OK")


if __name__ == "__main__":
    main()
