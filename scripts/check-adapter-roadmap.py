#!/usr/bin/env python3
"""Static guard for adapter expansion roadmap (#34)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROADMAP = ROOT / "docs" / "adapter-roadmap.md"
SCOPE = ROOT / "docs" / "scope.md"
README = ROOT / "README.md"
CI = ROOT / ".github" / "workflows" / "ci.yml"

REQUIRED_ROADMAP_TERMS = [
    "Issue #34",
    "v1 ships exactly one protocol adapter",
    "MCP",
    "Cloud-config adapters",
    "Framework-introspection adapters",
    "Vendor-desktop adapters",
    "In-house/custom surfaces",
    "Bedrock Agents",
    "LangChain registry",
    "Cloud-config adapter ADR",
    "Framework-introspection ADR",
    "Default local scans must stay offline",
    "docs/scope.md update requirement",
    "reeve scope list",
    "three-layer rule",
]

REQUIRED_SCOPE_TERMS = [
    "Adapter expansion roadmap",
    "docs/adapter-roadmap.md",
    "v0.2+",
]

REQUIRED_README_TERMS = [
    "docs/adapter-roadmap.md",
    "post-v0.1 adapter expansion",
]

FORBIDDEN_PROMISES = [
    "v1 ships Bedrock",
    "v1 ships LangChain",
    "cloud scans are enabled by default",
    "policy engine reads adapter internals",
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
            f"{path.relative_to(ROOT)} missing adapter roadmap terms:\n"
            + "\n".join(f"  - {term}" for term in missing)
        )


def reject_forbidden(path: Path) -> None:
    text = read(path)
    hits = [term for term in FORBIDDEN_PROMISES if term in text]
    if hits:
        fail(
            f"{path.relative_to(ROOT)} contains forbidden adapter roadmap promise:\n"
            + "\n".join(f"  - {term}" for term in hits)
        )


def main() -> None:
    require(ROADMAP, REQUIRED_ROADMAP_TERMS)
    require(SCOPE, REQUIRED_SCOPE_TERMS)
    require(README, REQUIRED_README_TERMS)
    require(CI, ["python3 scripts/check-adapter-roadmap.py"])
    reject_forbidden(ROADMAP)
    print("adapter roadmap contract OK")


if __name__ == "__main__":
    main()
