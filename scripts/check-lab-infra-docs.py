#!/usr/bin/env python3
"""Static contract checks for issue #29 lab docs/tooling."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "lab-infra.md"
ARCHETYPES = ROOT / "docs" / "demo-archetypes.md"
TOOL = ROOT / "tools" / "lab" / "aggregate.sh"
README = ROOT / "tools" / "lab" / "README.md"

REQUIRED_DOC_TERMS = [
    "ephemeral self-hosted CI",
    "ephemeral job VM",
    "No long-lived credentials",
    "Fork PRs",
    "Tagged releases",
    "Packer",
    "libvirt",
    "Tart",
    "No HTTP service",
    "No database",
    "tools/lab/",
    "Windows support is in scope",
]

REQUIRED_TOOL_TERMS = [
    "*.aibom.json",
    "no network",
    "no DB",
    "policyVerdicts",
    "capabilities",
    "is_symlink",
    "MAX_AIBOM_BYTES",
]

REQUIRED_ARCHETYPE_TERMS = [
    "45-endpoint",
    "macOS",
    "Linux",
    "Windows",
    "dev-cursor-claude-mcp-clean",
    "dev-codex-vscode-loose",
    "dev-shadow-stack",
    "dev-stale-config",
    "dev-prod-leakage",
    "dev-overgranted",
    "dev-shadow-mcp-server",
    "hr-claude-resume-screening",
    "accounting-codex-spreadsheet",
    "marketing-claude-image-gen",
    "sales-cursor-crm-scripts",
    "legal-claude-document-review",
    "33%",
    "surfaces.yaml.sigstore.json",
    "telemetry-gap",
    "tools/lab/aggregate.sh",
    "AppContainer",
]


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def require_terms(path: Path, terms: list[str]) -> None:
    if not path.exists():
        fail(f"missing required lab file: {path.relative_to(ROOT)}")
    text = path.read_text()
    missing = [term for term in terms if term not in text]
    if missing:
        fail(
            f"{path.relative_to(ROOT)} missing required lab terms:\n"
            + "\n".join(f"  - {term}" for term in missing)
        )


def require_executable(path: Path) -> None:
    if not os.access(path, os.X_OK):
        fail(f"lab tool must be executable: {path.relative_to(ROOT)}")


def run_aggregate_smoke() -> None:
    result = subprocess.run(
        [str(TOOL), str(ROOT / "schema" / "examples" / "fixtures" / "policy")],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        fail(f"aggregate smoke failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    for expected in ["# Reeve lab aggregate", "Artifacts scanned:", "Policy verdicts", "deny:"]:
        if expected not in result.stdout:
            fail(f"aggregate smoke output missing: {expected}")


def run_symlink_smoke() -> None:
    fixture = ROOT / "schema" / "examples" / "fixtures" / "policy" / "38-policy-02-publisher-allowlist-deny" / "fixture-38.aibom.json"
    with tempfile.TemporaryDirectory() as tmp:
        link = Path(tmp) / "linked.aibom.json"
        link.symlink_to(fixture)
        result = subprocess.run(
            [str(TOOL), tmp],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if result.returncode != 0:
        fail(f"aggregate symlink smoke failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    if "Artifacts scanned: 0" not in result.stdout:
        fail("aggregate symlink smoke did not skip symlinked AIBOM")


def main() -> None:
    require_terms(DOC, REQUIRED_DOC_TERMS)
    require_terms(ARCHETYPES, REQUIRED_ARCHETYPE_TERMS)
    require_terms(TOOL, REQUIRED_TOOL_TERMS)
    require_terms(
        README,
        [
            "aggregate.sh",
            "*.aibom.json",
            "No network access",
            "Symlinked artifacts",
            "20 MiB",
            "docs/demo-archetypes.md",
            "test-vps/",
            "issue #62",
        ],
    )
    require_executable(TOOL)
    run_aggregate_smoke()
    run_symlink_smoke()
    print("lab infra docs/tooling contract OK")


if __name__ == "__main__":
    main()
