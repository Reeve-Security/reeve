#!/usr/bin/env python3
"""Contract check for the repository private/ boundary protections."""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

REQUIRED_GITIGNORE = [
    "/private/",
    "*.aibom.json",
    "!schema/fixtures/aibom-v0.1.0/**/*.aibom.json",
    "!schema/fixtures/aibom-v0.2.0/**/*.aibom.json",
    "!schema/fixtures/aibom-v0.3.0/**/*.aibom.json",
    "*.cdx.json",
    "!schema/fixtures/aibom-v0.1.0/**/*.cdx.json",
    "!schema/fixtures/aibom-v0.2.0/**/*.cdx.json",
    "!schema/fixtures/aibom-v0.3.0/**/*.cdx.json",
    "*.sigstore.json",
    "!schema/fixtures/aibom-v0.1.0/**/*.sigstore.json",
    "!schema/fixtures/aibom-v0.2.0/**/*.sigstore.json",
    "!schema/fixtures/aibom-v0.3.0/**/*.sigstore.json",
    "*.tfstate",
    "*.tfstate.*",
    "inventory.yml",
]
REQUIRED_CONTRIBUTING = [
    "`tools/` is reusable open-source machinery",
    "`private/` is internal-only forever",
]
REQUIRED_TOOLS_README = [
    "`tools/` holds reusable open-source deployment helpers",
    "Do not commit local run output",
]
REQUIRED_GITLEAKS = [
    "useDefault = true",
    'id = "github-token-extended"',
]
REQUIRED_CI = [
    "gitleaks:",
    "Install gitleaks",
    "--report-format json",
    "--report-path",
    "--verbose",
    "Upload gitleaks report",
    "GITHUB_STEP_SUMMARY",
    "secret_redacted=",
    'gitleaks dir "${tmp_dir}"',
    "gitleaks found potential leaks",
    "gitleaks finding: rule=",
    "gitleaks positive control",
    "expected gitleaks to reject fake GitHub token",
    "private boundary contract",
    "python3 scripts/check-private-boundary.py",
]


def require_text(path: pathlib.Path, needles: list[str]) -> None:
    text = path.read_text()
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"{path.relative_to(ROOT)}: missing expected text: {needle}")


def main() -> int:
    require_text(ROOT / ".gitignore", REQUIRED_GITIGNORE)
    require_text(ROOT / ".gitleaks.toml", REQUIRED_GITLEAKS)
    require_text(ROOT / "CONTRIBUTING.md", REQUIRED_CONTRIBUTING)
    require_text(ROOT / "tools" / "README.md", REQUIRED_TOOLS_README)
    require_text(ROOT / ".github" / "workflows" / "ci.yml", REQUIRED_CI)

    private_history = subprocess.run(
        ["git", "log", "--all", "--oneline", "--", "private/"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    if private_history.stdout.strip():
        raise SystemExit("private/: expected empty git history")

    print("private boundary contract OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
