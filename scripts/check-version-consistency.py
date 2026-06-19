#!/usr/bin/env python3
"""Single source of truth for the Reeve version sync set.

The workspace version lives in Cargo.toml ([workspace.package] version). Several
other locations must repeat that exact version, and they drift silently. This
check reads the Cargo.toml version once and asserts every dependent location
matches, failing with a per-location message on drift so the fix is obvious.

Sync set checked here:
  - Cargo.lock pins for the 6 workspace crates
  - README.md verify-download examples (TAG=v<ver> and $TAG = "v<ver>")
  - crates/aibom-policy/bundles/<ver>.{wasm,json,provenance.json} all present

scripts/release-gate.sh delegates the lock/README/bundle checks to this script
rather than duplicating the logic; scripts/merge-gate.sh runs it on every PR.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

WORKSPACE_CRATES = [
    "aibom-core",
    "aibom-cli",
    "aibom-scanner",
    "aibom-signer",
    "aibom-validator",
    "aibom-policy",
]


def fail(message: str) -> None:
    raise SystemExit(f"check-version-consistency: FAIL: {message}")


def workspace_version() -> str:
    """Read [workspace.package] version from Cargo.toml."""
    text = (ROOT / "Cargo.toml").read_text()
    in_workspace_package = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_workspace_package = stripped == "[workspace.package]"
            continue
        if in_workspace_package:
            match = re.match(r'^version\s*=\s*"([^"]+)"\s*$', stripped)
            if match:
                return match.group(1)
    fail("could not read [workspace.package] version from Cargo.toml")
    raise AssertionError("unreachable")


def check_cargo_lock(version: str) -> None:
    """Each workspace crate's [[package]] block must pin `version`."""
    lock_text = (ROOT / "Cargo.lock").read_text()
    for crate in WORKSPACE_CRATES:
        locked = lock_package_version(lock_text, crate)
        if locked is None:
            fail(f"Cargo.lock has no [[package]] entry for {crate}")
        if locked != version:
            fail(
                f"Cargo.lock pins {crate} at '{locked}', expected '{version}' "
                "(run 'cargo update -w')"
            )
    print(f"    ok: Cargo.lock pins all {len(WORKSPACE_CRATES)} workspace crates to {version}")


def lock_package_version(lock_text: str, crate: str) -> str | None:
    """Find the version field inside the [[package]] block named `crate`."""
    in_target_block = False
    for line in lock_text.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            in_target_block = False
            continue
        if stripped == f'name = "{crate}"':
            in_target_block = True
            continue
        if in_target_block:
            match = re.match(r'^version = "([^"]+)"$', stripped)
            if match:
                return match.group(1)
    return None


def check_readme(version: str) -> None:
    """README verify-download TAG=v<ver> and $TAG = "v<ver>" must match.

    Only those two anchored assignment forms are checked, not every incidental
    v0.x.y mention in the README.
    """
    readme_text = (ROOT / "README.md").read_text()
    lines = readme_text.splitlines()
    bash_form = f"TAG=v{version}"
    ps_form = f'$TAG = "v{version}"'
    if not any(line.strip() == bash_form for line in lines):
        fail(
            f"README.md missing verify-download bash example line '{bash_form}' "
            "(run 'scripts/bump-version.sh <X.Y.Z>')"
        )
    if not any(line.strip() == ps_form for line in lines):
        fail(
            f"README.md missing verify-download powershell example line '{ps_form}' "
            "(run 'scripts/bump-version.sh <X.Y.Z>')"
        )
    print(f"    ok: README.md verify-download examples reference v{version}")


def check_policy_bundle(version: str) -> None:
    """The policy bundle triplet for this version must exist."""
    bundles = ROOT / "crates" / "aibom-policy" / "bundles"
    for ext in ("wasm", "json", "provenance.json"):
        path = bundles / f"{version}.{ext}"
        if not path.is_file():
            fail(
                f"missing policy bundle file {path.relative_to(ROOT)} "
                "(run 'scripts/build-policy-bundle.sh --write')"
            )
    print(f"    ok: policy bundle triplet present for {version}")


def main() -> None:
    version = workspace_version()
    print(f"==> version consistency for workspace version {version}")
    check_cargo_lock(version)
    check_readme(version)
    check_policy_bundle(version)
    print(f"check-version-consistency: OK ({version})")


if __name__ == "__main__":
    main()
