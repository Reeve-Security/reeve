#!/usr/bin/env python3
"""Drift-guard for GitHub Actions supply-chain hardening.

Two contracts, both checked against the committed workflows:

1. Every THIRD-PARTY action reference (`owner/repo@ref`, optionally with a
   subdirectory like `owner/repo/path@ref`) MUST be pinned to a full 40-hex
   commit SHA. Tag refs (e.g. `@v4`) and branch refs are rejected: a moving
   ref lets the action's code change out from under us between runs. Local
   actions (`./...`) and reusable workflows referenced by local path are NOT
   third-party and are always allowed.

2. `release.yml` is cargo-dist generated; regenerating it re-widens the
   top-level `permissions` to `contents: write`. The release only needs that
   write scope inside the `host` job, so we assert the top-level block does
   NOT grant `contents: write`. This catches regeneration drift.
"""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"

# `uses:` value, capturing the reference (quotes optional). We only inspect
# the captured target; whether it is third-party is decided below.
USES_RE = re.compile(r"""^\s*-?\s*uses:\s*["']?([^"'\s#]+)["']?""")

# A third-party action is `owner/repo` or `owner/repo/sub/dir`, followed by
# `@ref`. Local actions start with `./` or `../` and never match this.
THIRD_PARTY_RE = re.compile(r"^[^./][^/]*/[^/@]+(?:/[^@]+)?@(?P<ref>.+)$")

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _is_local(ref: str) -> bool:
    return ref.startswith("./") or ref.startswith("../") or ref.startswith("/")


def check_pinning() -> list[str]:
    errors: list[str] = []
    for workflow in sorted(WORKFLOW_DIR.glob("*.yml")):
        rel = workflow.relative_to(ROOT)
        for lineno, line in enumerate(workflow.read_text().splitlines(), start=1):
            match = USES_RE.match(line)
            if not match:
                continue
            target = match.group(1)
            if _is_local(target):
                continue
            tp = THIRD_PARTY_RE.match(target)
            if not tp:
                # Not an `owner/repo@ref` third-party form (e.g. a Docker
                # image ref or an odd local path); leave it for humans.
                continue
            ref = tp.group("ref")
            if not SHA_RE.match(ref):
                errors.append(
                    f"{rel}:{lineno}: third-party action not pinned to a "
                    f"40-hex SHA: uses: {target}"
                )
    return errors


def check_release_permissions() -> list[str]:
    release = WORKFLOW_DIR / "release.yml"
    if not release.exists():
        return [f"{release.relative_to(ROOT)}: missing"]
    errors: list[str] = []
    lines = release.read_text().splitlines()
    # Find the top-level (column-0) `permissions:` block. Job-level blocks are
    # indented, so they are not column-0 and are not inspected here.
    in_top_perms = False
    for lineno, line in enumerate(lines, start=1):
        if re.match(r"^permissions:\s*$", line):
            in_top_perms = True
            continue
        if in_top_perms:
            # The block ends at the next column-0 key.
            if line and not line[0].isspace():
                in_top_perms = False
                continue
            normalized = line.replace('"', "").replace("'", "").strip()
            normalized = re.sub(r"\s+", " ", normalized)
            if normalized == "contents: write":
                errors.append(
                    f"{release.relative_to(ROOT)}:{lineno}: top-level "
                    f"permissions must not grant 'contents: write' "
                    f"(cargo-dist regeneration drift); the host job grants it "
                    f"at job level instead"
                )
    return errors


def main() -> None:
    errors = check_pinning() + check_release_permissions()
    if errors:
        for err in errors:
            print(f"workflow-pinning: {err}")
        raise SystemExit(
            f"workflow-pinning: FAIL: {len(errors)} hardening violation(s)"
        )
    print("workflow pinning + release permissions contract OK")


if __name__ == "__main__":
    main()
