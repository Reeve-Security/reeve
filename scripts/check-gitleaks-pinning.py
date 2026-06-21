#!/usr/bin/env python3
"""Assert the CI gitleaks version is pinned in one repo-owned place and the CI
workflow reads it instead of hardcoding a version literal (#35).

This needs no gitleaks binary: it is a static drift check, so the merge gate can
run it locally while gitleaks itself stays a remote-only required check.

Checks:
  1. .gitleaks-version exists and is a single valid X.Y.Z semver.
  2. The ci.yml gitleaks job sources the version from .gitleaks-version and
     contains no hardcoded gitleaks version literal (no VERSION="X.Y.Z" and no
     gitleaks release-download URL with an inline numeric version), so the
     version cannot drift back inline.

Usage:
  check-gitleaks-pinning.py            # check the repo
  check-gitleaks-pinning.py --self-test
"""

from __future__ import annotations

import contextlib
import io
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VERSION_FILE = REPO_ROOT / ".gitleaks-version"
CI_FILE = REPO_ROOT / ".github" / "workflows" / "ci.yml"

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
# A hardcoded gitleaks version literal we must NOT find in the gitleaks job:
#   VERSION="8.24.2"   or   gitleaks/releases/download/v8.24.2/...
HARDCODED_VERSION_ASSIGN = re.compile(r'VERSION\s*=\s*"\d+\.\d+\.\d+"')
HARDCODED_DOWNLOAD_VERSION = re.compile(
    r"gitleaks/releases/download/v\d+\.\d+\.\d+"
)
READS_VERSION_FILE = re.compile(r"\.gitleaks-version")


def _fail(msg: str) -> None:
    print(f"check-gitleaks-pinning: FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def check_version_file_text(text: str) -> str:
    value = text.strip()
    if not value:
        _fail(".gitleaks-version is empty")
    if "\n" in value:
        _fail(".gitleaks-version must contain a single version line")
    if not SEMVER_RE.match(value):
        _fail(f".gitleaks-version must be X.Y.Z (got {value!r})")
    return value


def _gitleaks_job_text(ci_text: str) -> str:
    """Return the text of the `gitleaks:` job block (best-effort, indentation
    based) so the no-hardcode assertion is scoped to that job."""
    lines = ci_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^  gitleaks:\s*$", line):
            start = i
            break
    if start is None:
        _fail("no `gitleaks:` job found in ci.yml")
    end = len(lines)
    for j in range(start + 1, len(lines)):
        # next top-level job (two-space indent, `name:`-style key) ends the block
        if re.match(r"^  \S", lines[j]):
            end = j
            break
    return "\n".join(lines[start:end])


def check_ci_text(ci_text: str) -> None:
    job = _gitleaks_job_text(ci_text)
    if not READS_VERSION_FILE.search(job):
        _fail("ci.yml gitleaks job does not read the version from .gitleaks-version")
    if HARDCODED_VERSION_ASSIGN.search(job):
        _fail('ci.yml gitleaks job hardcodes VERSION="X.Y.Z"; read .gitleaks-version instead')
    if HARDCODED_DOWNLOAD_VERSION.search(job):
        _fail("ci.yml gitleaks job hardcodes a versioned download URL; build it from .gitleaks-version")


def check_repo() -> None:
    if not VERSION_FILE.is_file():
        _fail(f"missing {VERSION_FILE.name}")
    version = check_version_file_text(VERSION_FILE.read_text())
    if not CI_FILE.is_file():
        _fail("missing .github/workflows/ci.yml")
    check_ci_text(CI_FILE.read_text())
    print(f"check-gitleaks-pinning: OK (gitleaks pinned to {version} via .gitleaks-version)")


def _expect_reject(fn, *args, what: str) -> None:
    """Call fn(*args), expecting it to _fail (SystemExit). Swallow its stderr so
    the merge gate output stays clean."""
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            fn(*args)
        except SystemExit:
            return
    raise AssertionError(f"expected reject: {what}")


def self_test() -> None:
    # version-file parsing
    assert check_version_file_text("8.24.2\n") == "8.24.2"
    for bad in ("", "  ", "8.24", "v8.24.2", "8.24.2\n8.25.0", "latest"):
        _expect_reject(check_version_file_text, bad, what=f"version {bad!r}")

    good_ci = (
        "jobs:\n"
        "  gitleaks:\n"
        "    steps:\n"
        '      - run: VERSION="$(tr -d \'[:space:]\' < .gitleaks-version)"\n'
        '      - run: curl -L gitleaks/releases/download/v${VERSION}/x.tar.gz\n'
        "  other:\n"
        '      - run: VERSION="9.9.9"\n'  # hardcode in a DIFFERENT job must not trip us
    )
    check_ci_text(good_ci)  # must pass

    bad_assign = (
        "jobs:\n"
        "  gitleaks:\n"
        "    steps:\n"
        '      - run: VERSION="8.24.2"\n'
        '      - run: curl -L gitleaks/releases/download/v${VERSION}/x.tar.gz < .gitleaks-version\n'
    )
    _expect_reject(check_ci_text, bad_assign, what="hardcoded VERSION assign")

    bad_no_read = (
        "jobs:\n"
        "  gitleaks:\n"
        "    steps:\n"
        '      - run: VERSION="$(somewhere-else)"\n'
    )
    _expect_reject(check_ci_text, bad_no_read, what="does not read .gitleaks-version")

    print("check-gitleaks-pinning self-test OK")


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        self_test()
        return 0
    check_repo()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
