#!/usr/bin/env python3
"""Assert denied rigged-profile evidence for macOS Tart lab runs."""

from __future__ import annotations

import json
import pathlib
import sys


def fail(message: str) -> None:
    raise SystemExit(message)


def has_evidence(records: list[object], kind: str, needles: tuple[str, ...]) -> bool:
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("kind") != kind:
            continue
        reference = str(record.get("reference", ""))
        if any(needle in reference for needle in needles):
            return True
    return False


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: assert-rigged-profile.py <aibom.json>")

    aibom = json.loads(pathlib.Path(sys.argv[1]).read_text())
    evidence = aibom.get("aibom", {}).get("evidence")
    if not isinstance(evidence, list):
        fail("AIBOM missing top-level evidence array")

    if not has_evidence(
        evidence,
        "sandbox-filesystem",
        ("etc/passwd:READ",),
    ):
        fail("rigged profile missing denied filesystem evidence for passwd read")

    if not has_evidence(
        evidence,
        "sandbox-network",
        ("connect#-:80",),
    ):
        fail("rigged profile missing denied network evidence for rigged egress")

    print("rigged macOS profile assertion OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
