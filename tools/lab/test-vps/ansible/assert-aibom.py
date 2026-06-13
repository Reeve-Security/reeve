#!/usr/bin/env python3
"""Small profile assertion helper for lab AIBOM outputs."""

from __future__ import annotations

import json
import pathlib
import sys
from collections.abc import Iterator


def walk(value: object) -> Iterator[object]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: assert-aibom.py <aibom.json> <expected-json>")

    aibom = json.loads(pathlib.Path(sys.argv[1]).read_text())
    expected = json.loads(sys.argv[2])
    scalars = [str(item) for item in walk(aibom) if isinstance(item, (str, int, float, bool))]
    haystack = "\n".join(scalars)

    for text in expected.get("contains", []):
        if text not in haystack:
            raise SystemExit(f"AIBOM missing expected text: {text}")

    for text in expected.get("absent", []):
        if text in haystack:
            raise SystemExit(f"AIBOM contains forbidden text: {text}")

    for key, minimum in expected.get("min_occurrences", {}).items():
        count = haystack.count(key)
        if count < int(minimum):
            raise SystemExit(f"AIBOM expected at least {minimum} occurrence(s) of {key}, found {count}")

    print("AIBOM profile assertion OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
