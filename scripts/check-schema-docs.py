#!/usr/bin/env python3
"""Check schema docs against machine-readable sources."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schema"


def fail(message: str) -> None:
    print(f"schema-docs: {message}", file=sys.stderr)
    raise SystemExit(1)


def extract_error_codes_from_rust() -> set[str]:
    source = (ROOT / "crates/aibom-core/src/lib.rs").read_text()
    enum_match = re.search(r"pub enum ErrorCode \{(?P<body>.*?)\n\}", source, re.S)
    if not enum_match:
        fail("missing ErrorCode enum")
    return set(re.findall(r'#\[serde\(rename = "([^"]+)"\)\]', enum_match.group("body")))


def extract_error_codes_from_markdown() -> set[str]:
    markdown = (SCHEMA / "error-codes.md").read_text()
    return set(re.findall(r"^\| `([^`]+)` \|", markdown, re.M))


def check_error_code_docs() -> None:
    rust_codes = extract_error_codes_from_rust()
    doc_codes = extract_error_codes_from_markdown()
    missing = sorted(rust_codes - doc_codes)
    extra = sorted(doc_codes - rust_codes)
    if missing:
        fail("error-codes.md missing Rust codes: " + ", ".join(missing))
    if extra:
        fail("error-codes.md has unknown codes: " + ", ".join(extra))


def check_spec_paths() -> None:
    spec = (SCHEMA / "SPEC.md").read_text()
    for schema_file in sorted(SCHEMA.glob("*.json")):
        if f"`{schema_file.name}`" not in spec:
            fail(f"SPEC.md does not list {schema_file.name}")
    if "`fixtures/`" not in spec:
        fail("SPEC.md does not list fixtures/")
    if "examples/" in spec:
        fail("SPEC.md still references examples/")


def check_fixture_tree() -> None:
    expected_dirs = [
        "aibom-v0.1.0",
        "aibom-v0.2.0",
        "aibom-v0.3.0",
        "sensitive-data-report",
        "secret-rule-pack",
    ]
    for rel in expected_dirs:
        path = SCHEMA / "fixtures" / rel
        if not path.is_dir():
            fail(f"missing fixture directory {path.relative_to(ROOT)}")


def main() -> None:
    check_error_code_docs()
    check_spec_paths()
    check_fixture_tree()
    print("schema-docs OK")


if __name__ == "__main__":
    main()
