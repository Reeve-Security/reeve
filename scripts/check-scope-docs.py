#!/usr/bin/env python3
"""Static contract check for docs/scope.md.

This is intentionally lightweight: source remains the Rust SurfaceSpec registry,
and docs/scope.md must mention every discovery surface, path/glob, workspace
filename, and parser-root segment. If a future adapter changes discovery scope,
this check fails until the customer-facing scope contract is updated too.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DISCOVERY = ROOT / "crates/aibom-scanner/src/mcp/discovery"
DOC = ROOT / "docs/scope.md"
CI = ROOT / ".github/workflows/ci.yml"


def rust_strings(section: str) -> list[str]:
    return re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', section)


def balanced_block(text: str, start: int) -> str:
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise ValueError("unterminated SurfaceSpec block")


def list_section(block: str, field: str) -> str:
    marker = f"{field}: &"
    start = block.find(marker)
    if start == -1:
        return ""
    bracket = block.find("[", start)
    if bracket == -1:
        return ""
    depth = 0
    for i in range(bracket, len(block)):
        if block[i] == "[":
            depth += 1
        elif block[i] == "]":
            depth -= 1
            if depth == 0:
                return block[bracket : i + 1]
    raise ValueError(f"unterminated {field} list")


def workspace_block(block: str) -> str:
    marker = "workspace_search: Some(WorkspaceSearch"
    start = block.find(marker)
    if start == -1:
        return ""
    brace = block.find("{", start)
    return balanced_block(block, brace)


def workspace_blocks(block: str) -> list[str]:
    blocks: list[str] = []
    primary = workspace_block(block)
    if primary:
        blocks.append(primary)
    extra = list_section(block, "workspace_searches")
    for match in re.finditer(r"WorkspaceSearch\s*\{", extra):
        brace = extra.find("{", match.start())
        blocks.append(balanced_block(extra, brace))
    return blocks


def package_root_block(block: str) -> str:
    marker = "package_root_search: Some(PackageRootSearch"
    start = block.find(marker)
    if start == -1:
        return ""
    brace = block.find("{", start)
    return balanced_block(block, brace)


def expected_terms() -> set[str]:
    terms: set[str] = set()
    mod_text = (DISCOVERY / "mod.rs").read_text()
    skip_match = re.search(r"DEFAULT_SKIP_DIRS:\s*&\[&str\]\s*=\s*&\[(.*?)\];", mod_text, re.S)
    if skip_match:
        terms.update(rust_strings(skip_match.group(1)))
    for path in DISCOVERY.glob("*.rs"):
        if path.name == "mod.rs":
            continue
        text = path.read_text()
        marker = "SurfaceSpec {"
        marker_index = text.find(marker)
        if marker_index == -1:
            continue
        start = text.find("{", marker_index)
        block = balanced_block(text, start)
        for field in ("name",):
            m = re.search(rf'{field}:\s*"([^"]+)"', block)
            if m:
                terms.add(m.group(1))
        for field in ("paths", "glob_paths", "roots"):
            for value in rust_strings(list_section(block, field)):
                terms.add(value)
        for ws in workspace_blocks(block):
            for field in ("filename", "parent_dir"):
                m = re.search(rf'{field}:\s*(?:Some\()?"([^"]+)"', ws)
                if m:
                    terms.add(m.group(1))
            m = re.search(r"max_depth:\s*(\d+)", ws)
            if m:
                terms.add(f"max depth {m.group(1)}")
        package = package_root_block(block)
        if package:
            terms.update(rust_strings(package))
    terms.update([
        "docs/scope.md",
        "filesystem scope",
        "home directory",
        "source code",
        "secrets",
        "network shares",
        "sandbox-exec",
        "Landlock",
        "seccomp",
        "check-scope-docs.py",
    ])
    return terms


def main() -> int:
    doc = DOC.read_text()
    ci = CI.read_text()
    missing = sorted(term for term in expected_terms() if term not in doc)
    if "python3 scripts/check-scope-docs.py" not in ci:
        missing.append("CI step python3 scripts/check-scope-docs.py")
    if missing:
        print("docs/scope.md scope contract missing terms:", file=sys.stderr)
        for term in missing:
            print(f"  - {term}", file=sys.stderr)
        return 1
    print("scope docs contract OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
