#!/usr/bin/env python3
"""Verify that public Shipped launch capabilities have automated test proof."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_SCAN_ROOT = ROOT / "crates"
ISSUE_RE = re.compile(r"#(\d+)")
PROOF_RE = re.compile(r"//\s*launch-proof:\s*(.+)")
TEST_FN_RE = re.compile(r"^\s*(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
TEST_ATTR_RE = re.compile(r"^\s*#\[(?:test|[A-Za-z_][A-Za-z0-9_:]*::test)")


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON: {exc}") from exc


def marker_issues(line: str, path: pathlib.Path, lineno: int) -> list[str]:
    match = PROOF_RE.search(line)
    if not match:
        return []
    issues = ISSUE_RE.findall(match.group(1))
    if not issues:
        rel = path.relative_to(ROOT)
        raise SystemExit(f"{rel}:{lineno}: launch-proof marker has no issue number")
    return issues


def collect_proofs(scan_root: pathlib.Path) -> dict[str, list[str]]:
    proofs: dict[str, list[str]] = {}
    marker_locations: dict[tuple[str, int], list[str]] = {}
    associated_markers: set[tuple[str, int]] = set()

    for path in sorted(scan_root.rglob("*.rs")):
        rel = path.relative_to(ROOT)
        lines = path.read_text().splitlines()
        for idx, line in enumerate(lines):
            issues = marker_issues(line, path, idx + 1)
            if issues:
                marker_locations[(str(rel), idx + 1)] = issues

        for idx, line in enumerate(lines):
            fn_match = TEST_FN_RE.match(line)
            if not fn_match:
                continue

            prefix_start = idx
            while prefix_start > 0:
                previous = lines[prefix_start - 1].strip()
                if previous.startswith("#[") or previous.startswith("//"):
                    prefix_start -= 1
                    continue
                break
            prefix = lines[prefix_start:idx]
            nearby_markers: list[tuple[int, list[str]]] = []
            for offset, prefix_line in enumerate(prefix):
                marker_lineno = prefix_start + offset + 1
                issues = marker_issues(prefix_line, path, marker_lineno)
                if issues:
                    nearby_markers.append((marker_lineno, issues))

            if not nearby_markers:
                continue

            if not any(TEST_ATTR_RE.match(prefix_line.strip()) for prefix_line in prefix):
                raise SystemExit(f"{rel}:{idx + 1}: launch-proof marker is not on a test")
            if any(prefix_line.strip().startswith("#[ignore") for prefix_line in prefix):
                raise SystemExit(f"{rel}:{idx + 1}: launch-proof marker is on ignored test")

            test_name = fn_match.group(1)
            location = f"{rel}:{idx + 1} {test_name}"
            for marker_lineno, issues in nearby_markers:
                associated_markers.add((str(rel), marker_lineno))
                for issue in issues:
                    proofs.setdefault(issue, []).append(location)

    orphaned = sorted(set(marker_locations) - associated_markers)
    if orphaned:
        lines = ["launch-proof markers not attached to a Rust test:"]
        lines.extend(f"  {path}:{lineno}" for path, lineno in orphaned)
        raise SystemExit("\n".join(lines))

    if not proofs:
        raise SystemExit(f"{scan_root}: no launch-proof markers found")

    return proofs


def load_board(args: argparse.Namespace) -> dict[str, Any]:
    if args.board_json:
        return load_json(pathlib.Path(args.board_json))

    command = [
        "gh",
        "project",
        "item-list",
        str(args.project_number),
        "--owner",
        args.owner,
        "--format",
        "json",
        "--limit",
        "500",
    ]
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr.strip() or "gh project item-list failed")
    return json.loads(result.stdout)


def shipped_capabilities(board: dict[str, Any]) -> dict[str, str]:
    shipped: dict[str, str] = {}
    for item in board.get("items", []):
        if item.get("kind") != "Capability":
            continue
        if item.get("build State") != "Shipped":
            continue
        content = item.get("content") or {}
        number = content.get("number")
        title = content.get("title") or item.get("title") or "<untitled>"
        if not isinstance(number, int):
            raise SystemExit(f"Shipped capability missing issue number: {title}")
        shipped[str(number)] = str(title)
    return shipped


def validate_board(proofs: dict[str, list[str]], board: dict[str, Any], allow_extra: bool) -> None:
    mapped = set(proofs)
    shipped = shipped_capabilities(board)
    shipped_keys = set(shipped)

    missing = sorted(shipped_keys - mapped, key=int)
    if missing:
        lines = ["Shipped capabilities missing launch-proof markers:"]
        lines.extend(f"  #{issue} {shipped[issue]}" for issue in missing)
        raise SystemExit("\n".join(lines))

    extra = sorted(mapped - shipped_keys, key=int)
    if extra and not allow_extra:
        lines = ["Launch-proof markers are not Shipped on board:"]
        for issue in extra:
            refs = ", ".join(proofs[issue][:3])
            lines.append(f"  #{issue} {refs}")
        raise SystemExit("\n".join(lines))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scan-root",
        default=str(DEFAULT_SCAN_ROOT),
        help="directory to scan for Rust launch-proof markers",
    )
    parser.add_argument(
        "--map-only",
        action="store_true",
        help="compatibility alias for --markers-only",
    )
    parser.add_argument(
        "--markers-only",
        action="store_true",
        help="validate launch-proof markers only; default without --board",
    )
    parser.add_argument("--board", action="store_true", help="also check GitHub Project board")
    parser.add_argument("--board-json", help="check a saved gh project item-list JSON file")
    parser.add_argument("--owner", default="Reeve-Security", help="GitHub project owner")
    parser.add_argument("--project-number", type=int, default=2, help="GitHub project number")
    parser.add_argument(
        "--allow-extra-proof",
        action="store_true",
        help="allow proof markers that are not currently Shipped",
    )
    parser.add_argument(
        "--allow-extra-map",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scan_root = pathlib.Path(args.scan_root)
    if not scan_root.is_absolute():
        scan_root = ROOT / scan_root
    proofs = collect_proofs(scan_root)

    if args.board or args.board_json:
        validate_board(proofs, load_board(args), args.allow_extra_proof or args.allow_extra_map)

    proof_count = sum(len(locations) for locations in proofs.values())
    print(
        f"launch test gate OK: {len(proofs)} capabilities, {proof_count} proof markers"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
