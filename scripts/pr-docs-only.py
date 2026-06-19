#!/usr/bin/env python3
"""Decide whether a PR's changed files are entirely docs-only / paths-ignored.

The ignore list is NOT hardcoded here. It is read textually from the
`pull_request:` -> `paths-ignore:` block in `.github/workflows/ci.yml`, which is
the single source of truth: CI uses it to skip the heavy build/test matrix on a
docs-only change, and `scripts/merge-gate.sh --pr <N>` uses this helper to decide
that the intentionally-absent named checks are N/A for such a PR.

PyYAML is not installed in CI, so the block is parsed by indentation rather than
loaded as YAML.

usage:
  python3 scripts/pr-docs-only.py [PATH ...]   paths from argv, else one per stdin line
  python3 scripts/pr-docs-only.py --self-test  run built-in assertions

exit 0  => docs-only (changed set is non-empty AND every path matches an ignore pattern)
exit 1  => NOT docs-only (empty set, or some path is not ignored)
"""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def parse_paths_ignore(text: str) -> list[str]:
    """Return the `pull_request:` -> `paths-ignore:` patterns from ci.yml text.

    Textual / indentation-based parse (PyYAML is not available). We locate the
    `pull_request:` top-level key, then its `paths-ignore:` sub-key, then collect
    the `- 'pattern'` list items until the indentation drops back to the level of
    the `paths-ignore:` key (or shallower). We never read the `push:` block's
    list: scanning starts only after `pull_request:` is found.
    """
    lines = text.splitlines()
    patterns: list[str] = []

    in_pull_request = False
    pull_request_indent = -1
    in_ignore = False
    ignore_indent = -1

    for raw in lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = _indent(raw)

        if not in_pull_request:
            if stripped == "pull_request:":
                in_pull_request = True
                pull_request_indent = indent
            continue

        # Inside the pull_request block. A line at or below its indent that is
        # not part of it ends the block.
        if indent <= pull_request_indent and stripped != "pull_request:":
            break

        if not in_ignore:
            if stripped == "paths-ignore:":
                in_ignore = True
                ignore_indent = indent
            continue

        # Inside paths-ignore. List items are indented deeper than the key.
        if indent <= ignore_indent:
            # paths-ignore list ended.
            break
        if stripped.startswith("- "):
            value = stripped[2:].strip().strip("'").strip('"')
            if value:
                patterns.append(value)

    return patterns


def path_matches(path: str, pattern: str) -> bool:
    """Match a single changed path against one ignore pattern.

    - an exact filename matches itself (e.g. `README.md`);
    - a pattern ending in `/**` (e.g. `docs/**`) matches any path under that
      prefix (`docs/x`, `docs/x/y.md`);
    - a bare leaf `**` matches anything.
    """
    path = path.strip()
    if not path:
        return False
    if pattern == "**":
        return True
    if pattern.endswith("/**"):
        prefix = pattern[: -len("/**")]
        return path == prefix or path.startswith(prefix + "/")
    return path == pattern


def is_docs_only(paths: list[str], patterns: list[str]) -> bool:
    """True IFF the changed set is non-empty and every path matches a pattern."""
    cleaned = [p.strip() for p in paths if p.strip()]
    if not cleaned:
        return False
    return all(any(path_matches(p, pat) for pat in patterns) for p in cleaned)


def _read_paths(argv: list[str]) -> list[str]:
    if argv:
        return list(argv)
    return sys.stdin.read().splitlines()


def self_test() -> int:
    patterns = parse_paths_ignore(CI_WORKFLOW.read_text())

    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    # The helper and the CI policy cannot drift: the list parsed from ci.yml must
    # carry the expected entries.
    check("README.md" in patterns, f"expected README.md in paths-ignore, got {patterns}")
    check("docs/**" in patterns, f"expected docs/** in paths-ignore, got {patterns}")

    # We must read the pull_request block, not the push block. Both currently
    # match, but the parse should not have pulled push-only noise.
    check(len(patterns) >= 1, "paths-ignore parse returned no entries")

    # Synthetic decision cases against the parsed patterns.
    check(is_docs_only(["README.md"], patterns), "{README.md} should be docs-only")
    check(is_docs_only(["docs/x/y.md"], patterns), "{docs/x/y.md} should be docs-only")
    check(
        not is_docs_only(["README.md", "crates/foo.rs"], patterns),
        "{README.md, crates/foo.rs} should NOT be docs-only",
    )
    check(not is_docs_only([], patterns), "empty set should NOT be docs-only")
    check(
        not is_docs_only(["crates/foo.rs"], patterns),
        "{crates/foo.rs} should NOT be docs-only",
    )

    # Pattern-matcher unit cases.
    check(path_matches("docs/a", "docs/**"), "docs/a should match docs/**")
    check(path_matches("docs", "docs/**"), "docs should match docs/**")
    check(not path_matches("docsx/a", "docs/**"), "docsx/a should NOT match docs/**")
    check(path_matches("LICENSE", "LICENSE"), "LICENSE should match LICENSE")
    check(not path_matches("LICENSE.txt", "LICENSE"), "LICENSE.txt should NOT match LICENSE")
    check(path_matches("anything/here", "**"), "leaf ** should match anything")

    if failures:
        for message in failures:
            print(f"pr-docs-only self-test FAIL: {message}", file=sys.stderr)
        return 1
    print(f"pr-docs-only self-test OK ({len(patterns)} paths-ignore patterns parsed)")
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return self_test()

    patterns = parse_paths_ignore(CI_WORKFLOW.read_text())
    paths = _read_paths(argv)
    return 0 if is_docs_only(paths, patterns) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
