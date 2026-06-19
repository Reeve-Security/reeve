#!/usr/bin/env python3
"""Decide whether a set of changed file paths touches signing/release-sensitive code.

This is the single source of truth for "did the changes since the last release
touch a path that can break the live Sigstore signing or the release pipeline?".
`scripts/release-gate.sh` consumes it to decide whether a successful live
`live-sigstore-acceptance` run for the current HEAD must exist BEFORE a release
tag is cut. v0.3.10 shipped a cosign-signing regression precisely because the
live Sigstore path only ran on the tag, i.e. after it was too late; this gate
moves that proof to before the tag whenever a sensitive path moved.

The path set is intentionally narrow and deliberate, not a catch-all: only the
signer/CLI crates, the release + sigstore workflows, the deploy/MDM packaging
tooling, and the publish/release gate scripts themselves.

usage:
  python3 scripts/release-sensitive-paths.py [PATH ...]   paths from argv, else one per stdin line
  python3 scripts/release-sensitive-paths.py --self-test   run built-in assertions

exit 0  => sensitive (at least one changed path matches a sensitive pattern)
exit 1  => NOT sensitive (empty set, or no path matches)
"""

from __future__ import annotations

import sys


# Globs are deliberate. `prefix/**` matches anything under prefix (and the bare
# prefix); any other entry is an exact path match. Keep this list in lockstep
# with the issue / ADR that defines the release-sensitive surface.
SENSITIVE_PATTERNS: list[str] = [
    "crates/aibom-signer/**",
    "crates/aibom-cli/**",
    ".github/workflows/release.yml",
    ".github/workflows/live-sigstore-acceptance.yml",
    "tools/deploy/**",
    "tools/mdm/**",
    "scripts/advisory-publish-gate.sh",
    "scripts/release-gate.sh",
]


def path_matches(path: str, pattern: str) -> bool:
    """Match one changed path against one sensitive pattern.

    - a pattern ending in `/**` (e.g. `crates/aibom-signer/**`) matches the bare
      prefix and anything under it (`crates/aibom-signer`, `crates/aibom-signer/src/x.rs`);
    - any other pattern is an exact path match.
    """
    path = path.strip()
    if not path:
        return False
    if pattern.endswith("/**"):
        prefix = pattern[: -len("/**")]
        return path == prefix or path.startswith(prefix + "/")
    return path == pattern


def is_sensitive(paths: list[str], patterns: list[str] = SENSITIVE_PATTERNS) -> bool:
    """True IFF at least one changed path matches at least one sensitive pattern."""
    cleaned = [p.strip() for p in paths if p.strip()]
    return any(any(path_matches(p, pat) for pat in patterns) for p in cleaned)


def matching_paths(paths: list[str], patterns: list[str] = SENSITIVE_PATTERNS) -> list[str]:
    """Return the subset of changed paths that match a sensitive pattern."""
    return [
        p.strip()
        for p in paths
        if p.strip() and any(path_matches(p.strip(), pat) for pat in patterns)
    ]


def _read_paths(argv: list[str]) -> list[str]:
    if argv:
        return list(argv)
    return sys.stdin.read().splitlines()


def self_test() -> int:
    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    # A signer path -> sensitive.
    check(
        is_sensitive(["crates/aibom-signer/src/lib.rs"]),
        "a signer path should be sensitive",
    )
    # A release workflow change -> sensitive.
    check(
        is_sensitive([".github/workflows/release.yml"]),
        ".github/workflows/release.yml should be sensitive",
    )
    # The CLI crate -> sensitive.
    check(
        is_sensitive(["crates/aibom-cli/src/main.rs"]),
        "a cli path should be sensitive",
    )
    # The release gate script itself -> sensitive.
    check(
        is_sensitive(["scripts/release-gate.sh"]),
        "scripts/release-gate.sh should be sensitive",
    )
    # A docs-only / README change -> NOT sensitive.
    check(
        not is_sensitive(["README.md"]),
        "README.md should NOT be sensitive",
    )
    check(
        not is_sensitive(["docs/anything/here.md"]),
        "a docs path should NOT be sensitive",
    )
    # An unrelated crate not in the list -> NOT sensitive.
    check(
        not is_sensitive(["crates/aibom-policy/src/lib.rs"]),
        "crates/aibom-policy/src/lib.rs should NOT be sensitive",
    )
    # Empty set -> NOT sensitive.
    check(not is_sensitive([]), "empty set should NOT be sensitive")
    # Mixed set with one sensitive entry -> sensitive.
    check(
        is_sensitive(["README.md", "crates/aibom-signer/Cargo.toml"]),
        "a set containing a signer path should be sensitive",
    )

    # Pattern-matcher unit cases: prefix boundary must not over-match.
    check(
        not path_matches("crates/aibom-signer-extra/x.rs", "crates/aibom-signer/**"),
        "a sibling prefix should NOT match crates/aibom-signer/**",
    )
    check(
        path_matches("crates/aibom-signer", "crates/aibom-signer/**"),
        "the bare prefix should match crates/aibom-signer/**",
    )
    check(
        not path_matches("tools/deploy", "tools/mdm/**"),
        "tools/deploy should NOT match tools/mdm/**",
    )

    if failures:
        for message in failures:
            print(f"release-sensitive-paths self-test FAIL: {message}", file=sys.stderr)
        return 1
    print(
        f"release-sensitive-paths self-test OK "
        f"({len(SENSITIVE_PATTERNS)} sensitive patterns)"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return self_test()

    paths = _read_paths(argv)
    return 0 if is_sensitive(paths) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
