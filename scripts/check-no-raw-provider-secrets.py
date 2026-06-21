#!/usr/bin/env python3
"""Fail if a contiguous provider-looking secret literal exists in tracked source.

Raw, realistic-looking provider credentials embedded as one contiguous literal
in source trip third-party secret scanners (GitHub push protection, gitleaks,
vendor crawlers) and erode the "Reeve = evidence, not noise" posture (#33). The
fix is to assemble every such value from split fragments at runtime so no single
literal in the tree matches a real provider shape; this guard enforces that the
tree stays clean.

Scope is SOURCE only: the crates, scripts, schema, workflows, and root config
files. Prose (docs, Markdown, plan/snapshot files) is intentionally excluded so
a sentence discussing a `sk_live_` or `AKIA` prefix never trips the guard.

The guard is self-safe: its OWN detection patterns are built by concatenating
split prefix fragments at runtime, so this file contains no contiguous literal
that any pattern below could match. It does not rely on a broad self-exemption.

usage:
  python3 scripts/check-no-raw-provider-secrets.py            scan tracked source
  python3 scripts/check-no-raw-provider-secrets.py --self-test  run built-in assertions

exit 0  => clean (no contiguous provider literal in scanned source)
exit 1  => a contiguous provider literal was found, or a self-test assertion failed
"""

from __future__ import annotations

import re
import subprocess
import sys

# Prefix fragments are split so this source has no contiguous matchable literal.
# Each entry assembles its real prefix at runtime from pieces joined here.
_STRIPE_SK_LIVE = "sk" + "_" + "live" + "_"
_STRIPE_SK_TEST = "sk" + "_" + "test" + "_"
_STRIPE_RK_LIVE = "rk" + "_" + "live" + "_"
_STRIPE_RK_TEST = "rk" + "_" + "test" + "_"
_AWS_AKIA = "AK" + "IA"
_ANTHROPIC = "sk" + "-" + "ant" + "-"
_OPENAI_PROJ = "sk" + "-" + "proj" + "-"
_OPENAI_SK = "sk" + "-"
_GITHUB_PAT = "gh" + "p" + "_"
_JWT_HEAD = "ey" + "J"
# PEM private-key marker fragments, split so this guard's own source holds no
# contiguous full marker (the begin-dashes and the key-words / closing-dashes are
# joined only at runtime).
_PEM_BEGIN = "-" * 5 + "BEGIN "
_PEM_KEY_SUFFIX = "PRIVATE" + " KEY" + "-" * 5


# Each rule: (pattern-class, compiled regex). The regexes require a credential
# BODY after the prefix, so a bare prefix fragment (e.g. the `AKIA` literal used
# as a `starts_with` argument, or a `sk-ant-` prefix passed to a matcher) does
# NOT match. Only a contiguous prefix+body shape does.
def _build_rules() -> list[tuple[str, re.Pattern[str]]]:
    rules: list[tuple[str, re.Pattern[str]]] = [
        # stripe live/test secret + restricted keys: prefix + >=10 body chars.
        ("stripe-key", re.compile(_STRIPE_SK_LIVE + r"[A-Za-z0-9]{10,}")),
        ("stripe-key", re.compile(_STRIPE_SK_TEST + r"[A-Za-z0-9]{10,}")),
        ("stripe-key", re.compile(_STRIPE_RK_LIVE + r"[A-Za-z0-9]{10,}")),
        ("stripe-key", re.compile(_STRIPE_RK_TEST + r"[A-Za-z0-9]{10,}")),
        # AWS access key id: AKIA + exactly 16 uppercase/digit chars.
        ("aws-access-key", re.compile(_AWS_AKIA + r"[A-Z0-9]{16}")),
        # anthropic api key: sk-ant- + >=10 body chars.
        ("anthropic-api-key", re.compile(_ANTHROPIC + r"[A-Za-z0-9_-]{10,}")),
        # openai project key: sk-proj- + >=10 body chars.
        ("openai-api-key", re.compile(_OPENAI_PROJ + r"[A-Za-z0-9_-]{10,}")),
        # openai legacy key: sk- + >=20 body chars (avoids sk-ant-/sk-proj- which
        # are matched above and short prose like "sk-foo").
        ("openai-api-key", re.compile(_OPENAI_SK + r"[A-Za-z0-9]{20,}")),
        # github personal access token: ghp_ + >=20 body chars.
        ("github-token", re.compile(_GITHUB_PAT + r"[A-Za-z0-9]{20,}")),
        # JWT: eyJ<base64>. (header segment of a JSON Web Token).
        ("jwt", re.compile(_JWT_HEAD + r"[A-Za-z0-9_-]{8,}\.")),
        # PEM private-key block: a full begin-marker with an uppercase label
        # (RSA / EC / OPENSSH) or unlabeled. Bare begin-prefixes and the
        # production detector regex (label class [A-Z0-9 ]{0,64}, with brackets
        # and digits) do not match: they lack the contiguous closing key marker.
        ("private-key-pem", re.compile(_PEM_BEGIN + r"[A-Z ]{0,40}" + _PEM_KEY_SUFFIX)),
    ]
    return rules


RULES = _build_rules()

# Files/trees scanned. SOURCE only; prose is excluded so discussing a prefix in
# documentation never trips the guard.
INCLUDE_PREFIXES = (
    "crates/",
    "scripts/",
    "schema/",
    ".github/workflows/",
)


def _is_root_config(path: str) -> bool:
    return "/" not in path and path.endswith(".toml")


def _is_scanned_source(path: str) -> bool:
    """True for tracked SOURCE paths in scope; False for prose and out-of-scope."""
    if path.endswith(".md"):
        return False
    if path.startswith("docs/"):
        return False
    if _is_root_config(path):
        return True
    return any(path.startswith(prefix) for prefix in INCLUDE_PREFIXES)


def _redact(prefix_class: str, matched: str) -> str:
    """Show a short literal prefix of the match, then <REDACTED>, never the body."""
    head = matched[:8]
    return f"{head}<REDACTED>"


def tracked_source_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [p for p in out.splitlines() if p and _is_scanned_source(p)]


def scan_text(text: str) -> list[tuple[int, str, str]]:
    """Return (line_no, pattern-class, redacted-match) for every contiguous hit."""
    hits: list[tuple[int, str, str]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern_class, rx in RULES:
            for m in rx.finditer(line):
                hits.append((line_no, pattern_class, _redact(pattern_class, m.group(0))))
    return hits


def scan_files(paths: list[str]) -> list[tuple[str, int, str, str]]:
    findings: list[tuple[str, int, str, str]] = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for line_no, pattern_class, redacted in scan_text(text):
            findings.append((path, line_no, pattern_class, redacted))
    return findings


def self_test() -> int:
    failures: list[str] = []

    def check(condition: bool, message: str) -> None:
        if not condition:
            failures.append(message)

    # Positive samples assembled at runtime: each MUST be flagged.
    positives = {
        "stripe-key": _STRIPE_SK_LIVE + "vB7qL9mR2xT6pW4zY8nC",
        "aws-access-key": _AWS_AKIA + "7Q4M2Z9X8C5N1P3R",
        "anthropic-api-key": _ANTHROPIC + "api03-" + ("a" * 24),
        "openai-api-key": _OPENAI_PROJ + "vB7qL9mR2xT6pW4zY8nC",
        "github-token": _GITHUB_PAT + ("a" * 24),
        "jwt": _JWT_HEAD + "hbGciOiJIUzI1NiJ9.",
    }
    for expected_class, sample in positives.items():
        hits = scan_text(sample)
        check(
            any(cls == expected_class for _, cls, _ in hits),
            f"positive sample for {expected_class} should be flagged",
        )
        # The redacted output must never echo the full sample body.
        for _, _, redacted in hits:
            check(
                sample not in redacted,
                f"redacted output for {expected_class} must not echo the value",
            )

    # Benign samples that must NOT be flagged.
    benigns = [
        "a normal sentence with no secrets",
        # bare prefixes used as code fragments (starts_with args) must not trip.
        _AWS_AKIA,
        _ANTHROPIC,
        _STRIPE_SK_LIVE,
        f'token.starts_with("{_AWS_AKIA}")',
        # short sk- prose must not look like a legacy openai key.
        _OPENAI_SK + "foo",
    ]
    for sample in benigns:
        hits = scan_text(sample)
        check(not hits, f"benign sample should NOT be flagged: {sample!r}")

    # PEM private-key markers: every real label and the unlabeled form must be
    # flagged; the production detector-regex form and a bare begin-prefix must NOT.
    for label in ("RSA ", "EC ", "OPENSSH ", ""):
        marker = _PEM_BEGIN + label + _PEM_KEY_SUFFIX
        check(
            any(cls == "private-key-pem" for _, cls, _ in scan_text(marker)),
            f"PEM marker with label {label!r} should be flagged",
        )
    detector_form = _PEM_BEGIN + "[A-Z0-9 ]{0,64}" + _PEM_KEY_SUFFIX
    check(
        not any(cls == "private-key-pem" for _, cls, _ in scan_text(detector_form)),
        "production detector regex form must not be flagged",
    )
    check(
        not any(cls == "private-key-pem" for _, cls, _ in scan_text(_PEM_BEGIN)),
        "bare begin-prefix must not be flagged",
    )

    # This guard's own source MUST be clean (no contiguous literal of its own).
    own_hits = scan_files([sys.argv[0] if sys.argv and sys.argv[0] else __file__])
    check(not own_hits, "the guard's own source must contain no contiguous literal")

    if failures:
        for message in failures:
            print(f"check-no-raw-provider-secrets self-test FAIL: {message}", file=sys.stderr)
        return 1
    print(
        f"check-no-raw-provider-secrets self-test OK "
        f"({len(RULES)} provider patterns)"
    )
    return 0


def main(argv: list[str]) -> int:
    if argv and argv[0] == "--self-test":
        return self_test()

    paths = tracked_source_files()
    findings = scan_files(paths)
    if findings:
        print(
            "Contiguous provider-looking secret literal(s) found in tracked source.",
            file=sys.stderr,
        )
        print(
            "Assemble these from split fragments at runtime so no single literal "
            "matches a provider shape (#33).",
            file=sys.stderr,
        )
        for path, line_no, pattern_class, redacted in findings:
            print(f"{path}:{line_no}: {pattern_class}: {redacted}", file=sys.stderr)
        return 1
    print(f"check-no-raw-provider-secrets OK ({len(paths)} source files scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
