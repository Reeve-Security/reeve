#!/usr/bin/env python3
"""Assert the Rust toolchain is pinned in one repo-owned place
(rust-toolchain.toml) and every Rust-installing path in the workflows agrees
with that pin (#38).

Background: a local rustc at one version and CI on a rolling `stable` (the
dtolnay/rust-toolchain action with an implicit stable channel) produced
clippy drift and a wasted CI run. The pin's job is agreement between local
and CI, not recency; bump rust-toolchain.toml deliberately.

This needs no Rust toolchain installed: it is a static drift check, so the
merge gate can run it anywhere.

Checks:
  1. rust-toolchain.toml exists and pins channel = "X.Y.Z" (exact semver,
     no rolling channel names).
  2. Every `uses: dtolnay/rust-toolchain@...` step in the covered workflows
     passes `with: toolchain: <channel>`; a missing input (implicit stable)
     or a different version fails.
  3. No `rustup install` / `rustup default` / `--default-toolchain` command
     in the covered workflows names a toolchain other than the pinned
     channel. Commands that name no toolchain at all are allowed: rustup's
     cargo shim reads rust-toolchain.toml in the repo working directory, so
     they resolve to the pin automatically (this is how the cargo-dist
     generated container path in release.yml stays unedited).

Usage:
  check-toolchain-contract.py            # check the repo
  check-toolchain-contract.py --self-test
"""

from __future__ import annotations

import contextlib
import io
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLCHAIN_FILE = REPO_ROOT / "rust-toolchain.toml"
WORKFLOW_FILES = (
    Path(".github/workflows/ci.yml"),
    Path(".github/workflows/release.yml"),
    Path(".github/workflows/live-sigstore-acceptance.yml"),
)

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
CHANNEL_RE = re.compile(r'^\s*channel\s*=\s*"([^"]*)"\s*$', re.MULTILINE)
DTOLNAY_USES_RE = re.compile(r"^(\s*)-\s*uses:\s*[\"']?dtolnay/rust-toolchain@")
TOOLCHAIN_INPUT_RE = re.compile(r"^\s*toolchain:\s*[\"']?([^\"'\s#]+)")
# rustup commands that would pick a toolchain outside rust-toolchain.toml:
#   rustup install 1.2.3 / rustup toolchain install stable /
#   rustup default nightly / rustup-init --default-toolchain stable
RUSTUP_PIN_RE = re.compile(
    r"rustup\s+(?:toolchain\s+)?install\s+(\S+)"
    r"|rustup\s+default\s+(\S+)"
    r"|--default-toolchain[= ](\S+)"
)


def _fail(msg: str) -> None:
    print(f"check-toolchain-contract: FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def parse_channel(toml_text: str) -> str:
    match = CHANNEL_RE.search(toml_text)
    if not match:
        _fail('rust-toolchain.toml has no channel = "X.Y.Z" line')
    channel = match.group(1)
    if not SEMVER_RE.match(channel):
        _fail(
            f"rust-toolchain.toml channel must be an exact X.Y.Z version "
            f"(got {channel!r}); rolling channels defeat the pin"
        )
    return channel


def _dtolnay_step_toolchains(text: str) -> list[tuple[int, str | None]]:
    """Return (lineno, toolchain-input-or-None) for every dtolnay/rust-toolchain
    step. The step block is delimited by indentation: it ends at the first
    non-blank line indented at or left of the step's own `-`."""
    lines = text.splitlines()
    found: list[tuple[int, str | None]] = []
    for i, line in enumerate(lines):
        uses = DTOLNAY_USES_RE.match(line)
        if not uses:
            continue
        dash_indent = len(uses.group(1))
        toolchain: str | None = None
        for follower in lines[i + 1 :]:
            if not follower.strip():
                continue
            if len(follower) - len(follower.lstrip()) <= dash_indent:
                break
            input_match = TOOLCHAIN_INPUT_RE.match(follower)
            if input_match:
                toolchain = input_match.group(1)
                break
        found.append((i + 1, toolchain))
    return found


def check_workflow_text(name: str, text: str, channel: str) -> None:
    for lineno, toolchain in _dtolnay_step_toolchains(text):
        if toolchain is None:
            _fail(
                f"{name}:{lineno}: dtolnay/rust-toolchain step has no "
                f"`toolchain:` input (implicit rolling stable); "
                f"add `toolchain: {channel}` to match rust-toolchain.toml"
            )
        if toolchain != channel:
            _fail(
                f"{name}:{lineno}: dtolnay/rust-toolchain pins {toolchain!r} "
                f"but rust-toolchain.toml pins {channel!r}"
            )
    for match in RUSTUP_PIN_RE.finditer(text):
        named = next(group for group in match.groups() if group is not None)
        if named != channel:
            _fail(
                f"{name}: rustup command names toolchain {named!r} "
                f"but rust-toolchain.toml pins {channel!r} "
                f"(name no toolchain at all to inherit the repo pin)"
            )


def check_repo() -> None:
    if not TOOLCHAIN_FILE.is_file():
        _fail("missing rust-toolchain.toml at the repo root")
    channel = parse_channel(TOOLCHAIN_FILE.read_text())
    for rel in WORKFLOW_FILES:
        workflow = REPO_ROOT / rel
        if not workflow.is_file():
            _fail(f"missing {rel}")
        check_workflow_text(str(rel), workflow.read_text(), channel)
    print(
        f"check-toolchain-contract: OK (toolchain pinned to {channel} via "
        f"rust-toolchain.toml; {len(WORKFLOW_FILES)} workflows agree)"
    )


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
    # channel parsing
    assert parse_channel('[toolchain]\nchannel = "1.92.0"\n') == "1.92.0"
    for bad in ("", "[toolchain]\n", 'channel = "stable"', 'channel = "1.92"'):
        _expect_reject(parse_channel, bad, what=f"channel from {bad!r}")

    channel = "1.92.0"
    good = (
        "jobs:\n"
        "  check:\n"
        "    steps:\n"
        "      - uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000 # pinned\n"
        "        with:\n"
        "          toolchain: 1.92.0\n"
        "          components: rustfmt, clippy\n"
        "      - name: container rustup, no version named (inherits repo pin)\n"
        "        run: curl https://sh.rustup.rs | sh -s -- -y\n"
        "      - run: rustup install 1.92.0\n"
    )
    check_workflow_text("good.yml", good, channel)  # must pass

    missing_input = (
        "    steps:\n"
        "      - uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000\n"
        "      - name: next step\n"
        "        run: cargo test\n"
    )
    _expect_reject(
        check_workflow_text, "bad.yml", missing_input, channel,
        what="dtolnay step without toolchain input",
    )

    wrong_version = (
        "    steps:\n"
        "      - uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000\n"
        "        with:\n"
        "          toolchain: 1.93.0\n"
    )
    _expect_reject(
        check_workflow_text, "bad.yml", wrong_version, channel,
        what="dtolnay step pinning a different version",
    )

    rolling_input = (
        "    steps:\n"
        "      - uses: dtolnay/rust-toolchain@0000000000000000000000000000000000000000\n"
        "        with:\n"
        "          toolchain: stable\n"
    )
    _expect_reject(
        check_workflow_text, "bad.yml", rolling_input, channel,
        what="dtolnay step naming a rolling channel",
    )

    for bad_run in (
        "      - run: rustup default stable\n",
        "      - run: rustup toolchain install 1.93.0\n",
        "      - run: rustup-init -y --default-toolchain stable\n",
    ):
        _expect_reject(
            check_workflow_text, "bad.yml", bad_run, channel,
            what=f"rustup drift {bad_run.strip()!r}",
        )

    print("check-toolchain-contract self-test OK")


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        self_test()
        return 0
    check_repo()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
