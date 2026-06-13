#!/usr/bin/env python3
"""Static contract for issue #57 Track 1 Windows binary distribution.

Track 1 promotes the proven Windows cargo-dist lane from probe-only to release
contract: the next tagged release must publish a signed Windows zip. Later
issue #57 tracks may add discovery while profiling and sandbox enforcement
remain separate.
"""
from __future__ import annotations

from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(haystack: str, needle: str, where: str) -> None:
    if needle not in haystack:
        raise SystemExit(f"{where}: missing expected text: {needle}")


def require_absent(haystack: str, needle: str, where: str) -> None:
    if needle in haystack:
        raise SystemExit(f"{where}: forbidden text present: {needle}")


def main() -> None:
    dist = read("dist-workspace.toml")
    dist_config = tomllib.loads(dist)
    release = read(".github/workflows/release.yml")
    readme = read("README.md")
    releases = read("docs/releases/README.md")
    adr = read("docs/decisions/0015-windows-binary-distribution.md")
    adr_index = read("docs/decisions/README.md")
    ci = read(".github/workflows/ci.yml")

    dist_section = dist_config.get("dist", {})
    targets = dist_section.get("targets", [])
    runners = dist_section.get("github-custom-runners", {})
    windows_runner = runners.get("x86_64-pc-windows-msvc")
    if "x86_64-pc-windows-msvc" not in targets:
        raise SystemExit("dist-workspace.toml: missing Windows release target")
    if isinstance(windows_runner, str):
        windows_runner_name = windows_runner
    elif isinstance(windows_runner, dict):
        windows_runner_name = windows_runner.get("runner")
    else:
        windows_runner_name = None
    if windows_runner_name != "blacksmith-4vcpu-windows-2025":
        raise SystemExit(
            "dist-workspace.toml: Windows release target must use "
            "blacksmith-4vcpu-windows-2025"
        )

    for needle in [
        "Windows is a signed binary-distribution target",
        "Windows profiling and sandbox",
    ]:
        require(dist, needle, "dist-workspace.toml")

    for needle in [
        "-name '*.zip'",
        "dtolnay/rust-toolchain@stable",
        "cosign sign-blob --yes --bundle",
        "cosign verify-blob",
        "gh release create",
    ]:
        require(release, needle, ".github/workflows/release.yml")

    for needle in [
        "Windows release artifacts begin with `v0.1.3`",
        "aibom-cli-x86_64-pc-windows-msvc.zip",
        "Expand-Archive",
        "--bundle \"${ASSET}.bundle\"",
        "Windows profiling and sandbox enforcement",
    ]:
        require(readme, needle, "README.md")

    for needle in [
        "Windows binary distribution",
        "v0.1.3",
        "binary distribution + MCP config-file discovery",
        "Windows profiling / sandbox enforcement",
    ]:
        require(releases, needle, "docs/releases/README.md")

    for needle in [
        "ADR-0015: Windows binary distribution starts without Windows discovery or profiling",
        "0015-windows-binary-distribution.md",
    ]:
        require(adr_index, needle, "docs/decisions/README.md")

    for needle in [
        "x86_64-pc-windows-msvc",
        "aibom-cli-x86_64-pc-windows-msvc.zip",
        "verifiable cosign `.bundle`",
        "does not add Windows discovery",
        "does not add Windows profiling",
        "does not add Windows sandbox enforcement",
    ]:
        require(adr, needle, "docs/decisions/0015-windows-binary-distribution.md")

    for forbidden in [
        "Windows profiling is supported",
        "Windows AppContainer enforcement is supported",
    ]:
        require_absent(readme, forbidden, "README.md")
        require_absent(releases, forbidden, "docs/releases/README.md")

    require(ci, "python3 scripts/check-windows-release-track1.py", ".github/workflows/ci.yml")
    print("windows release Track 1 contract OK")


if __name__ == "__main__":
    main()
