#!/usr/bin/env python3
"""Static contract for issue #57 Track 0 Windows release viability.

This is intentionally a documentation/configuration contract. It proves that the
repo advertises a Windows cargo-dist release target and records the Blacksmith
Windows runner/toolchain/cosign facts needed to evaluate CI results. Later
issue #57 tracks may add product behavior without changing the Track 0 facts.
"""
from __future__ import annotations

from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist-workspace.toml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"
TRACK0_WORKFLOW = ROOT / ".github" / "workflows" / "windows-release-track0.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"
ADR = ROOT / "docs" / "decisions" / "0014-windows-release-track0.md"
ADR_INDEX = ROOT / "docs" / "decisions" / "README.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def require(text: str, needle: str, where: Path) -> None:
    if needle not in text:
        raise SystemExit(f"{where.relative_to(ROOT)}: missing expected text: {needle}")


def require_absent(text: str, needle: str, where: Path) -> None:
    if needle in text:
        raise SystemExit(f"{where.relative_to(ROOT)}: forbidden Track 0 text present: {needle}")


def main() -> None:
    dist = read(DIST)
    dist_config = tomllib.loads(dist)
    release = read(RELEASE)
    track0_workflow = read(TRACK0_WORKFLOW)
    ci = read(CI)
    adr = read(ADR)
    adr_index = read(ADR_INDEX)

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
        require(dist, needle, DIST)

    for needle in [
        "dist plan",
        "matrix: ${{ fromJson(needs.plan.outputs.val).ci.github.artifacts_matrix }}",
        "runs-on: ${{ matrix.runner }}",
        "dtolnay/rust-toolchain@stable",
        "dist build ${{ needs.plan.outputs.tag-flag }} --allow-dirty --print=linkage --output-format=json",
    ]:
        require(release, needle, RELEASE)

    for needle in [
        "name: Windows release Track 0",
        "workflow_dispatch:",
        "pull_request:",
        "runs-on: blacksmith-4vcpu-windows-2025",
        "timeout-minutes: 30",
        "dtolnay/rust-toolchain@stable",
        "sigstore/cosign-installer@v3.8.1",
        "cosign version",
        "dist build --allow-dirty --print=linkage --output-format=json --artifacts=local --target=x86_64-pc-windows-msvc",
    ]:
        require(track0_workflow, needle, TRACK0_WORKFLOW)

    for needle in [
        "python3 scripts/check-windows-release-track0.py",
        "sigstore/cosign-installer@v3.8.1",
    ]:
        require(ci, needle, CI)

    for needle in [
        "ADR-0014: Track 0 adds a Windows release-build target without Windows discovery or profiling",
        "0014-windows-release-track0.md",
    ]:
        require(adr_index, needle, ADR_INDEX)

    for needle in [
        "x86_64-pc-windows-msvc",
        "blacksmith-2vcpu-windows-2025",
        "blacksmith-4vcpu-windows-2025",
        "blacksmith-8vcpu-windows-2025",
        "blacksmith-16vcpu-windows-2025",
        "blacksmith-32vcpu-windows-2025",
        "blacksmith-4vcpu-windows-2025",
        "Visual Studio Build Tools 2022",
        "Docker Linux containers are not supported",
        "official GitHub Windows runner image",
        "runner_os == 'Windows'",
        "cosign-windows-amd64.exe",
        "release-build-only",
        "does **not** add Windows discovery, profiling, sandbox enforcement, ETW collection, or Windows path grammar",
        "Windows sandbox support is still deferred",
    ]:
        require(adr, needle, ADR)

    for forbidden in [
        "AppContainer *(chosen)*",
        "ETW *(chosen)*",
        "Windows discovery *(chosen)*",
    ]:
        require_absent(adr, forbidden, ADR)

    print("windows release Track 0 contract OK")


if __name__ == "__main__":
    main()
