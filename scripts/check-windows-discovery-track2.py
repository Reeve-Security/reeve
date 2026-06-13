#!/usr/bin/env python3
"""Static contract for issue #57 Track 2 Windows MCP discovery paths.

Track 2 adds Windows config-file discovery only. It must update scanner
path specs, externally-observable tests, scope docs, release notes, and an
ADR while keeping Windows profiling and sandbox enforcement out of scope.
"""
from __future__ import annotations

from pathlib import Path

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
    claude_code = read("crates/aibom-scanner/src/mcp/discovery/claude_code.rs")
    vscode = read("crates/aibom-scanner/src/mcp/discovery/vscode_mcp.rs")
    tests = read("crates/aibom-scanner/tests/discovery_surfaces.rs")
    scope = read("docs/scope.md")
    readme = read("README.md")
    releases = read("docs/releases/README.md")
    v013 = read("docs/releases/v0.1.3.md")
    dist = read("dist-workspace.toml")
    adr = read("docs/decisions/0016-windows-mcp-discovery-paths.md")
    adr_index = read("docs/decisions/README.md")
    ci = read(".github/workflows/ci.yml")

    for needle in [
        ".mcp.json",
        ".claude.json",
        ".claude/settings.json",
    ]:
        require(claude_code, needle, "claude_code.rs")

    for needle in [
        ".config/Code/User/mcp.json",
        ".config/Code/User/settings.json",
        "AppData/Roaming/Code/User/mcp.json",
        "AppData/Roaming/Code/User/settings.json",
    ]:
        require(vscode, needle, "vscode_mcp.rs")

    for needle in [
        "discovers_windows_user_config_paths",
        "scope_catalog_marks_windows_appdata_paths",
        "AppData/Roaming/Claude/claude_desktop_config.json",
        ".claude/settings.json",
        "AppData/Roaming/Code/User/settings.json",
        "Zed has no Windows build",
    ]:
        require(tests, needle, "discovery_surfaces.rs")

    for needle in [
        "Windows user",
        "AppData/Roaming/Claude/claude_desktop_config.json",
        ".claude/settings.json",
        "AppData/Roaming/Code/User/mcp.json",
        "AppData/Roaming/Code/User/settings.json",
        "Zed has no Windows build",
        "Windows discovery is config-file discovery only",
        "Windows profiling and Windows sandbox enforcement remain separate product claims",
    ]:
        require(scope, needle, "docs/scope.md")

    for needle in [
        "supports MCP",
        "config-file discovery",
        "Windows profiling and sandbox enforcement",
    ]:
        require(readme, needle, "README.md")

    for needle in [
        "Windows signed binary + MCP config-file discovery",
        "v0.1.3",
        "binary distribution + MCP config-file discovery",
        "Windows observational",
        "AppContainer enforcement",
        "v0.2.0",
    ]:
        require(releases, needle, "docs/releases/README.md")

    for needle in [
        "Windows MCP config-file discovery",
        "v0.1.3",
        "Windows profiling",
    ]:
        require(v013, needle, "docs/releases/v0.1.3.md")

    for needle in [
        "Windows is a signed binary-distribution target",
        "Windows config-file",
        "Windows profiling and sandbox",
    ]:
        require(dist, needle, "dist-workspace.toml")

    for needle in [
        "ADR-0016: Windows MCP discovery is config-file only",
        "0016-windows-mcp-discovery-paths.md",
    ]:
        require(adr_index, needle, "docs/decisions/README.md")

    for needle in [
        "Windows MCP config-file discovery",
        "AppData/Roaming/Claude/claude_desktop_config.json",
        "AppData/Roaming/Code/User/settings.json",
        ".claude/settings.json",
        "Zed has no Windows build",
        "does not add Windows profiling",
        "sandbox enforcement",
        "AppContainer remains deferred",
    ]:
        require(adr, needle, "docs/decisions/0016-windows-mcp-discovery-paths.md")

    for forbidden in [
        "Windows profiling is supported",
        "Windows AppContainer enforcement is supported",
    ]:
        require_absent(readme, forbidden, "README.md")
        require_absent(releases, forbidden, "docs/releases/README.md")
        require_absent(scope, forbidden, "docs/scope.md")

    require(ci, "python3 scripts/check-windows-discovery-track2.py", ".github/workflows/ci.yml")
    print("windows discovery Track 2 contract OK")


if __name__ == "__main__":
    main()
