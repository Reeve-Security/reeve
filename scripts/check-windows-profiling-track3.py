#!/usr/bin/env python3
"""Static contract for issue #57 Track 3 Windows observational profiling.

Track 3 is a design-boundary slice only. It records that future Windows
behavior evidence may start as explicit observational profiling while
keeping Windows sandbox enforcement and AppContainer work deferred.
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
    readme = read("README.md")
    scope = read("docs/scope.md")
    roadmap = read("docs/adapter-roadmap.md")
    adr = read("docs/decisions/0017-windows-observational-profiling.md")
    adr_index = read("docs/decisions/README.md")
    ci = read(".github/workflows/ci.yml")
    windows_workflow = read(".github/workflows/windows-release-track0.yml")
    profile = read("crates/aibom-scanner/src/mcp/profile/mod.rs")
    profile_test = read("crates/aibom-scanner/tests/profile_rigged.rs")

    for needle in [
        "ADR-0017",
        "Windows observational profiling under ADR-0017",
        "Windows profiling and sandbox enforcement",
    ]:
        require(readme, needle, "README.md")

    for needle in [
        "ADR-0017",
        "Windows discovery is config-file discovery only",
        "Windows observational profiling",
        "observation rather than enforcement",
        "Windows profiling and Windows sandbox enforcement remain separate product claims",
    ]:
        require(scope, needle, "docs/scope.md")

    for needle in [
        "Issue #57 remains MCP-adapter work",
        "ADR-0017",
        "observational",
        "AppContainer enforcement later",
    ]:
        require(roadmap, needle, "docs/adapter-roadmap.md")

    for needle in [
        "ADR-0017: Windows profiling starts as explicit observational evidence",
        "0017-windows-observational-profiling.md",
    ]:
        require(adr_index, needle, "docs/decisions/README.md")

    for needle in [
        "Issue #57 Track 3",
        "ETW-backed",
        "not the same thing as a sandbox",
        "must label the run as observational",
        "must emit an",
        "explicit warning evidence record",
        "must not turn that run into",
        "clean\nprofile",
        "does not add Windows profiling code",
        "does not change the",
        "schema, policy engine, or three-layer architecture",
        "AppContainer enforcement",
    ]:
        require(adr, needle, "docs/decisions/0017-windows-observational-profiling.md")

    require(
        profile,
        "run_windows_observational_server",
        "crates/aibom-scanner/src/mcp/profile/mod.rs",
    )
    for needle in [
        "ProfileEventSource::WindowsTracerpt",
        "parse_windows_tracerpt_events",
        "Windows profiling is observational only; no kernel-level enforcement; see ADR-0017",
        "Windows ETW trace unavailable; telemetry gap recorded",
        "Windows ETW trace produced no parseable events",
        "maps_windows_tracerpt_lines_to_observational_events",
        "windows_tracerpt_records_loss_as_unmapped_warning_event",
    ]:
        require(profile, needle, "crates/aibom-scanner/src/mcp/profile/mod.rs")
    require(ci, "python3 scripts/check-windows-profiling-track3.py", ".github/workflows/ci.yml")
    require(
        windows_workflow,
        "cargo test -p aibom-scanner windows_",
        ".github/workflows/windows-release-track0.yml",
    )
    require(
        profile_test,
        "windows_observational_profile_emits_warning_evidence",
        "crates/aibom-scanner/tests/profile_rigged.rs",
    )
    for needle in [
        "windows_positive_control_requires_concrete_observed_events",
        "Windows ETW concrete event capture broken or unavailable on runner",
        "sandbox-filesystem, sandbox-network, and sandbox-process evidence",
    ]:
        require(profile_test, needle, "crates/aibom-scanner/tests/profile_rigged.rs")

    releases = read("docs/releases/README.md")
    v020 = read("docs/releases/v0.2.0.md")
    for needle in [
        "Windows observational profiling",
        "telemetry-gap evidence",
        "positive-control fixture requires filesystem, network, and process evidence",
        "observational profiling only; no sandbox enforcement",
    ]:
        require(releases, needle, "docs/releases/README.md")
    for needle in [
        "Windows observational profiling",
        "Telemetry-gap evidence",
        "Positive-control proof",
        "observation, not containment",
        "v0.2.0 does not ship AppContainer",
    ]:
        require(v020, needle, "docs/releases/v0.2.0.md")

    for forbidden in [
        "Windows profiling is implemented today",
        "Windows sandbox enforcement is implemented",
        "AppContainer enforcement is implemented",
    ]:
        require_absent(readme, forbidden, "README.md")
        require_absent(scope, forbidden, "docs/scope.md")
        require_absent(roadmap, forbidden, "docs/adapter-roadmap.md")

    print("windows profiling Track 3 contract OK")


if __name__ == "__main__":
    main()
