#!/usr/bin/env python3
"""Static checks for release artifact signing contract.

This intentionally avoids live Sigstore calls. It verifies that the
release workflow, ADR, and README stay aligned on the externally visible
release-signing behavior introduced for GitHub issue #27.
"""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(haystack: str, needle: str, where: str) -> None:
    if needle not in haystack:
        raise SystemExit(f"{where}: missing expected text: {needle}")


def require_unique_adr_numbers() -> None:
    seen: dict[str, str] = {}
    for path in sorted((ROOT / "docs/decisions").glob("[0-9][0-9][0-9][0-9]-*.md")):
        number = path.name[:4]
        if number in seen:
            raise SystemExit(f"docs/decisions: duplicate ADR number {number}: {seen[number]} and {path.name}")
        seen[number] = path.name


release = read(".github/workflows/release.yml")
readme = read("README.md")
adr = read("docs/decisions/0010-release-artifact-signing.md")
adr_index = read("docs/decisions/README.md")
ci = read(".github/workflows/ci.yml")

require_unique_adr_numbers()

for needle in [
    '"contents": "write"',
    '"id-token": "write"',
    "Install cosign v3.0.6",
    "--allow-dirty --output-format=json > plan-dist-manifest.json",
    "dist build ${{ needs.plan.outputs.tag-flag }} --allow-dirty --print=linkage --output-format=json",
    "dist build ${{ needs.plan.outputs.tag-flag }} --allow-dirty --output-format=json \"--artifacts=global\"",
    "--allow-dirty --steps=upload --steps=release --output-format=json",
    "COSIGN_VERSION: v3.0.6",
    "COSIGN_LINUX_AMD64_SHA256:",
    "Stage source and policy bundle artifacts",
    "git archive",
    "policy_bundle_version=",
    "${RELEASE_TAG#v}",
    "crates/aibom-policy/bundles/${policy_bundle_version}.wasm",
    "cosign sign-blob --yes --bundle",
    "cosign verify-blob",
    "--certificate-oidc-issuer \"https://token.actions.githubusercontent.com\"",
    "-name '*.tar.gz'",
    "-name '*.tgz'",
    "-name '*.tar.xz'",
    "-name '*.zip'",
    "-name '*.sh'",
    "-name '*.wasm'",
    "release-artifact-signing-manifest.txt",
]:
    require(release, needle, ".github/workflows/release.yml")

for needle in [
    "Current private-repo install",
    "Unauthenticated `curl` downloads from GitHub",
    "gh release download \"${TAG}\"",
    "--repo Reeve-Security/reeve",
    "install -m 0755 \"${ASSET%.tar.xz}/aibom-cli\"",
    "Verify release artifacts",
    "shell installer",
    "aibom-cli-installer.sh",
    "cosign verify-blob",
    "--bundle \"${ASSET}.bundle\"",
    "https://token.actions.githubusercontent.com",
    "release.yml@refs/tags/v",
]:
    require(readme, needle, "README.md")

for needle in [
    "ADR-0010",
    "cosign v3.0.6",
    "cosign sign-blob --yes --bundle",
    "GitHub Actions OIDC",
    "policy bundle",
    "*.sh",
    "GitHub issue #27",
]:
    require(adr, needle, "docs/decisions/0010-release-artifact-signing.md")

for needle in [
    "ADR-0009: Linux profiling uses enforcement when available, with explicit observational fallback",
    "0009-linux-profile-observational-fallback.md",
    "ADR-0010: Release artifacts are signed as keyless cosign bundles",
    "0010-release-artifact-signing.md",
]:
    require(adr_index, needle, "docs/decisions/README.md")

for needle in [
    "workflow_dispatch:",
    "github.event.pull_request.draft != true",
    "blacksmith-4vcpu-ubuntu-2404",
    "blacksmith-6vcpu-macos-latest",
    "Swatinem/rust-cache@v2",
    "python3 scripts/check-release-signing.py",
]:
    require(ci, needle, ".github/workflows/ci.yml")

print("release-signing contract OK")
