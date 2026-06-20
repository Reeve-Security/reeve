#!/usr/bin/env python3
"""Smoke-check the Linux release archive for sensitive-data scan support."""

from __future__ import annotations

import argparse
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path

ARCHIVE_NAME = "aibom-cli-x86_64-unknown-linux-gnu.tar.xz"
# Realistic high-entropy key: the legacy AWS docs example placeholder is now
# suppressed as a known placeholder by rule pack >=2026.05.1, so this contract
# must assert detection with a key that actually fires. The value is assembled
# from split fragments so no contiguous provider-shaped literal sits in source
# (#33); it is byte-identical to the prior literal at runtime.
SECRET = "AKIA" + "7Q4M2Z9X8C5N1P3R"
SESSION_NAME = "ReleaseSmoke"
SESSION_RELATIVE_PATH = Path(".claude") / "projects" / SESSION_NAME / "session.jsonl"
HELP_FLAGS = (
    "--include-conversation-metadata",
    "--scan-conversation-secrets",
    "--conversation-rules-file",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate that the Linux release archive exposes sensitive-data scan flags."
    )
    parser.add_argument(
        "artifacts_dir",
        type=Path,
        help="Directory containing release artifacts from the GitHub release workflow.",
    )
    return parser.parse_args()


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"ERROR: {message}")


def run_checked(*args: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        fail(
            "command failed: "
            + " ".join(args)
            + f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def find_linux_archive(artifacts_dir: Path) -> Path:
    matches = sorted(artifacts_dir.glob(ARCHIVE_NAME))
    if not matches:
        fail(f"missing {ARCHIVE_NAME} in {artifacts_dir}")
    if len(matches) != 1:
        fail(f"expected exactly one {ARCHIVE_NAME}, found {len(matches)}")
    return matches[0]


def extract_release_binary(archive: Path, temp_root: Path) -> Path:
    with tarfile.open(archive, mode="r:*") as bundle:
        bundle.extractall(temp_root)
    binaries = sorted(
        path
        for path in temp_root.rglob("aibom-cli")
        if path.is_file() and path.name == "aibom-cli"
    )
    if not binaries:
        fail(f"no aibom-cli binary found inside {archive.name}")
    if len(binaries) != 1:
        fail(f"expected one aibom-cli binary in {archive.name}, found {len(binaries)}")
    binary = temp_root / "aibom-cli-smoke-copy"
    binary.write_bytes(binaries[0].read_bytes())
    binary.chmod(0o755)
    return binary


def write_session(root: Path, content: str) -> None:
    session = root / SESSION_RELATIVE_PATH
    session.parent.mkdir(parents=True, exist_ok=True)
    session.write_text(content, encoding="utf-8")


def find_sensitive_report(output_dir: Path) -> Path:
    reports = sorted(output_dir.rglob("*.sensitive-data.json"))
    if not reports:
        fail(f"no sensitive-data report emitted under {output_dir}")
    if len(reports) != 1:
        fail(f"expected one sensitive-data report under {output_dir}, found {len(reports)}")
    return reports[0]


def run_scan(binary: Path, flag: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="reeve-release-input-") as root_dir, tempfile.TemporaryDirectory(
        prefix="reeve-release-output-"
    ) as out_dir:
        root = Path(root_dir)
        output = Path(out_dir)
        write_session(root, SECRET)
        result = run_checked(
            str(binary),
            "scan",
            "--no-system-config",
            "--target",
            str(root),
            "--output-dir",
            str(output),
            "--skip-sign",
            flag,
        )
        if "sensitive-data " not in result.stdout:
            fail(f"scan output did not advertise sensitive-data artifact for {flag}")
        report_path = find_sensitive_report(output)
        if str(report_path) not in result.stdout:
            fail(f"scan output did not print emitted sensitive-data report path for {flag}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report_text = json.dumps(report, sort_keys=True)
        if SECRET in report_text or SESSION_NAME in report_text:
            fail(f"sensitive-data report leaked raw content for {flag}")
        return report


def assert_help_flags(binary: Path) -> None:
    result = run_checked(str(binary), "scan", "--help")
    for flag in HELP_FLAGS:
        if flag not in result.stdout:
            fail(f"release binary help text missing {flag}")


def assert_metadata_scan(binary: Path) -> None:
    report = run_scan(binary, "--include-conversation-metadata")
    inputs = report["sensitiveDataReport"]["inputs"]
    surfaces = report["sensitiveDataReport"]["surfaces"]
    if inputs["metadataInventory"] is not True:
        fail("metadata-only scan should set metadataInventory=true")
    if inputs["contentPatternScan"] is not False:
        fail("metadata-only scan should keep contentPatternScan=false")
    if not any(surface["surface"] == "claude-code" for surface in surfaces):
        fail("metadata-only scan did not report the claude-code surface")


def assert_secret_scan(binary: Path) -> None:
    report = run_scan(binary, "--scan-conversation-secrets")
    inputs = report["sensitiveDataReport"]["inputs"]
    findings = report["sensitiveDataReport"]["findings"]
    if inputs["metadataInventory"] is not True:
        fail("secret scan should still include metadata inventory")
    if inputs["contentPatternScan"] is not True:
        fail("secret scan should set contentPatternScan=true")
    if not inputs["rulePacks"]:
        fail("secret scan should record at least one rule pack")
    if not any(finding["patternClass"] == "aws-access-key" for finding in findings):
        fail("secret scan did not record the expected aws-access-key finding")
    if not all(finding["humanReviewRequired"] is True for finding in findings):
        fail("secret scan findings must all require human review")


def main() -> None:
    args = parse_args()
    artifacts_dir = args.artifacts_dir.resolve()
    archive = find_linux_archive(artifacts_dir)
    with tempfile.TemporaryDirectory(prefix="reeve-release-smoke-") as temp_dir:
        binary = extract_release_binary(archive, Path(temp_dir))
        assert_help_flags(binary)
        assert_metadata_scan(binary)
        assert_secret_scan(binary)
    print(f"PASS release sensitive-data smoke: {archive.name}")


if __name__ == "__main__":
    main()
