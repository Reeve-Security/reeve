#!/usr/bin/env python3
"""Static contract checks for macOS Tart validation tooling."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "tools/lab/test-mac/README.md",
    "tools/lab/test-mac/mac-matrix.yml",
    "tools/lab/test-mac/run-mac.sh",
    "tools/lab/test-mac/assert-rigged-profile.py",
]

TERMS = {
    "tools/lab/test-mac/README.md": [
        "Tart",
        "reeve-mac-base",
        "run-mac.sh",
        "mac-empty",
        "mac-engineering-stack",
        "private/mac-fleet-<date>/<profile>/",
        "sandbox-exec",
        "#99",
        "#144",
    ],
    "tools/lab/test-mac/mac-matrix.yml": [
        "mac-empty",
        "mac-claude-desktop-only",
        "mac-codex-app-only",
        "mac-mixed-nondev",
        "mac-engineering-stack",
        "expected_aibom",
    ],
    "tools/lab/test-mac/run-mac.sh": [
        "mac-matrix.yml",
        "TART_BASE_VM",
        "tart clone",
        "tart run",
        "tart delete",
        "launchctl kickstart",
        "private/mac-fleet-",
        "RELEASE_SIGNER_REGEX",
        "cosign verify-blob",
        "release-cosign.txt",
        "upload_to_guest_once",
        "download_from_guest_once",
        "mktemp",
        "aibom-cli-aarch64-apple-darwin.tar.xz",
        "aibom-cli-x86_64-apple-darwin.tar.xz",
        "assert-aibom.py",
        "assert-rigged-profile.py",
        "rigged-server/server.py",
        "rigged-profile.aibom.json",
        "expects_granted_permissions",
        "granted-policy.aibom.json",
        "policy check",
        "risky-grant",
        "--no-system-config",
        "--profile-yes",
        "tools/deploy/curl-install/install.sh",
    ],
    "tools/lab/test-mac/assert-rigged-profile.py": [
        "sandbox-filesystem",
        "sandbox-network",
        "etc/passwd:READ",
        "connect#-:80",
    ],
}


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    for rel in REQUIRED:
        path = ROOT / rel
        if not path.exists():
            fail(f"missing macOS Tart lab file: {rel}")
        text = path.read_text()
        for term in TERMS.get(rel, []):
            if term not in text:
                fail(f"{rel} missing required term: {term}")

    run_script = ROOT / "tools/lab/test-mac/run-mac.sh"
    subprocess.run(["bash", "-n", str(run_script)], check=True)
    if not os.access(run_script, os.X_OK):
        fail("tools/lab/test-mac/run-mac.sh must be executable")

    helper = ROOT / "tools/lab/test-mac/assert-rigged-profile.py"
    with tempfile.TemporaryDirectory(prefix="reeve-mac-lab-pycache-") as pycache:
        env = {**os.environ, "PYTHONPYCACHEPREFIX": pycache}
        subprocess.run(
            [sys.executable, "-m", "py_compile", str(helper)],
            check=True,
            env=env,
        )

    matrix = json.loads((ROOT / "tools/lab/test-mac/mac-matrix.yml").read_text())
    if len(matrix) != 5:
        fail("macOS matrix must define exactly 5 initial profiles")
    if not all("expected_aibom" in profile for profile in matrix):
        fail("each macOS profile must define expected_aibom")
    if not any("claude_desktop" in profile.get("agents", []) for profile in matrix):
        fail("macOS matrix must include Claude Desktop coverage")
    if not any("codex_cli" in profile.get("agents", []) for profile in matrix):
        fail("macOS matrix must include Codex App/CLI-compatible coverage")

    sample = ROOT / "private" / "test-mac-rigged-sample.aibom.json"
    sample.parent.mkdir(parents=True, exist_ok=True)
    sample.write_text(
        json.dumps(
            {
                "aibom": {
                    "evidence": [
                        {
                            "kind": "sandbox-filesystem",
                            "reference": "sandbox://scan/event-1/open#/etc/passwd:READ",
                        },
                        {
                            "kind": "sandbox-network",
                            "reference": "sandbox://scan/event-2/connect#-:80",
                        },
                    ]
                }
            }
        )
    )
    try:
        subprocess.run([sys.executable, str(helper), str(sample)], check=True)
    finally:
        sample.unlink(missing_ok=True)

    print("macOS Tart lab contract OK")


if __name__ == "__main__":
    main()
