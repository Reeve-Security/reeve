#!/usr/bin/env python3
"""Static checks for Reeve deployment templates."""

from __future__ import annotations

import subprocess
import tempfile
from os import environ
from pathlib import Path
from platform import system
from shutil import which


ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "tools/mdm/README.md",
    "tools/mdm/jamf/README.md",
    "tools/mdm/jamf/postinstall.sh",
    "tools/mdm/intune/README.md",
    "tools/mdm/intune/install-windows.ps1",
    "tools/mdm/intune/install-macos.sh",
    "tools/mdm/workspace-one/README.md",
    "tools/mdm/workspace-one/install.sh",
    "tools/deploy/README.md",
    "tools/deploy/VALIDATION.md",
    "tools/deploy/curl-install/README.md",
    "tools/deploy/curl-install/install.sh",
    "tools/deploy/ansible/README.md",
    "tools/deploy/ansible/reeve.yml",
    "tools/deploy/group-policy/README.md",
    "tools/deploy/group-policy/install-reeve.ps1",
]

NEEDLES = [
    "--require-signed-config",
    "surfaces.yaml.sigstore.json",
]


def main() -> None:
    for rel in REQUIRED:
        path = ROOT / rel
        if not path.exists():
            raise SystemExit(f"missing deployment template: {rel}")
        text = path.read_text()
        for needle in NEEDLES:
            if rel.endswith((".sh", ".ps1")) and needle not in text:
                raise SystemExit(f"{rel} missing {needle}")
        if rel.endswith((".sh", ".ps1")) and "signeridentityregexp" not in text.replace("_", "").lower():
            raise SystemExit(f"{rel} missing signer identity regexp")
        if rel.endswith("README.md"):
            if "surfaces.yaml.sigstore.json" not in text:
                raise SystemExit(f"{rel} missing signed bundle reference")
            if "signer" not in text.lower():
                raise SystemExit(f"{rel} missing signer customization reference")

    for script in sorted((ROOT / "tools").glob("**/*.sh")):
        subprocess.run(["bash", "-n", str(script)], check=True)
    if which("shellcheck"):
        subprocess.run(["shellcheck", *map(str, sorted((ROOT / "tools").glob("**/*.sh")))], check=True)
    if which("pwsh"):
        for script in sorted((ROOT / "tools").glob("**/*.ps1")):
            subprocess.run(
                [
                    "pwsh",
                    "-NoProfile",
                    "-Command",
                    "$null = [scriptblock]::Create([Console]::In.ReadToEnd())",
                ],
                input=script.read_text(),
                text=True,
                check=True,
            )

    if "ansible.builtin.systemd" not in (ROOT / "tools/deploy/ansible/reeve.yml").read_text():
        raise SystemExit("ansible playbook missing systemd timer")

    validate_curl_install_template()

    print("deployment template contract OK")


def validate_curl_install_template() -> None:
    with tempfile.TemporaryDirectory(prefix="reeve-deploy-template-") as tmp:
        base = Path(tmp)
        remote = base / "remote"
        root = base / "endpoint"
        log = base / "stub.log"
        remote.mkdir()
        root.mkdir()

        binary = remote / "aibom-cli"
        binary.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${REEVE_STUB_LOG:?missing REEVE_STUB_LOG}"
test -f "${REEVE_INSTALL_ROOT:?missing REEVE_INSTALL_ROOT}/etc/reeve/surfaces.yaml" || test -f "${REEVE_INSTALL_ROOT}/Library/Application Support/Reeve/surfaces.yaml"
test -f "${REEVE_INSTALL_ROOT}/etc/reeve/surfaces.yaml.sigstore.json" || test -f "${REEVE_INSTALL_ROOT}/Library/Application Support/Reeve/surfaces.yaml.sigstore.json"
case "$*" in
  *"scope list"*"--require-signed-config"*"--signer-identity-regexp"*) exit 0 ;;
  *) echo "unexpected aibom-cli args: $*" >&2; exit 2 ;;
esac
"""
        )
        binary.chmod(0o755)
        config = remote / "surfaces.yaml"
        bundle = remote / "surfaces.yaml.sigstore.json"
        config.write_text("version: 1\nsurfaces: []\n")
        bundle.write_text('{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}\n')

        env = environ.copy()
        env.update(
            {
                "REEVE_BINARY_URL": binary.as_uri(),
                "REEVE_SURFACE_CONFIG_URL": config.as_uri(),
                "REEVE_SURFACE_CONFIG_BUNDLE_URL": bundle.as_uri(),
                "REEVE_SIGNER_IDENTITY_REGEXP": r"^https://github.com/Reeve-Security/reeve/.*$",
                "REEVE_INSTALL_ROOT": str(root),
                "REEVE_SKIP_SCHEDULER": "1",
                "REEVE_STUB_LOG": str(log),
            }
        )
        subprocess.run(
            ["bash", str(ROOT / "tools/deploy/curl-install/install.sh")],
            check=True,
            env=env,
            stdout=subprocess.DEVNULL,
        )

        if system() == "Darwin":
            expected = [
                root / "usr/local/bin/aibom-cli",
                root / "Library/Application Support/Reeve/surfaces.yaml",
                root / "Library/Application Support/Reeve/surfaces.yaml.sigstore.json",
                root / "Library/LaunchDaemons/com.reeve.scan.plist",
            ]
            scheduler = (root / "Library/LaunchDaemons/com.reeve.scan.plist").read_text()
        else:
            expected = [
                root / "usr/local/bin/aibom-cli",
                root / "etc/reeve/surfaces.yaml",
                root / "etc/reeve/surfaces.yaml.sigstore.json",
                root / "etc/systemd/system/reeve-scan.service",
                root / "etc/systemd/system/reeve-scan.timer",
            ]
            scheduler = (root / "etc/systemd/system/reeve-scan.service").read_text()
        for path in expected:
            if not path.exists():
                raise SystemExit(f"curl-install endpoint validation missing {path}")
        if "--require-signed-config" not in scheduler or "--signer-identity-regexp" not in scheduler:
            raise SystemExit("curl-install endpoint validation missing signed-config scheduler flags")
        if "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin" not in scheduler:
            raise SystemExit("curl-install endpoint validation missing scheduler PATH for cosign")
        if system() == "Darwin" and "<key>HOME</key><string>/var/root</string>" not in scheduler:
            raise SystemExit("curl-install endpoint validation missing launchd root HOME for cosign")
        if system() != "Darwin" and "Environment=HOME=/root" not in scheduler:
            raise SystemExit("curl-install endpoint validation missing systemd root HOME for cosign")
        if "scope list --require-signed-config --signer-identity-regexp" not in log.read_text():
            raise SystemExit("curl-install endpoint validation did not verify signed config")


if __name__ == "__main__":
    main()
