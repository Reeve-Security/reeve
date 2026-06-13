#!/usr/bin/env python3
"""Static contract checks for Phase 1 VPS validation tooling."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    ".github/workflows/sign-surface-config.yml",
    "tools/lab/test-vps/README.md",
    "tools/lab/test-vps/terraform/main.tf",
    "tools/lab/test-vps/terraform/variables.tf",
    "tools/lab/test-vps/terraform/outputs.tf",
    "tools/lab/test-vps/terraform/cloud-init.yml",
    "tools/lab/test-vps/ansible/ansible.cfg",
    "tools/lab/test-vps/ansible/inventory.example.yml",
    "tools/lab/test-vps/ansible/phase1-validate.yml",
    "tools/lab/test-vps/ansible/fleet-profile.yml",
    "tools/lab/test-vps/ansible/fleet-matrix.yml",
    "tools/lab/test-vps/ansible/assert-aibom.py",
    "tools/lab/test-vps/ansible/fixtures/approvals/claude-code-allow-deny.json",
    "tools/lab/test-vps/ansible/fixtures/approvals/claude-code-deny-heavy.json",
    "tools/lab/test-vps/ansible/fixtures/approvals/codex-cli-danger.toml",
    "tools/lab/test-vps/ansible/fixtures/mcp/claude-desktop-mcp.json",
    "tools/lab/test-vps/ansible/fixtures/mcp/cursor-mcp.json",
    "tools/lab/test-vps/ansible/fixtures/mcp/vscode-mcp.json",
    "tools/lab/test-vps/ansible/fixtures/mcp/continue-config.yaml",
    "tools/lab/test-vps/ansible/fixtures/mcp/zed-settings.json",
    "tools/lab/test-vps/ansible/fixtures/mcp/factory-mcp.json",
    "tools/lab/test-vps/ansible/fixtures/mcp/custom-surface-mcp.json",
    "tools/lab/test-vps/ansible/roles/reeve_install/tasks/release.yml",
    "tools/lab/test-vps/ansible/roles/reeve_install/tasks/install.yml",
    "tools/lab/test-vps/ansible/roles/reeve_surface_config/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/reeve_systemd/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_profile_user/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_claude_code/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_claude_code_deny/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_claude_desktop/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_codex_cli/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_cursor/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_vscode/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_continue/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_zed/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_factory/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/agent_custom_surface/tasks/main.yml",
    "tools/lab/test-vps/ansible/roles/assert_aibom/tasks/main.yml",
    "tools/lab/test-vps/ansible/verify.sh",
    "tools/lab/test-vps/run.sh",
    "tools/lab/test-vps/run-fleet.sh",
    "tools/lab/test-vps/destroy.sh",
]

TERMS = {
    ".github/workflows/sign-surface-config.yml": [
        "workflow_dispatch",
        "id-token: write",
        "cosign sign-blob",
        "surfaces.yaml.sigstore.json",
    ],
    "tools/lab/test-vps/README.md": [
        "Phase 1",
        "HCLOUD_TOKEN",
        "sign-surface-config.yml",
        "surface_signer_identity_regexp",
        "tofu apply",
        "./run.sh",
        "run-fleet.sh",
        "./run-fleet.sh all",
        "./run-fleet.sh --list",
        "fleet-matrix.yml",
        "private/fleet-<date>/<profile>/",
        "SUMMARY.md",
        "./destroy.sh",
        "ansible-playbook",
        "tofu destroy",
        "#62",
    ],
    "tools/lab/test-vps/terraform/main.tf": [
        "hetznercloud/hcloud",
        "data \"hcloud_ssh_key\"",
        "hcloud_server",
        "user_data",
    ],
    "tools/lab/test-vps/terraform/variables.tf": [
        "ubuntu-24.04",
        "cpx11",
        "ssh_key_name",
        "registered in Hetzner Cloud",
    ],
    "tools/lab/test-vps/terraform/cloud-init.yml": [
        "/etc/reeve-phase1-validation",
    ],
    "tools/lab/test-vps/ansible/ansible.cfg": [
        "roles_path = roles",
        "inject_facts_as_vars = False",
    ],
    "tools/lab/test-vps/ansible/phase1-validate.yml": [
        "include_role",
        "reeve_install",
        "reeve_surface_config",
        "reeve_systemd",
        "assert_aibom",
    ],
    "tools/lab/test-vps/ansible/fleet-profile.yml": [
        "profile_agents",
        "agent_profile_user",
        "agent_claude_code",
        "agent_claude_code_deny",
        "agent_claude_desktop",
        "agent_codex_cli",
        "agent_cursor",
        "agent_vscode",
        "agent_continue",
        "agent_zed",
        "agent_factory",
        "agent_custom_surface",
        "assert_aibom",
    ],
    "tools/lab/test-vps/ansible/fleet-matrix.yml": [
        "empty-ubuntu-24",
        "claude-code-approvals-ubuntu-22",
        "codex-app-config-ubuntu-24",
        "dev-stack-ubuntu-24",
        "fedora-43-codex-cli",
        "custom-surface-ubuntu-24",
        "deny-list-dominant-ubuntu-24",
        "claude-desktop-config-ubuntu-24",
        "mixed-nondev-ubuntu-24",
        "ubuntu-24.04",
        "fedora-43",
        "rocky-9",
        "expected_aibom",
    ],
    "tools/lab/test-vps/ansible/assert-aibom.py": [
        "AIBOM profile assertion OK",
        "min_occurrences",
    ],
    "tools/lab/test-vps/ansible/roles/reeve_install/tasks/release.yml": [
        "ansible_os_family == \"Debian\"",
        "ansible_os_family == \"RedHat\"",
        "cosign",
        "verify-blob",
        "aibom-cli.tar.xz.bundle",
    ],
    "tools/lab/test-vps/ansible/roles/reeve_install/tasks/install.yml": [
        "deploy/curl-install/install.sh",
        "REEVE_SURFACE_CONFIG_BUNDLE_URL",
    ],
    "tools/lab/test-vps/ansible/roles/reeve_surface_config/tasks/main.yml": [
        "cosign",
        "Verify surface config bundle before install",
        "surfaces.yaml.sigstore.json",
    ],
    "tools/lab/test-vps/ansible/roles/reeve_systemd/tasks/main.yml": [
        "scope",
        "list",
        "--require-signed-config",
        "scan_target_root",
        "reeve-scan.timer",
        "systemctl start reeve-scan.service",
        "/var/lib/reeve/scans",
    ],
    "tools/lab/test-vps/ansible/roles/agent_profile_user/tasks/main.yml": [
        "profile_user",
        "profile_home",
    ],
    "tools/lab/test-vps/ansible/roles/agent_claude_code/tasks/main.yml": [
        "{{ profile_home }}/.claude/settings.json",
        "claude-code-allow-deny.json",
    ],
    "tools/lab/test-vps/ansible/roles/agent_claude_code_deny/tasks/main.yml": [
        "{{ profile_home }}/.claude/settings.json",
        "claude-code-deny-heavy.json",
    ],
    "tools/lab/test-vps/ansible/roles/agent_claude_desktop/tasks/main.yml": [
        "{{ profile_home }}/.config/Claude/claude_desktop_config.json",
        "claude-desktop-mcp.json",
    ],
    "tools/lab/test-vps/ansible/roles/agent_codex_cli/tasks/main.yml": [
        "{{ profile_home }}/.codex/config.toml",
        "codex-cli-danger.toml",
    ],
    "tools/lab/test-vps/ansible/roles/agent_cursor/tasks/main.yml": [
        "{{ profile_home }}/.cursor/mcp.json",
        "cursor-mcp.json",
    ],
    "tools/lab/test-vps/ansible/roles/agent_vscode/tasks/main.yml": [
        "{{ profile_home }}/.config/Code/User/mcp.json",
        "vscode-mcp.json",
    ],
    "tools/lab/test-vps/ansible/roles/agent_continue/tasks/main.yml": [
        "{{ profile_home }}/.continue/config.yaml",
        "continue-config.yaml",
    ],
    "tools/lab/test-vps/ansible/roles/agent_zed/tasks/main.yml": [
        "{{ profile_home }}/.config/zed/settings.json",
        "zed-settings.json",
    ],
    "tools/lab/test-vps/ansible/roles/agent_factory/tasks/main.yml": [
        "{{ profile_home }}/.factory/mcp.json",
        "factory-mcp.json",
    ],
    "tools/lab/test-vps/ansible/roles/agent_custom_surface/tasks/main.yml": [
        "{{ profile_home }}/.phase1-agent/mcp.json",
        "custom-surface-mcp.json",
    ],
    "tools/lab/test-vps/ansible/roles/assert_aibom/tasks/main.yml": [
        "assert-aibom.py",
        "validation-summary.txt",
        "phase1-latest.aibom.json",
    ],
    "tools/lab/test-vps/run.sh": [
        "gh workflow run sign-surface-config.yml",
        "gh run watch",
        "tofu apply -auto-approve",
        "ansible-playbook",
    ],
    "tools/lab/test-vps/run-fleet.sh": [
        "fleet-matrix.yml",
        "profile_names",
        "run-fleet.sh\" \"${profile}\"",
        "profile_json",
        "tofu apply -auto-approve",
        "ansible-playbook -i inventory.yml fleet-profile.yml",
        "SUMMARY_ROW=",
        "awk -v profile=\"${PROFILE_NAME}\"",
        "index($0, \"| \" profile \" |\") == 1",
        "private/fleet-",
        "SUMMARY.md",
        "tofu destroy -auto-approve",
    ],
    "tools/lab/test-vps/destroy.sh": [
        "tofu destroy -auto-approve",
        "Billing stopped",
    ],
}


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    for rel in REQUIRED:
        path = ROOT / rel
        if not path.exists():
            fail(f"missing Phase 1 VPS file: {rel}")
        text = path.read_text()
        for term in TERMS.get(rel, []):
            if term not in text:
                fail(f"{rel} missing required term: {term}")

    for rel in [
        "tools/lab/test-vps/ansible/verify.sh",
        "tools/lab/test-vps/run.sh",
        "tools/lab/test-vps/run-fleet.sh",
        "tools/lab/test-vps/destroy.sh",
    ]:
        path = ROOT / rel
        subprocess.run(["bash", "-n", str(path)], check=True)
        if not os.access(path, os.X_OK):
            fail(f"{rel} must be executable")

    cloud_init = (ROOT / "tools/lab/test-vps/terraform/cloud-init.yml").read_text()
    for forbidden in ["package_update:", "package_upgrade:", "packages:", "systemd-timesyncd"]:
        if forbidden in cloud_init:
            fail(f"cloud-init must stay distro-neutral; forbidden term: {forbidden}")

    subprocess.run(
        [
            sys.executable,
            "-c",
            "import json, pathlib; m=json.loads(pathlib.Path('tools/lab/test-vps/ansible/fleet-matrix.yml').read_text()); assert len(m) >= 12; assert all('expected_aibom' in p for p in m); assert all(p.get('image') != 'fedora-40' for p in m)",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    print("Phase 1 VPS lab contract OK")


if __name__ == "__main__":
    main()
