#!/usr/bin/env python3
"""Contract check for OSS-safe files under tools/."""

from __future__ import annotations

import ipaddress
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

FORBIDDEN_TRACKED_SUFFIXES = (
    "terraform.tfstate",
    "terraform.tfstate.backup",
    ".tfstate",
    ".tfstate.backup",
    "inventory.yml",
)
FORBIDDEN_PATH_PARTS = (
    "/evidence/",
    "/.terraform/",
)
FORBIDDEN_TEXT_PATTERNS = {
    "personal home path": re.compile(r"/Users/|/home/[A-Za-z0-9._-]+"),
    "ssh path assumption": re.compile(r"~/.ssh/|\$HOME/.ssh/|\${HOME}/.ssh/"),
    "private key material": re.compile(r"BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY"),
    "github token": re.compile(r"\b(?:gh[opusr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    "developer username": re.compile(r"\bdgem8\b"),
}
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOC_ONLY_ALLOWED_PRIVATE_REFS = ("`private/`",)
ALLOWED_TEST_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/32"),
)


def fail(message: str) -> None:
    raise SystemExit(message)


def tracked_tools_files() -> list[pathlib.Path]:
    result = subprocess.run(
        ["git", "ls-files", "tools"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [ROOT / line for line in result.stdout.splitlines() if line]


def is_allowed_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in network for network in ALLOWED_TEST_NETS)


def main() -> int:
    files = tracked_tools_files()
    if not files:
        fail("tools/: expected tracked OSS tooling files")

    for path in files:
        rel = path.relative_to(ROOT).as_posix()
        if rel.endswith(FORBIDDEN_TRACKED_SUFFIXES):
            fail(f"{rel}: generated local state must not be tracked")
        if any(part in f"/{rel}" for part in FORBIDDEN_PATH_PARTS):
            fail(f"{rel}: local runtime directory must not be tracked")

        text = path.read_text(errors="ignore")
        for name, pattern in FORBIDDEN_TEXT_PATTERNS.items():
            match = pattern.search(text)
            if match:
                fail(f"{rel}: forbidden {name}: {match.group(0)}")

        for match in IPV4.finditer(text):
            ip = match.group(0)
            if not is_allowed_ip(ip):
                fail(f"{rel}: concrete non-documentation IPv4 address: {ip}")

        if "private/" in text:
            for line in text.splitlines():
                if "private/" in line and not any(allowed in line for allowed in DOC_ONLY_ALLOWED_PRIVATE_REFS):
                    fail(f"{rel}: private/ reference must stay limited to documented phase input paths")

    print("tools OSS readiness contract OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
