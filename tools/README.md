# Tools

`tools/` holds reusable open-source deployment helpers and MDM templates
that support Reeve's published install path: ways to roll Reeve out across
a fleet of endpoints.

## What's here

- `deploy/` holds install patterns for teams without full MDM: curl install,
  Ansible, and Windows Group Policy.
- `mdm/` holds templates for teams with endpoint management: Jamf Pro,
  Microsoft Intune, and Workspace ONE.

Each subdirectory has its own README with platform-specific steps.

The templates verify the signed surface config but do not sign scan output;
output signing is tracked post-launch.

## Boundary

Do not commit local run output, customer material, secrets, or
environment-specific files into `tools/` or any tracked directory.

Tracked files under `tools/` must stay reusable and placeholder-only:

- no generated state, inventories, or evidence outputs;
- no real server IPs, tokens, customer names, or personal workstation paths;
- example IPs use documentation ranges such as `203.0.113.0/24`.

CI enforces this with `scripts/check-tools-oss-readiness.py` plus gitleaks.
