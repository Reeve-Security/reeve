# Demo Fleet Archetypes

> **Current recording source:** ADR-0023 and
> [`infra/demo-fleet/variant-matrix.md`](../infra/demo-fleet/variant-matrix.md)
> define the one-shot 50-endpoint recording dataset. This file remains a
> background archetype catalog from the earlier #59 planning stream.

Issue #59 uses these archetypes as the content contract for the 45-endpoint
demo fleet. They are lab fixtures, not product defaults. Each archetype
must produce believable MCP config state, signed Reeve evidence, and at
least one customer-readable story.

## Fleet Shape

Target fleet:

| OS family | Count | Required variants |
|---|---:|---|
| macOS | 15 | macOS 14 + macOS 15, Apple Silicon primary |
| Linux | 15 | Ubuntu 22.04, Ubuntu 24.04, Debian 12, Fedora, Arch or RHEL 9 |
| Windows | 15 | Windows 11 + Windows 10, x86_64 |

User mix:

| Audience | Minimum endpoints | Archetypes |
|---|---:|---|
| Developer | 30 | seven developer archetypes below |
| Non-developer | 15 | five knowledge-worker archetypes below |

This keeps non-developer profiles at 33%, above the issue #59 minimum of
30%.

## Required Per-Endpoint Content

Every Packer image or first-boot profile must define:

- hostname prefix matching the archetype id;
- local user account with role-appropriate home directory content;
- one or more MCP config files in paths covered by `docs/scope.md`;
- system-wide signed `surfaces.yaml` plus
  `surfaces.yaml.sigstore.json` where custom surfaces are needed;
- scheduled Reeve scan using the deployment template from
  `tools/deploy/` or `tools/mdm/`;
- expected policy verdicts, including clean cases; and
- one short demo sentence explaining what a buyer learns from the
  endpoint.

The goal is evidence realism. Do not add fake protocol adapters or
non-MCP scanner behavior.

## Developer Archetypes

| Archetype | OS coverage | Surfaces | Expected evidence | Demo sentence |
|---|---|---|---|---|
| `dev-cursor-claude-mcp-clean` | macOS, Linux, Windows | Cursor, Claude Desktop | signed config, no deny verdicts | "Managed developer endpoint: Reeve proves the expected MCP stack is present and clean." |
| `dev-codex-vscode-loose` | macOS, Linux, Windows | Codex CLI, VS Code MCP | declared/observed capability delta | "A server claims one capability set but observed behavior is wider." |
| `dev-shadow-stack` | macOS, Linux, Windows | Cursor, Claude Code | publisher allowlist deny | "Shadow AI tooling appears outside the approved publisher set." |
| `dev-stale-config` | macOS, Linux | Claude Desktop, Continue | stale scan-age or missing provenance warning | "Old config remains registered even after the tool is no longer actively used." |
| `dev-prod-leakage` | Linux, macOS | Claude Code, Codex CLI | secret-read or sensitive-path evidence | "Local production-like secrets are reachable from an MCP server registration." |
| `dev-overgranted` | macOS, Windows | VS Code MCP, Cursor | granted capability exceeds declared behavior | "Permissions granted by config are broader than what the tool says it needs." |
| `dev-shadow-mcp-server` | Linux, Windows | user-defined custom surface | custom-surface discovery evidence | "Customer-defined surfaces reveal MCP registrations outside known vendor paths." |

## Non-Developer Archetypes

| Archetype | OS coverage | Surfaces | Expected evidence | Demo sentence |
|---|---|---|---|---|
| `hr-claude-resume-screening` | macOS, Windows | Claude Desktop | document-read filesystem evidence | "HR laptops running Claude are in scope even without developer tools." |
| `accounting-codex-spreadsheet` | Windows, Linux | Codex CLI, spreadsheet MCP | sensitive-file read warning | "Finance workflows can expose spreadsheet paths through AI automation." |
| `marketing-claude-image-gen` | macOS, Windows | Claude Desktop, image-generation MCP | network egress evidence | "Marketing AI tools create external service dependencies that security teams need to see." |
| `sales-cursor-crm-scripts` | Windows, macOS | Cursor, VS Code MCP | CRM token path or network evidence | "Sales scripting around CRM systems becomes inventory evidence, not tribal knowledge." |
| `legal-claude-document-review` | macOS, Windows | Claude Desktop | broad filesystem grant warning | "Legal document review needs explicit proof of which directories AI tooling can reach." |

## Image Inputs

Each archetype directory, when implemented under future Packer inputs,
should carry these files:

```text
archetypes/<id>/
  README.md                 # story, OS targets, expected verdicts
  surfaces.yaml             # custom surfaces for this profile, if any
  surfaces.yaml.sigstore.json
  mcp/
    claude_desktop_config.json
    cursor-mcp.json
    codex-config.toml
    vscode-settings.json
  sample-home/
    documents/
    projects/
    secrets/
  expected/
    verdicts.json
    aggregate-row.md
```

Config files may be absent when the archetype does not use that surface.
Keep sample secrets fake, deterministic, and clearly marked as fixtures.

## Evidence Contract

Each endpoint must run:

```bash
aibom-cli scan --target "$HOME" \
  --introspect-execute --introspect-execute-yes \
  --profile --profile-yes \
  --policy-check \
  --sign-mode real \
  --output-dir "/srv/reeve-lab/$HOSTNAME"
```

For Windows endpoints, `--profile` records observational evidence or an
explicit telemetry-gap marker. Do not describe Windows results as
sandbox enforcement until AppContainer work lands.

The lab collector then runs:

```bash
tools/lab/aggregate.sh /srv/reeve-lab > /srv/reeve-lab/summary.md
```

`summary.md` must include at least one clean endpoint, one deny verdict,
one warning verdict, one Windows endpoint, and one non-developer
endpoint.

## Blockers Before Full Fleet Build

- #62 still needs at least one true endpoint/package validation before
  these templates are treated as deployment-certified.
- Lab hosts must exist: Ubuntu NUC for libvirt/KVM and Apple Silicon Mac
  mini for Tart.
- Windows VM licensing and activation path must be documented before
  scaling beyond local demo use.
