# Pillar launch audit

Last updated: 2026-06-05

This is the launch claim boundary for Reeve's three product pillars. It
answers one question: what can the public README, demo script, blog, and
sales notes safely say today without implying unsupported coverage?

This document does not replace `docs/scope.md`. The scope document is
the path-level filesystem contract. This audit is the product-claim
contract that maps shipped code to the three pillars.

## Summary

| Pillar | Launch-supported slice | Not a safe claim today |
|---|---|---|
| 1. Tool access | MCP config inventory, explicit `tools/list` introspection, optional profile evidence for documented surfaces | "All AI tools", browser extensions, OAuth/webhooks, or Windows sandbox enforcement |
| 2. Approvals | Granted-permission evidence for Claude Code, Codex CLI, and Codex App saved-approval formats | Saved approvals for every assistant or every MCP surface |
| 3. Conversation secrets | Two-opt-in sensitive-data report for Claude Desktop, Claude Code, Claude Cowork, Cursor, Codex CLI, and Codex App stores | Default conversation scanning, raw content export, PII classification, or custom rule packs |

The pillars are launchable as a bounded, documented slice. They are not
universally complete across every AI assistant, every OS-specific
storage path, or every future agent feature.

## Pillar 1: Tool access

Tool access means: Reeve inventories MCP servers registered on an
endpoint, records config-derived identity by default, can request MCP
`tools/list` only after explicit operator consent, and can optionally
profile local stdio MCP servers under the platform boundary documented
in `docs/scope.md`.

### Safe claims

- Default scans read documented config paths only; they do not execute
  MCP servers.
- Built-in MCP config discovery covers Claude Desktop, Claude Cowork, Cursor,
  Continue, Claude Code, Codex CLI, Factory, Zed, and VS Code MCP.
- Signed or explicitly supplied custom MCP surface configs can extend
  discovery with `source: "user-defined"` lower-trust labeling.
- Claude Desktop MCP config discovery includes the Windows user path
  `AppData/Roaming/Claude/claude_desktop_config.json`.
- `--introspect-execute` is a separate consent tier that may execute a
  local stdio MCP server briefly to request `tools/list`.
- `--profile` is another consent tier that produces observed behavior
  evidence. macOS uses `sandbox-exec`; Linux uses Landlock/seccomp when
  available and explicitly labels fallback observation; Windows is
  observational only under ADR-0017.
- Reeve produces evidence for the customer's policy process. It does
  not approve, block, remediate, patch, or secure the endpoint.

### Unsafe claims

- Do not say Reeve covers all AI tools, all desktop extensions, all
  browser extensions, all OAuth grants, or all webhooks.
- Do not say Windows behavior evidence is sandbox enforcement.
  AppContainer remains deferred.
- Do not say Reeve runs every AI tool in a sandbox. Profiling is
  opt-in, and the enforcement boundary depends on the OS.
- Do not say Reeve sees live traffic. ADR-0022 keeps Reeve as a config
  reader and evidence producer, not an MCP proxy.

### Remaining gaps

| Gap | Tracker | Launch demo blocker? |
|---|---|---|
| Real Windows Claude Desktop demo validation | #100 | Yes, if the recording shows real Windows Claude Desktop discovery |
| Real Windows Claude Desktop conversation-store smoke | #217 | Yes, if the recording claims real Windows conversation-secret validation |
| Browser extensions / IDE plugins beyond MCP | #181 | No; v0.3+ expansion |
| Connected services, OAuth, API keys, webhooks | #183 | No; v0.3+ expansion |
| Signed fleet manifest for cloud-demo evidence chain | #218 | Demo-infra blocker, not a Pillar 1 scanner blocker |

## Pillar 2: Approvals

Approvals means: Reeve emits saved approval state as
`granted-permission` evidence where an adapter has a known, tested
format for durable user approvals.

### Safe claims

- AIBOM v0.2 supports a `granted` capability source and
  `granted-permission` evidence records.
- Claude Code approval parsing covers `.claude/settings.json`
  `permissions.allow`.
- Codex CLI approval parsing covers `.codex/config.toml`
  `projects.*.approval_policy` and `projects.*.sandbox_mode`.
- Codex App approval parsing covers `.codex/config.toml`
  `apps.*.tools.*.approval_mode` and emits privacy-safe
  `codex-app://config#...` evidence references instead of local file paths.
- Claude Desktop approval parsing covers `claude_desktop_config.json`
  `preferences.localAgentModeTrustedFolders[]` on macOS and Windows,
  emitting `fs:read` / `fs:write` grants only for absolute trusted-folder
  paths, with home/user identity redacted from saved-grant path qualifiers.
- Reports and policies can surface risky saved approvals for those
  supported formats.
- Approval evidence is read-only. Reeve does not alter, revoke, or
  enforce approvals.

### Unsafe claims

- Do not say Reeve inventories all "always allow" approvals.
- Do not claim broad saved-approval coverage for Claude Desktop beyond
  plaintext trusted folders, or for Cursor, Continue, Factory, Zed,
  VS Code MCP, or Cowork until real fixtures prove their durable
  approval formats.
- Do not claim last-used timestamps for approvals. That is separate
  future work.

### Remaining gaps

| Gap | Tracker | Launch demo blocker? |
|---|---|---|
| Real approval-state fixtures for remaining MCP surfaces | #167 | Only if demo claims those surfaces' approvals |
| Umbrella saved-permissions inventory beyond current parsers | #83 / #4 | No, unless public copy broadens the approval claim |
| Last-used timestamps for approval entries | #182 | No; v0.3+ expansion |

## Pillar 3: Conversation secrets

Conversation secrets means: Reeve can produce a separate signed
sensitive-data report for supported conversation/session roots when the
operator passes explicit opt-in flags.

### Safe claims

- Default scans do not read conversation logs or session stores.
- `--include-conversation-metadata` inventories metadata only: redacted
  path, file count, total bytes, and timestamps.
- `--scan-conversation-secrets` is a second opt-in that reads content
  under supported roots and runs bundled secret-pattern rules.
- The report is separate from the AIBOM and excludes raw conversation
  content, surrounding snippets, raw secret values, embeddings,
  screenshots, searchable indexes, and hashes of secret values.
- Supported roots today are:
  - Claude Desktop macOS:
    `Library/Application Support/Claude/projects/**`
  - Claude Desktop Windows:
    `AppData/Roaming/Claude/projects/**`
  - Claude Code:
    `.claude/projects/**`
  - Claude Cowork macOS:
    `Library/Application Support/Claude/local-agent-mode-sessions/*/*/**`
  - Claude Cowork Windows:
    `AppData/Roaming/Claude/local-agent-mode-sessions/*/*/**`
  - Claude Cowork Windows Store package root:
    `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/**`
  - Cursor:
    `.cursor/projects/*/agent-transcripts/*/**`
  - Codex App macOS:
    `Library/Application Support/Codex/archived_sessions/**`
  - Codex App Windows:
    `.codex/sessions/**` when `.codex/config.toml` contains App plugin or marketplace state
  - Codex CLI:
    `.codex/sessions/**`
- Reeve labels the shared `.codex/sessions/**` store as either
  `codex-app` or `codex-cli` in one scan, not both.
- Bundled default pattern classes are `anthropic-api-key`,
  `aws-access-key`, `jwt`, `oauth-client-secret`, `openai-api-key`, and
  `stripe-key`.

### Unsafe claims

- Do not say Reeve scans conversations by default.
- Do not say Reeve exports or stores raw conversations.
- Do not claim PII classification.
- Do not claim customer rule templates or PII classifiers ship.
- Do not claim Continue, Factory, Zed, or VS Code
  conversation-store coverage until those roots are implemented and
  documented.
- Do not claim real Windows Claude Desktop conversation-secret validation
  until #217 closes with a real Windows smoke result.

### Remaining gaps

| Gap | Tracker | Launch demo blocker? |
|---|---|---|
| Real Windows Claude Desktop conversation-store smoke | #217 | Yes, if demo claims real Windows validation |
| Sensitive-data report fixtures and lab profile | #175 | No for core loop; yes if launch claims lab-validated breadth beyond current fixtures |
| Customer rule templates | #178 follow-up | No; do not claim until a template pack ships |
| PII / non-public-data classifier | #184 | No; v0.3+ expansion |
| Sensitive-data report policies | #172 | No, unless demo claims policy verdicts over sensitive-data reports |
| SARIF rendering for sensitive-data findings | #173 | No; output-format expansion |

## Demo-script rule

The demo script may use only claims in the "safe claims" sections above.
If a future scene names Cowork, additional approval surfaces, real
Windows conversation-store validation, or a central corpus result, the
corresponding tracker must be closed or the scene must be marked as
future work.

No demo language should say "Reeve secured the endpoint." The precise
claim is: Reeve inventoried the configured AI tool surface and produced
signed evidence for the customer's existing security process.

## Launch-readiness reading order

For any launch claim review, read in this order:

1. `docs/scope.md` for exact read paths and execution boundaries.
2. This audit for allowed and forbidden pillar claims.
3. `README.md` for the public quickstart and status language.
4. `docs/demo-script.md` only after the script is ready to be checked
   against this audit.
