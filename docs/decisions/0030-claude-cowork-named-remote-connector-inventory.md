# ADR-0030: Claude Cowork named remote connector inventory from plaintext plugin manifests

- **Status:** Accepted
- **Date:** 2026-05-25
- **Decides:** Inventory Cowork named remote connectors from plaintext `cowork_plugins` state
- **Related:** ADR-0027, ADR-0028, ADR-0029, `docs/scope.md`, GitHub issue #247, GitHub issue #252

## Context

ADR-0029 deliberately limited Cowork remote connector support to opaque
IndexedDB/LevelDB presence because that state is app-internal and not safely
parseable yet. Later fixture research found a separate plaintext path for the
connector registration list:

- `LocalCache/Roaming/Claude/local-agent-mode-sessions/<account>/<org>/cowork_plugins/installed_plugins.json`
- bundled plugin manifests under `cowork_plugins/**/*.mcp.json`
- sibling `cowork_settings.json` with `enabledPlugins` and
  `extraKnownMarketplaces` state

This path can identify which named HTTP MCP connectors the endpoint is
registered to call without decrypting approval blobs or parsing LevelDB records.

## Options considered

### A. Keep only opaque presence markers

Rejected. Presence markers are safe, but they miss the high-value endpoint
fact: "this agent has Slack, HubSpot, or Gmail registered as a remote MCP
connector."

### B. Parse plaintext plugin state and keep approvals presence-only *(chosen)*

Chosen. Reeve follows `installed_plugins.json` to bundled `.mcp.json`
manifests, emits connector names, transport, and URL, and reads
`cowork_settings.json` only for enable-state. Encrypted approval caches and
IndexedDB/LevelDB stores remain presence-only.

### C. Decode IndexedDB/LevelDB and approval blobs

Rejected for this slice. That may eventually expose per-tool approvals or richer
connector metadata, but it requires separate fixture proof and a security
decision for encrypted/binary app state.

## Decision

Reeve inventories Cowork named remote connectors from the Store/UWP package root
using package-root glob discovery:

```text
AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_plugins/installed_plugins.json
AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_settings.json
AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_plugins/**/*.mcp.json
```

For each installed plugin, Reeve resolves the bundled `.mcp.json` manifest and
emits a normal MCP provider plus declared capability
`mcp:cowork:remote-connector:registered` with qualifiers for connector id,
name, transport, URL, enable-state when known, and manifest path.

Reeve does not crawl marketplaces, decrypt `dxt:allowlistCache`, parse
IndexedDB/LevelDB connector approval records, extract tokens, or emit Cowork
`granted` capabilities from this state.

## Rationale

This is the narrow useful evidence path. The connector registration manifests
are plaintext and bounded below the observed Cowork session directory, so Reeve
can prove connector presence by name without crossing into secrets or app-private
approval records.

The path is still observed, not documented by Anthropic as a stable contract.
That means it must stay registry-scoped, fixture-pinned to the real Store path,
and marked fragile in docs.

## Plain-language summary

Reeve can now say, "This endpoint has Cowork registered to call Slack over HTTP"
when Cowork stores that fact in plaintext plugin manifests.

Reeve still cannot say which Slack tools were approved or which calls are
currently allowed. Approval state stays encrypted or app-internal, so Reeve only
reports that those opaque stores exist.

## Consequences

- **This decision commits the project to:** bounded `cowork_plugins` connector
  inventory with real Store-path fixtures.
- **This decision unblocks:** VM validation for named Cowork marketing
  connectors such as Slack, HubSpot, Gmail, Canva, Amplitude, or Klaviyo when
  present.
- **This decision forecloses:** treating opaque LevelDB/IndexedDB presence as
  named connector inventory.
- **This decision defers:** approval decrypt/parsing, per-tool connector grants,
  remote marketplace crawling, and token extraction.

## References

- `docs/decisions/0027-claude-cowork-local-mcpb-inventory.md`
- `docs/decisions/0028-ai-harness-extension-npm-dependency-inventory.md`
- `docs/decisions/0029-claude-cowork-approval-and-remote-connector-state.md`
- `docs/scope.md`
- GitHub issue #247 comment: https://github.com/Reeve-Security/reeve/issues/247#issuecomment-4534012291
- GitHub issue #252: https://github.com/Reeve-Security/reeve/issues/252
