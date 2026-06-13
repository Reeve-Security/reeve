# ADR-0027: Claude Cowork inventory is limited to local MCPB install state

- **Status:** Accepted; extended by ADR-0029 and ADR-0030 for Cowork state stores
- **Date:** 2026-05-25
- **Decides:** Scope boundary for Claude Cowork / Store extension inventory

## Context

Claude Cowork Store-package captures show multiple durable local stores:

- `claude_desktop_config.json`, which may contain no `mcpServers` when
  connectors are installed through Cowork UI flows;
- `extensions-installations.json`, which is plaintext JSON describing
  installed MCPB extensions, launch metadata, signature status, and declared
  tools;
- `Claude Extensions/*/manifest.json`, which can backfill extension metadata;
- `Claude Extensions Settings/*.json`, which carries enable state;
- encrypted Electron safeStorage/DPAPI blobs and binary IndexedDB/LevelDB
  stores for approvals and remote connectors.

MCPB itself is documented by Anthropic, but the Cowork Store-package files
above are app-internal observed stores. Treat their path grammar and JSON shape
as fixture-pinned and fragile until Anthropic publishes a stable Cowork state
contract.

Reeve needs useful Cowork evidence without expanding into token extraction,
remote connector reverse-engineering, or generic package scans.

## Decision

Reeve will inventory Claude Cowork local MCPB extension installs from the
Store/UWP package root:

```text
AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/extensions-installations.json
AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/Claude Extensions/*/manifest.json
AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/Claude Extensions Settings/*.json
```

This remains inside the MCP adapter because MCPB extensions register MCP
servers and emit the same canonical AIBOM component/capability evidence as
other MCP surfaces.

Reeve will not decrypt Electron safeStorage/DPAPI blobs, parse
IndexedDB/LevelDB remote connector stores, crawl marketplaces, or scan generic
endpoint `node_modules` as part of this decision.

## Consequences

- Cowork-installed local MCPB extensions can appear even when
  `claude_desktop_config.json` has no `mcpServers` block.
- Unsigned extension status and declared tool names become policy-visible as
  MCP namespace capabilities.
- Approval/allowlist and remote connector claims are handled only by later
  fixture-backed ADRs: ADR-0029 for opaque store presence and ADR-0030 for
  plaintext `cowork_plugins` connector manifests.
- Cowork app-internal file names and JSON shapes remain observed, fragile, and
  pinned by captured fixtures rather than treated as a vendor-stable API.
- Extension dependency inventory remains a separate scoped feature: only
  dependencies under registered AI harness extension roots, not generic
  endpoint package scanning.

## Plain-Language Summary

Reeve can read the plaintext Cowork files that list locally installed MCPB
extensions and their tools. Later ADRs add opaque approval-store presence and
plaintext `cowork_plugins` connector inventory, but Reeve still must not decrypt
approval caches or infer connector grants from encrypted/binary stores in this
scope.
