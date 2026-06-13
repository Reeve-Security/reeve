# ADR-0029: Claude Cowork opaque approval and remote connector state reporting

- **Status:** Accepted; amended by ADR-0030 for plaintext `cowork_plugins` connector manifests and ADR-0039 for plaintext session approval fields
- **Date:** 2026-05-25
- **Decides:** Support boundary for Claude Cowork approval-state and remote-connector stores
- **Related:** ADR-0027, ADR-0028, ADR-0030, ADR-0039, `docs/scope.md`, GitHub issue #247, GitHub issue #252

## Context

Reeve already inventories Claude Cowork local MCPB extension installs under
ADR-0027 and scoped extension npm dependencies under ADR-0028. That support is
limited to plaintext local extension state observed in the Windows Store/UWP
Claude package root.

The remaining Cowork question is saved approval/allowlist state and remote
marketing connector state. Evidence recorded in GitHub issue #247 shows:

- `extensions-installations.json` is parseable JSON for installed MCPB
  extensions.
- `Claude Extensions Settings/*.json` was observed to contain only
  `{"isEnabled": true}` enable-state data.
- `config.json` contains `dxt:allowlistCache` for extension
  allowlist/approval state, but the observed value is an encrypted Electron
  safeStorage blob using the `v10` / DPAPI form.
- Remote connector approval state points to Electron app stores such as
  IndexedDB/LevelDB under the Store/UWP package, but the record format is not
  documented. ADR-0030 separately covers plaintext connector registration
  manifests found under `cowork_plugins`.

Reeve needs useful evidence without crossing into credential extraction,
decrypting local app secrets, or claiming connector inventory that is not
fixture-proven.

## Options considered

### A. Claim full support from local MCPB extension inventory alone

Rejected. Installed local MCPB extensions are useful evidence, but approval
state and remote connector state live separately.

### B. Decrypt and parse every observed Cowork store now

Rejected. Decrypting `dxt:allowlistCache` and parsing LevelDB records could
eventually produce richer evidence, but it needs separate fixture proof and a
security decision. It risks extracting credentials or app-private state.

### C. Report opaque store presence only *(chosen)*

Chosen. Reeve records that the encrypted approval cache exists and that likely
Electron LevelDB/IndexedDB connector stores exist. It does not decrypt blob
values, parse LevelDB records, emit tokens, or claim effective Cowork approval
grants.

## Decision

Reeve reports `config.json` `dxt:allowlistCache` presence as declared
capability `mcp:cowork:approval-cache:encrypted` with qualifiers that mark the
store as `electron-safeStorage-dpapi` and `presence-only`.

Reeve reports candidate Electron connector stores under the Cowork app root as
declared capability `mcp:cowork:remote-connector-store:candidate` with
qualifiers that mark the store format, path, and `presence-only` support:

- `IndexedDB/*.leveldb`
- `Local Storage/leveldb`

Reeve does not decrypt Electron safeStorage/DPAPI data, parse IndexedDB or
LevelDB records, extract credentials, or emit Cowork `granted` capabilities
from these stores. Reeve inventories connector URLs/names only from plaintext
`cowork_plugins/**/*.mcp.json` manifests under ADR-0030, not from encrypted or
LevelDB stores.

This uses the existing `mcp:*` extension capability namespace, so no AIBOM
schema bump is required. The observed Cowork app-internal paths are flagged as
fragile and fixture-pinned because Anthropic does not publish them as a stable
contract.

## Rationale

Presence-only reporting is the useful middle ground. Operators can see that
there is durable Cowork approval or connector state outside the plaintext MCPB
extension inventory, while Reeve avoids unsafe parsing and overclaiming.

This preserves the product boundary: local Cowork MCPB extensions and extension
dependencies are inventoried; encrypted approval blobs and opaque connector
stores are detected but not decoded.

## Plain-language summary

Reeve can now say, "Cowork has an encrypted approval cache here" and "Cowork has
candidate remote connector state stores here." It cannot say which approvals or
remote connectors are inside those opaque stores.

Reeve does not decrypt the approval blob and does not read LevelDB records. It
records presence only, so customers know more work is needed before treating the
endpoint as fully covered.

## Consequences

- **This decision commits the project to:** reporting Cowork opaque state-store
  presence without secret extraction or connector claims from encrypted/binary
  stores.
- **This decision unblocks:** a useful #252 implementation slice that is safe to
  test on real Windows installs.
- **This decision forecloses:** implying that store presence proves a specific
  approval, connector, URL, token, or grant.
- **This decision defers:** any safeStorage/DPAPI decrypt behavior, exact
  IndexedDB/LevelDB record parsing, connector identity inventory from those
  stores, and any future security decision for reading encrypted/binary app
  state.

## References

- `docs/decisions/0027-claude-cowork-local-mcpb-inventory.md`
- `docs/decisions/0028-ai-harness-extension-npm-dependency-inventory.md`
- `docs/scope.md`
- GitHub issue #247 comment: https://github.com/Reeve-Security/reeve/issues/247#issuecomment-4534012291
- GitHub issue #252: https://github.com/Reeve-Security/reeve/issues/252
