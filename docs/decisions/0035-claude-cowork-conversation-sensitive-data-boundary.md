# ADR-0035: Claude Cowork conversation scanning stays in the opt-in sensitive-data report

- **Status:** Accepted
- **Date:** 2026-06-05
- **Decides:** Privacy boundary for Claude Cowork conversation/session-store scanning on macOS and Windows
- **Related:** ADR-0019, ADR-0027, ADR-0029, ADR-0030, `docs/scope.md`, GitHub issue #422, GitHub issue #423

## Context

Reeve already supports an ADR-0019 sensitive-data report for opt-in
conversation/session-store metadata and secret-pattern findings. This report is
separate from the AIBOM and never serializes raw conversation content, raw
secret values, surrounding snippets, embeddings, screenshots, searchable
indexes, or hashes of secret values.

Claude Cowork stores useful plaintext session files under
`local-agent-mode-sessions/*/*/**` on macOS and Windows. The same application
also has opaque Electron stores such as `IndexedDB/`, `Local Storage/leveldb/`,
and encrypted safeStorage/DPAPI approval state. Those opaque stores are already
presence-only under ADR-0029 and must not become conversation parsers by
accident.

## Options Considered

### A. Emit Cowork conversation evidence in the AIBOM

Rejected. Transcript-derived findings are more private than the broad inventory
artifact. Putting them in the AIBOM would weaken the sharing boundary.

### B. Parse Cowork Electron stores for broader coverage

Rejected. This would require LevelDB/IndexedDB parsing or encrypted store
handling. That is outside the launch boundary and would need a separate ADR and
fixtures.

### C. Reuse ADR-0019 and add only plaintext Cowork session roots *(chosen)*

Chosen. Reeve inventories metadata only under `--include-conversation-metadata`,
reads contents only under `--scan-conversation-secrets`, and emits only the
existing redacted sensitive-data report fields.

## Decision

Claude Cowork conversation/session-store scanning is implemented only through
the separate ADR-0019 sensitive-data report.

Reeve supports these Claude Cowork roots:

1. `Library/Application Support/Claude/local-agent-mode-sessions/*/*/**` as
   `claude-cowork`.
2. `AppData/Roaming/Claude/local-agent-mode-sessions/*/*/**` as
   `claude-cowork`.
3. `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/**`
   as `claude-cowork`.

The `*/*` session identifiers are treated as user-controlled path segments and
are redacted in serialized roots and findings.

The implementation must not decrypt safeStorage/DPAPI data and must not parse
Cowork `IndexedDB/` or `Local Storage/leveldb/` as conversation stores.

The report may serialize surface name, redacted root, file count, total bytes,
modified timestamps, pattern class, rule id, confidence, match count, and
redacted path. It must not serialize raw conversation content, raw secret
values, snippets, embeddings, screenshots, searchable indexes, or secret-value
hashes.

## Rationale

This follows the existing ADR-0019 consent model instead of creating a new
artifact. It gives launch coverage for the plaintext Cowork session files while
keeping opaque Electron stores under the stricter presence-only boundary already
documented for Cowork state.

The wildcard roots make the claim precise: Reeve can inspect plaintext files in
known session directories after explicit operator consent. It does not claim
semantic reconstruction of Cowork conversations and does not broaden into
encrypted or database-backed stores.

## Plain-language Summary

Claude Cowork can leave plaintext session files on disk. Those files can show
whether someone pasted a token into a Cowork conversation, but they can also
contain private prompts, project names, and customer details.

Reeve does not put that material in the normal AIBOM. Default scans do not read
Cowork session files. With `--include-conversation-metadata`, Reeve counts files
and sizes under known Cowork session roots. With `--scan-conversation-secrets`,
Reeve reads those files to look for secret-like patterns, but still writes only
redacted paths and pattern labels.

Reeve does not decrypt Cowork's encrypted stores and does not parse its
IndexedDB or LevelDB stores as conversation history.

## Consequences

- **This decision commits the project to:** Claude Cowork conversation scanning
  only through the opt-in sensitive-data report; redacted macOS and Windows
  session roots; and no raw transcript or secret serialization.
- **This decision unblocks:** Claude Cowork conversation coverage for macOS
  (#422) and Windows (#423).
- **This decision forecloses:** placing Cowork transcript-derived evidence in
  the AIBOM or treating opaque Electron stores as supported conversation roots.
- **This decision defers:** Cowork conversation semantic parsing, LevelDB /
  IndexedDB parsing, encrypted store decryption, and raw conversation export.

## References

- `docs/decisions/0019-conversation-log-sensitive-data-report.md`
- `docs/decisions/0027-claude-cowork-local-mcpb-inventory.md`
- `docs/decisions/0029-claude-cowork-approval-and-remote-connector-state.md`
- `docs/decisions/0030-claude-cowork-named-remote-connector-inventory.md`
- `docs/scope.md`
- GitHub issue #422: https://github.com/Reeve-Security/reeve/issues/422
- GitHub issue #423: https://github.com/Reeve-Security/reeve/issues/423
