# ADR-0042: Codex App global state is parsed only for full-access grant fields

- **Status:** Accepted 2026-06-08
- **Decides:** Privacy boundary for `.codex/.codex-global-state.json`
- **Related:** ADR-0008, ADR-0032, ADR-0033, ADR-0034, `docs/scope.md`, GitHub issue #445

## Context

Codex App can persist global state in `.codex/.codex-global-state.json`. Captured
state shows full-access indicators near prompt history and other private app
payloads.

The full-access fields are launch-relevant grant evidence. Prompt history and
the rest of the blob are high-risk private data and must not be dumped,
serialized, or used as broad inventory.

## Options considered

### A. Skip global state entirely

Rejected. This misses plaintext full-access grants that are different from
Codex CLI project approvals and Codex App per-tool approvals.

### B. Parse and report the whole global-state blob

Rejected. This would leak prompt history, project context, and other private app
state.

### C. Parse only narrow full-access fields *(chosen)*

Chosen. Reeve reads a fixed allowlist of fields and emits grant evidence only
from those fields.

## Decision

Reeve reads `.codex/.codex-global-state.json` only for:

1. `agent-mode`;
2. `sandboxPolicy.type`;
3. `approvalPolicy`;
4. `skip-full-access-confirm`;
5. `active-workspace-roots`.

Full-access mode emits `mcp:codex-app:full-access`. `approvalPolicy = "never"`
emits wildcard `exec:subprocess`. Active workspace roots emit `fs:read` and
`fs:write` with home path segments redacted.

Prompt history and all other global-state fields are out of scope and are never
serialized.

## Rationale

This follows ADR-0008 without weakening the privacy boundary from ADR-0032 and
ADR-0033. Reeve records the saved authority that matters to endpoint risk and
does not turn the App's private global state into a report artifact.

The path is under the existing `codex-app` surface because it is desktop App
state, not Codex CLI project state.

## Plain-language summary

The Codex App global-state file can contain both permission state and private
prompt history. Reeve needs the permission state, not the private history.

Reeve now reads a small fixed list of fields. If those fields show full access,
the report says so. It does not copy the rest of the file.

Workspace paths are useful as grant scope, but usernames are not. Home segments
are redacted before output.

## Consequences

- **This decision commits the project to:** narrow field allowlisting for
  `.codex/.codex-global-state.json`; Codex App full-access grants; and prompt
  history exclusion.
- **This decision unblocks:** Codex App full-access detection (#445).
- **This decision forecloses:** dumping or schema-walking the full global-state
  blob.
- **This decision defers:** encrypted or binary Codex App approval-store
  parsing.

## References

- `docs/decisions/0008-granted-source-amendment.md`
- `docs/decisions/0032-codex-app-plugin-discovery-privacy-boundary.md`
- `docs/decisions/0033-codex-app-conversation-sensitive-data-boundary.md`
- `docs/decisions/0034-codex-app-approval-state-boundary.md`
- `docs/scope.md`

