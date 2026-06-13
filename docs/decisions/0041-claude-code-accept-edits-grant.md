# ADR-0041: Claude Code `acceptEdits` is saved auto-edit grant evidence

- **Status:** Accepted 2026-06-08
- **Decides:** Grant boundary for Claude Code `acceptEdits`
- **Related:** ADR-0008, ADR-0031, `docs/scope.md`, GitHub issue #446

## Context

Claude Code can persist auto-edit approval state in `.claude.json`. Desktop
local-agent sessions can also contain session-local `.claude/.claude.json` files
with the same `acceptEdits` field.

That state is not an MCP registration and can exist without any configured MCP
server. It is still saved authority: the agent can edit files without asking
again.

## Options considered

### A. Ignore `acceptEdits`

Rejected. This would miss a real saved grant visible in plaintext config.

### B. Treat the whole `.claude.json` file as approval state

Rejected. The file can contain prompts, project state, and other private fields.
Only the narrow approval field is needed.

### C. Parse `acceptEdits` as a grant-only `fs:write` provider *(chosen)*

Chosen. Reeve emits `fs:write` grant evidence only when `acceptEdits` contains a
fixture-proven affirmative value.

## Decision

Reeve parses `acceptEdits` from:

1. user-global `.claude.json`;
2. macOS session-local
   `Library/Application Support/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json`;
3. Windows user session-local
   `AppData/Roaming/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json`;
4. Windows package-root session-local
   `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json`.

Affirmative values emit a grant-only `claude-code` component with `fs:write`
capability evidence. Raw prompt, session, project, and user fields are not
serialized.

## Rationale

ADR-0008 treats saved approvals as first-class granted capability evidence.
`acceptEdits` is saved auto-edit authority. It is narrower than full filesystem
access, but the core taxonomy has no "edit current buffer" capability; `fs:write`
is the conservative representation.

The parser is field-specific so private data in the surrounding config never
becomes evidence by accident.

## Plain-language summary

If an agent has "accept edits" turned on, it can write changes without another
prompt. That matters even when no MCP server is registered.

Reeve now records that fact as a file-write grant. It does not publish the rest
of the Claude Code config file.

Session-local copies count too, because the saved authority can live inside a
desktop session directory rather than only in the top-level home config.

## Consequences

- **This decision commits the project to:** narrow `acceptEdits` parsing and
  grant-only `fs:write` evidence.
- **This decision unblocks:** Claude Code auto-edit approval coverage (#446).
- **This decision forecloses:** treating arbitrary `.claude.json` fields as
  approval grants.
- **This decision defers:** a more granular "agent edit" capability id.

## References

- `docs/decisions/0008-granted-source-amendment.md`
- `docs/decisions/0031-bounded-project-config-discovery.md`
- `docs/scope.md`

