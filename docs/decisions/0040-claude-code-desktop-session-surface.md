# ADR-0040: Claude Code desktop session state is a separate surface

- **Status:** Accepted 2026-06-08
- **Decides:** Surface boundary for Claude Code desktop session descriptors
- **Related:** ADR-0008, ADR-0039, `docs/scope.md`, GitHub issue #444, GitHub issue #450

## Context

Claude Code CLI approval state is already discovered from `.claude/settings.json`,
`.claude/settings.local.json`, and `.claude.json`. The Claude desktop app also
has a Claude Code mode with a separate session store under
`claude-code-sessions/*/*/local_*.json`.

Those desktop session descriptors are shaped like Cowork's plaintext session
descriptors, but they are not the Claude Code CLI config store. They need a
surface label that lets reports distinguish terminal CLI grants from desktop
app session grants.

The same descriptors can carry `scheduledTaskId` and `sessionType`. Those fields
are useful session metadata, but they do not prove that a task is safe.

## Options considered

### A. Fold desktop session descriptors into `claude-code`

Rejected. This would make CLI coverage look like desktop app coverage and make
the launch claim harder to audit.

### B. Treat desktop session descriptors as Cowork

Rejected. The parser shape is similar, but the store and buyer-facing surface
are different.

### C. Add `claude-code-desktop` as a separate built-in surface *(chosen)*

Chosen. Reeve reuses the bounded plaintext session parser but emits a distinct
surface label, distinct MCP tool capability namespace, and distinct evidence
references.

## Decision

Reeve adds a built-in `claude-code-desktop` surface for
`claude-code-sessions/*/*/local_*.json` on macOS, Windows user profiles, and
Windows package roots.

The surface uses the Cowork plaintext session boundary from ADR-0039:
fixture-proven approval fields can emit grant evidence, while remote MCP
descriptors remain inventory. Claude Code desktop tool grants use
`mcp:claude-code-desktop-tool:<tool>` and evidence references use
`claude-code-desktop://session#<field>`.

`scheduledTaskId` and `sessionType` emit session metadata capabilities for
traceability only. They are not safety verdicts and are not approval grants.

## Rationale

The surface split preserves the buyer-facing claim. "Claude Code CLI approvals"
and "Claude Code desktop session approvals" are different proof surfaces even
when their JSON fields are similar.

Reusing the existing bounded parser keeps the implementation small, but separate
surface names, capability ids, and evidence references prevent accidental
overclaiming.

## Plain-language summary

Claude Code has a command-line version and a desktop-app session store. A grant
found in one should not silently count as coverage for the other.

Reeve now calls the desktop store `claude-code-desktop`. That makes reports and
board rows honest: CLI grants stay CLI grants, desktop grants stay desktop
grants.

The desktop session file can also say that a session was scheduled or what type
of session it was. Reeve records that as context, not as proof that the session
was safe or approved.

## Consequences

- **This decision commits the project to:** a `claude-code-desktop` surface,
  desktop-specific capability ids, and redacted desktop session evidence
  references.
- **This decision unblocks:** Claude Code desktop session discovery (#444) and
  session metadata reporting (#450).
- **This decision forecloses:** using Claude Code CLI fixtures alone to claim
  Claude Code desktop session coverage.
- **This decision defers:** deeper correlation between scheduled tasks, grants,
  and later observed execution.

## References

- `docs/decisions/0008-granted-source-amendment.md`
- `docs/decisions/0039-claude-cowork-plaintext-session-approval-boundary.md`
- `docs/scope.md`

