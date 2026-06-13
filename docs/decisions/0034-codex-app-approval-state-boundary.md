# ADR-0034: Codex App saved tool approvals are distinct from Codex CLI project approvals

- **Status:** Accepted
- **Date:** 2026-06-05
- **Decides:** Privacy and surface boundary for Codex App saved approval-state parsing
- **Related:** ADR-0008, ADR-0032, ADR-0033, `docs/scope.md`, GitHub issue #426, GitHub issue #427

## Context

Codex CLI and the Codex desktop App share plaintext state in
`.codex/config.toml`, but they do not represent the same surface.

The file can contain:

- Codex CLI project approvals under `projects.*.approval_policy`;
- Codex CLI sandbox grants under `projects.*.sandbox_mode`;
- Codex App saved tool approvals under `apps.*.tools.*.approval_mode`;
- Codex App plugin and marketplace inventory under `plugins.*` and
  `marketplaces.*`;
- private project paths under `projects.*`.

Before this decision, Reeve parsed `apps.*.tools.*.approval_mode` as part of
the `codex-cli` grant provider. That was useful evidence, but it blurred the
launch claim: App saved tool approvals are desktop App state, not CLI project
approval state.

## Options considered

### A. Keep App tool approvals under `codex-cli`

Rejected. It preserves compatibility but continues the product ambiguity that
issues #426 and #427 were opened to fix.

### B. Treat Codex App approval state as opaque presence-only

Rejected for this slice. The relevant approval fields are plaintext TOML and
can be parsed without decrypting Electron, DPAPI, safeStorage, IndexedDB, or
LevelDB state.

### C. Split App tool approvals into a `codex-app` grant provider *(chosen)*

Chosen. Reeve continues reading `.codex/config.toml`, but routes
`projects.*` grant state to `codex-cli` and routes `apps.*.tools.*` approval
state to `codex-app`.

## Decision

Reeve treats Codex App saved tool approvals as their own built-in surface:
`codex-app`.

The split is:

1. `projects.*.approval_policy` and `projects.*.sandbox_mode` emit Codex CLI
   `granted-permission` evidence.
2. `apps.*.tools.*.approval_mode = "approve"` emits Codex App
   `granted-permission` evidence.
3. Codex App approval evidence references use `codex-app://config#...`
   references, not raw local file paths.
4. Codex App approval parsing never emits `projects.*` table keys, project
   paths, usernames, prompt text, transcript text, or marketplace local paths.
5. Opaque Electron stores remain out of scope unless a later ADR and fixtures
   prove a safe plaintext format.

## Rationale

ADR-0008 says saved approvals are a first-class `granted` capability source.
The surface label matters because buyers ask, "Which app has inherited
authority?" `codex-cli` and `codex-app` have different users and different
risk stories, even when they share a config file.

Using `codex-app://config#...` references keeps the useful evidence pointer
without leaking the user's home path or project layout. App tool names and
approval mode are the grant facts; local path coordinates are not.

## Plain-language summary

Codex CLI and the Codex desktop App can write approval settings into the same
config file. That does not mean they are the same product surface. A developer
using a terminal and an employee clicking around in the desktop App create
different launch claims and different risk narratives.

Reeve now separates them. Project-level CLI settings stay labeled as Codex CLI.
Desktop App tool approvals are labeled as Codex App.

The parser only records the approval facts: which App tool has been approved.
It does not publish where the config file lived on disk, which projects the
user opened, their username, prompt text, transcripts, or local marketplace
paths.

If future Codex App approval state moves into encrypted or binary Electron
stores, Reeve will not decrypt it under this decision. It will need a new
decision and real fixtures.

## Consequences

- **This decision commits the project to:** separate `codex-app` grant evidence
  for App tool approvals; `codex-cli` grant evidence for project/sandbox state;
  redacted App approval references; and no parsing of opaque Electron stores.
- **This decision unblocks:** Codex App approval coverage for macOS (#426) and
  Windows (#427).
- **This decision forecloses:** using Codex CLI approval tests to claim Codex
  desktop App approval coverage.
- **This decision defers:** encrypted or binary Codex App approval-store parsing.

## References

- `docs/decisions/0008-granted-source-amendment.md`
- `docs/decisions/0032-codex-app-plugin-discovery-privacy-boundary.md`
- `docs/decisions/0033-codex-app-conversation-sensitive-data-boundary.md`
- `docs/scope.md`
- GitHub issue #426: https://github.com/Reeve-Security/reeve/issues/426
- GitHub issue #427: https://github.com/Reeve-Security/reeve/issues/427
