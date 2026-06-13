# ADR-0033: Codex App conversation scanning stays in the opt-in sensitive-data report

- **Status:** Accepted
- **Date:** 2026-06-05
- **Decides:** Privacy boundary for Codex App conversation/session-store scanning on macOS and Windows
- **Related:** ADR-0019, ADR-0032, `docs/scope.md`, GitHub issue #428, GitHub issue #429

## Context

Reeve already supports opt-in conversation/session-store sensitive-data reports
under ADR-0019. That report is separate from the AIBOM and has a stronger
privacy boundary: it may contain redacted file metadata and pattern classes, but
never raw conversation content, raw secret values, surrounding snippets,
embeddings, screenshots, searchable indexes, or hashes of secret values.

Codex App adds two launch-relevant stores:

- macOS archived sessions under
  `Library/Application Support/Codex/archived_sessions/**`;
- Windows session JSONL state under `.codex/sessions/**`, sharing the same
  plaintext store shape already used by Codex CLI.

Both stores can contain high-value evidence for leaked tokens in AI
conversation history. They can also contain private prompts, customer data,
repository names, usernames, and local project names. The launch question is
where this evidence belongs and how it is labeled without turning the public
AIBOM into a transcript carrier.

## Options considered

### A. Emit Codex App conversation evidence in the AIBOM

Rejected. This would mix transcript-derived evidence into the broad inventory
artifact. The AIBOM is designed to be shared more widely than raw or derived
conversation data.

### B. Do not scan Codex App conversation/session stores

Rejected. The stores are plaintext and launch-relevant. Ignoring them would
leave Codex App behind Claude Desktop, Claude Code, and Codex CLI for the
conversation-secrets pillar even though the evidence is locally available.

### C. Reuse ADR-0019 and add Codex App as an opt-in sensitive-data surface *(chosen)*

Chosen. Reeve inventories Codex App session-store metadata only when
`--include-conversation-metadata` is passed, reads contents only when
`--scan-conversation-secrets` is passed, and emits only the existing redacted
sensitive-data report fields.

## Decision

Codex App conversation/session-store scanning is implemented only through the
separate ADR-0019 sensitive-data report.

Reeve supports these Codex App roots:

1. `Library/Application Support/Codex/archived_sessions/**` as `codex-app`.
2. `.codex/sessions/**` as `codex-app` when `.codex/config.toml` contains Codex
   App plugin or marketplace state. Without that App marker, the same path
   remains the existing `codex-cli` session store.

The implementation must not double-count the shared `.codex/sessions/**` path
as both `codex-app` and `codex-cli` during the same scan.

The report may serialize surface name, redacted root, file count, total bytes,
modified timestamps, pattern class, rule id, confidence, match count, and
redacted path. It must not serialize raw conversation content, raw secret
values, snippets, embeddings, screenshots, searchable indexes, or secret-value
hashes.

## Rationale

This follows the existing ADR-0019 boundary instead of creating a new artifact
type. It keeps launch claims simple: default scans do not read conversations;
metadata inventory is one opt-in; content pattern scanning is a second opt-in;
and transcript-derived findings stay out of the public AIBOM.

The Windows label rule exists because Codex App and Codex CLI can share
`.codex/sessions/**`. The App marker avoids duplicate reports and gives the
operator a clearer answer: when App plugin/marketplace state is present, the
session store is treated as Codex App evidence for issue #429; otherwise it
remains Codex CLI evidence.

## Plain-language summary

Codex App keeps conversation/session files on disk. Those files can be useful:
they may reveal that an API key or token was pasted into an AI conversation.
But they are also private because they can contain prompts, project names,
customer details, and local file names.

Reeve does not put that material in the normal AIBOM. The AIBOM is the broad
tool inventory. Conversation-derived findings stay in a separate report that
operators must ask for explicitly.

There are two levels of consent. With `--include-conversation-metadata`, Reeve
counts files and sizes under known session roots without reading conversation
bodies. With `--scan-conversation-secrets`, Reeve reads those files to look for
secret-like patterns, but still writes only redacted paths and pattern labels.
It does not write the prompt, the secret value, nearby text, or a hash of the
secret.

On Windows, Codex App can use the same `.codex/sessions` folder as Codex CLI.
Reeve does not report the same files twice. If the Codex config shows App
plugin or marketplace state, that folder is labeled as `codex-app`; otherwise
it stays `codex-cli`.

## Consequences

- **This decision commits the project to:** Codex App conversation scanning only
  through the opt-in sensitive-data report; redacted roots for macOS and Windows;
  no double-counting of `.codex/sessions/**`; and no raw transcript or secret
  serialization.
- **This decision unblocks:** Codex App conversation coverage for macOS (#428)
  and Windows (#429).
- **This decision forecloses:** placing Codex App transcript-derived evidence in
  the AIBOM or labeling the shared Windows session path as both Codex App and
  Codex CLI in one scan.
- **This decision defers:** deeper Codex App conversation semantics beyond
  metadata inventory and secret-pattern findings.

## References

- `docs/decisions/0019-conversation-log-sensitive-data-report.md`
- `docs/decisions/0032-codex-app-plugin-discovery-privacy-boundary.md`
- `docs/scope.md`
- GitHub issue #428: https://github.com/Reeve-Security/reeve/issues/428
- GitHub issue #429: https://github.com/Reeve-Security/reeve/issues/429
