# ADR-0036: Cursor conversation scanning stays in the opt-in sensitive-data report

- **Status:** Accepted
- **Date:** 2026-06-05
- **Decides:** Privacy boundary for Cursor agent transcript scanning on macOS and Windows
- **Related:** ADR-0019, ADR-0021, `docs/scope.md`, GitHub issue #367, GitHub issue #368

## Context

Reeve already supports an ADR-0019 sensitive-data report for opt-in
conversation/session-store metadata and secret-pattern findings. This report is
separate from the AIBOM and never serializes raw conversation content, raw
secret values, surrounding snippets, embeddings, screenshots, searchable
indexes, or hashes of secret values.

Cursor stores plaintext agent transcripts under
`.cursor/projects/<project>/agent-transcripts/<session>/*.jsonl`. These files
are launch-relevant because developers may paste credentials into agent chats,
but they also contain private prompts, project names, repository paths, and
session identifiers.

Cursor may also have app-state stores in SQLite or VS Code-style user data
locations. Those are not part of this decision because no launch fixture proves
a stable, safe parser for them.

## Options Considered

### A. Emit Cursor transcript findings in the AIBOM

Rejected. Transcript-derived findings are more private than the broad inventory
artifact. Putting them in the AIBOM would weaken the sharing boundary.

### B. Parse all Cursor app-state stores

Rejected. SQLite or app-state parsing needs separate fixture proof and a
separate privacy/security decision.

### C. Reuse ADR-0019 and add only plaintext Cursor agent transcripts *(chosen)*

Chosen. Reeve inventories metadata only under `--include-conversation-metadata`,
reads contents only under `--scan-conversation-secrets`, and emits only the
existing redacted sensitive-data report fields.

## Decision

Cursor conversation/session scanning is implemented only through the separate
ADR-0019 sensitive-data report.

Reeve supports this Cursor root:

1. `.cursor/projects/*/agent-transcripts/*/**` as `cursor`.

The project and session path segments are treated as user-controlled and are
redacted in serialized roots and findings.

The implementation must not parse Cursor SQLite, IndexedDB, or VS Code-style
app-state databases as conversation stores under this ADR.

The report may serialize surface name, redacted root, file count, total bytes,
modified timestamps, pattern class, rule id, confidence, match count, and
redacted path. It must not serialize raw conversation content, raw secret
values, snippets, embeddings, screenshots, searchable indexes, or secret-value
hashes.

## Rationale

This follows the existing ADR-0019 consent model and avoids a new artifact type.
The root is narrow and fixture-shaped: plaintext Cursor agent transcript files
only. That gives launch coverage for the proven store while avoiding broader
Cursor app-state claims.

## Plain-language Summary

Cursor keeps plaintext agent transcript files on disk. Those files can show
whether someone pasted a token into a Cursor chat, but they can also contain
private prompts, project names, and local paths.

Reeve does not put that material in the normal AIBOM. Default scans do not read
Cursor transcript files. With `--include-conversation-metadata`, Reeve counts
files and sizes under the known transcript root. With
`--scan-conversation-secrets`, Reeve reads those files to look for secret-like
patterns, but still writes only redacted paths and pattern labels.

Reeve does not parse Cursor app databases as conversation history in this
decision.

## Consequences

- **This decision commits the project to:** Cursor conversation scanning only
  through the opt-in sensitive-data report; redacted project/session roots; and
  no raw transcript or secret serialization.
- **This decision unblocks:** Cursor conversation coverage for macOS (#367) and
  Windows (#368) when the `.cursor/projects/*/agent-transcripts/*/**` root is
  present.
- **This decision forecloses:** placing Cursor transcript-derived evidence in
  the AIBOM or treating Cursor app-state databases as supported conversation
  roots.
- **This decision defers:** Cursor SQLite/app-state parsing and deeper
  transcript semantics beyond metadata inventory and secret-pattern findings.

## References

- `docs/decisions/0019-conversation-log-sensitive-data-report.md`
- `docs/decisions/0021-secret-rule-pack-schema.md`
- `docs/scope.md`
- GitHub issue #367: https://github.com/Reeve-Security/reeve/issues/367
- GitHub issue #368: https://github.com/Reeve-Security/reeve/issues/368
