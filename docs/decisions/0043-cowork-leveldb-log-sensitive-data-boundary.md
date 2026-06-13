# ADR-0043: Cowork LevelDB `.log` files enter only the opt-in sensitive-data report

- **Status:** Accepted 2026-06-08
- **Decides:** Sensitive-data boundary for Claude Cowork IndexedDB LevelDB log files
- **Related:** ADR-0019, ADR-0029, ADR-0035, `docs/scope.md`, GitHub issue #448

## Context

ADR-0035 kept Claude Cowork conversation scanning limited to plaintext
`local-agent-mode-sessions/*/*/**` files. Later captures showed plaintext
conversation-like strings in IndexedDB LevelDB write-ahead `.log` files under
bounded Claude app-state roots.

Those `.log` files can be scanned as plaintext after the operator explicitly
opts into the sensitive-data report. The adjacent `.ldb` SSTables are different:
they can be Snappy-compressed or record-structured and need a real parser before
they can be claimed safely.

## Options considered

### A. Keep all IndexedDB/LevelDB files out of scope

Rejected. It misses plaintext `.log` evidence that can be scanned without a
database parser.

### B. Parse all LevelDB files

Rejected. `.ldb` SSTables require LevelDB/Snappy handling and would blur the
no-opaque-store boundary from ADR-0029.

### C. Scan `.log` files only under explicit opt-in *(chosen)*

Chosen. Reeve adds the bounded LevelDB roots to the sensitive-data report and
filters content reads to `.log` files only.

## Decision

Claude Cowork IndexedDB LevelDB `.log` files are supported only through the
ADR-0019 sensitive-data report flags:

1. `Library/Application Support/Claude/IndexedDB/*.leveldb/*.log`;
2. `AppData/Roaming/Claude/IndexedDB/*.leveldb/*.log`;
3. `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/IndexedDB/*.leveldb/*.log`.

Default scans still do not read conversation/session stores. Reeve does not
parse `.ldb` files, Snappy-compressed records, Local Storage LevelDB, or
encrypted safeStorage/DPAPI approval blobs under this decision.

## Rationale

This keeps the ADR-0019 privacy model intact while closing a real plaintext
coverage gap. `.log` files are ordinary plaintext-like files for the purpose of
secret-pattern scanning; `.ldb` files are not.

Filtering by extension gives a clear contract that tests can enforce and
customers can audit by grepping `docs/scope.md`.

## Plain-language summary

Cowork can leave useful text in LevelDB `.log` files. Those files may contain
conversation material, so Reeve reads them only when the user turns on the
sensitive-data report.

Reeve still does not parse the full database. It skips `.ldb` files and does
not decrypt protected app state.

This gives a narrow, testable improvement without turning Reeve into an Electron
database extractor.

## Consequences

- **This decision commits the project to:** `.log`-only LevelDB scanning under
  explicit sensitive-data opt-in.
- **This decision unblocks:** Cowork LevelDB log secret scanning (#448).
- **This decision forecloses:** claiming `.ldb`, Local Storage LevelDB, or
  encrypted approval-store parsing.
- **This decision defers:** true LevelDB/IndexedDB record parsing.

## References

- `docs/decisions/0019-conversation-log-sensitive-data-report.md`
- `docs/decisions/0029-claude-cowork-approval-and-remote-connector-state.md`
- `docs/decisions/0035-claude-cowork-conversation-sensitive-data-boundary.md`
- `docs/scope.md`

