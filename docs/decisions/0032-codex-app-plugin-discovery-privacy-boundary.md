# ADR-0032: Codex App plugin/marketplace discovery redacts absolute paths and never reads the opaque Electron store

- **Status:** Accepted
- **Date:** 2026-06-04
- **Decides:** Privacy boundary for Codex desktop App plugin and marketplace inventory
- **Related:** ADR-0005, ADR-0027, ADR-0029, `docs/scope.md`, GitHub issue #424, GitHub issue #425

## Context

The Codex desktop App keeps a plaintext `~/.codex/config.toml` that declares
installed plugins and the marketplaces they came from:

- `[plugins."name@marketplace"]` tables with an `enabled` field;
- `[marketplaces.<id>]` tables with `source_type` and `source`;
- `[projects."/abs/path"]` tables, one per project directory the user has
  opened, plus an opaque Electron store under
  `~/Library/Application Support/Codex` (and the Windows equivalent).

This file is high-value endpoint evidence: it names which plugins an agent can
load and from which marketplaces. But it is also a privacy minefield. The
marketplace `source` field can be an absolute filesystem path
(`/Users/<name>/.codex/...`, `C:\Users\<name>\...`, or a UNC share), and the
`[projects.*]` tables enumerate **every project directory on the user's disk**.
Both leak the
operator's username and the layout of their machine. If Reeve serialized them
verbatim, the AIBOM — an artifact meant to be shared, signed, and published —
would carry personal identity and filesystem-layout data.

Reeve already commits to a no-decrypt / presence-only rule for opaque app
stores (ADR-0027, extended by ADR-0029): encrypted or binary app-internal
state is reported as present, never read. The Codex Electron store is exactly
that kind of store. We need a decision that captures the useful plaintext
inventory while keeping these two privacy leaks — absolute paths and the
project list — out of the emitted artifact, and keeping the opaque store
presence-only.

## Options considered

### A. Emit `config.toml` contents verbatim

Rejected. Simplest to implement, but it ships the user's username, home-path
layout, and full project directory list inside a signed, shareable artifact.
That is an identity and filesystem-layout disclosure in the exact document
Reeve expects customers to publish.

### B. Skip Codex App discovery entirely

Rejected. Throwing away the plaintext plugin and marketplace inventory to
avoid the leak loses the whole point: knowing which plugins and marketplaces
an agent endpoint can pull from is precisely the evidence Reeve exists to
produce.

### C. Inventory plaintext plugins/marketplaces, redact absolute paths, never touch projects or the opaque store *(chosen)*

Chosen. Reeve parses `[plugins.*]` and `[marketplaces.*]` from
`config.toml`, but redacts every absolute filesystem path before it reaches
the AIBOM, never parses or emits `[projects.*]`, and treats the Electron
store as presence-only — consistent with ADR-0027/ADR-0029.

## Decision

For Codex desktop App discovery (issues #424 macOS, #425 Windows), Reeve:

1. **Discovers plugins and marketplaces** from the plaintext
   `~/.codex/config.toml`: each `[plugins."name@marketplace"]` table (with its
   `enabled` field) and each referenced `[marketplaces.<id>]` table (with
   `source_type` and `source`).
2. **Redacts all absolute filesystem paths** before emitting. Any absolute
   path — most importantly a marketplace `source` of `source_type` that points
   at the local disk or a Windows UNC share — is replaced with the literal
   placeholder `<redacted-abs-path>`. URL-typed `source` values (registry/HTTP
   marketplaces) pass through unchanged, since a public URL is not an identity
   leak.
3. **Never parses or emits `[projects.*]`.** The project directory list is
   skipped entirely; it never enters the parser's output and never appears in
   the AIBOM.
4. **Never decrypts or reads the opaque Electron store**
   (`~/Library/Application Support/Codex` on macOS, the Windows equivalent).
   That store is reported presence-only, consistent with the existing
   no-decrypt rule (ADR-0027, ADR-0029).

Plugins and marketplaces are emitted as canonical AIBOM evidence inside the
MCP adapter, using the namespaced `mcp` capability extension defined in
ADR-0005; no new core capability ids are introduced.

## Rationale

This is the narrow privacy-safe evidence path. The plugin and marketplace
tables answer the question that matters — "what can this agent load, and from
where" — while the two redaction rules strip the parts of `config.toml` that
are purely about the human and their machine, not about the agent's tooling.

URLs are allowed through because a marketplace URL is a public coordinate, not
a personal one; an absolute local path is the opposite. Skipping `[projects.*]`
wholesale (rather than redacting per-entry) is deliberate: the *list of project
names and their existence* is itself the leak, so there is nothing safe left to
emit once paths are removed.

Treating the Electron store as presence-only keeps Codex consistent with the
Cowork decisions: Reeve does not become a decryptor of app-private state for
any surface. Honoring one uniform no-decrypt rule across surfaces is easier to
audit and harder to get wrong than per-surface exceptions.

## Plain-language summary

The Codex desktop App keeps a plain text settings file that lists which plugins
are installed and which "marketplaces" (plugin sources) they came from. That is
genuinely useful for a security inventory — it tells you what an AI agent on
this machine is allowed to load and where those tools originate.

The catch is that the same file also contains things that are about the *person*
and their *computer*, not about the agent: the full path to files on their disk
(which usually contains their username, like `/Users/jane/...`), and a list of
every project folder they have ever opened. Reeve's whole job is to produce an
inventory that you can sign and share with auditors or customers. You do not
want to hand someone a "tool inventory" that quietly also reveals your username
and a map of your hard drive.

So Reeve takes the useful part and leaves the private part behind. It reads the
plugins and marketplaces, but before writing anything out it scrubs absolute
file paths — replacing them with a `<redacted-abs-path>` marker. Web addresses
(URLs) are left alone, because a public link is not a personal secret. The list
of project folders is never read at all. And the
encrypted internal database that Codex keeps is only ever noted as "present" —
Reeve never opens it or tries to decrypt it, exactly as it already refuses to
crack open Claude Cowork's encrypted stores.

Think of it like making an inventory of a building's contents by reading the
labels on the boxes, while deliberately not photographing the return addresses
or peeking inside the locked safe.

## Consequences

- **This decision commits the project to:** redacting every absolute filesystem
  path out of Codex App evidence, never serializing `[projects.*]`, and treating
  the Codex Electron store as presence-only.
- **This decision unblocks:** Codex desktop App plugin and marketplace inventory
  on macOS (#424) and Windows (#425), with fixtures that assert no absolute path,
  username, or project directory survives into the AIBOM.
- **This decision forecloses:** emitting `config.toml` verbatim, inventorying the
  user's project directory list, and decrypting the Codex Electron store.
- **This decision defers:** any future per-project or per-plugin grant evidence
  that would require reading the opaque store; that needs a separate
  fixture-backed security decision.

## References

- `docs/decisions/0005-capability-taxonomy.md`
- `docs/decisions/0027-claude-cowork-local-mcpb-inventory.md`
- `docs/decisions/0029-claude-cowork-approval-and-remote-connector-state.md`
- `docs/scope.md`
- GitHub issue #424: https://github.com/Reeve-Security/reeve/issues/424
- GitHub issue #425: https://github.com/Reeve-Security/reeve/issues/425
