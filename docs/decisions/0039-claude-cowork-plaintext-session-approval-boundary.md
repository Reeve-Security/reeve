# ADR-0039: Claude Cowork plaintext session approval fields are parsed as grant evidence

- **Status:** Accepted 2026-06-06
- **Decides:** Support and claim boundary for Claude Cowork plaintext session approval parsing
- **Related:** ADR-0008, ADR-0029, ADR-0030, ADR-0035, `docs/scope.md`, GitHub issue #386, GitHub issue #390

## Context

Claude Cowork stores local-agent-mode session JSON under
`local-agent-mode-sessions/*/*/local_*.json`. Reeve already reads these files
for `remoteMcpServersConfig` remote-MCP inventory and keeps encrypted Cowork
approval/cache stores presence-only under ADR-0029.

Captured session fixtures also show plaintext fields that describe saved
approval state:

- `enabledMcpTools`
- `userSelectedFolders`
- `egressAllowedDomains`
- `orgCliExecPolicies`
- dangerous `permissionMode` values that bypass prompts

Those fields are different from `remoteMcpServersConfig`. The remote config
proves that a remote MCP server and its advertised tools were present; it does
not prove user approval. The approval fields above can be emitted as
`granted-permission` evidence when their shape is fixture-proven.

## Options considered

### A. Keep all Cowork approvals blocked

Rejected. This would ignore plaintext session fields that can be parsed without
decrypting safeStorage/DPAPI or reading opaque Electron stores.

### B. Treat all session state as approval

Rejected. Session files also contain inventory, prompts, cwd, user identity, and
other ambient app state. Inferring grants from every approval-looking field
would overclaim and could leak private state.

### C. Parse only fixture-proven plaintext approval fields *(chosen)*

Chosen. Reeve emits Cowork grants only from narrow plaintext fields with tests
that pin the accepted shapes. `remoteMcpServersConfig` stays inventory-only, and
opaque stores stay presence-only under ADR-0029.

## Decision

Reeve parses Claude Cowork `local_*.json` session files and emits a standalone
`claude-cowork` grant-state component when fixture-proven approval fields are
present.

The mapping is:

1. `enabledMcpTools` approved entries emit `mcp:cowork-tool:<tool>` granted
   capabilities with a `toolName` qualifier.
2. `userSelectedFolders[]` absolute POSIX, Windows drive, or UNC paths emit
   `fs:read` and `fs:write` grants. Home/user path segments are redacted before
   serialization.
3. `egressAllowedDomains` entries emit `net:egress` grants with `host` and,
   when present, `scheme` / `port` qualifiers.
4. `orgCliExecPolicies` approved command entries emit `exec:subprocess` grants
   with `cmd` and `argCount` qualifiers.
5. dangerous `permissionMode` bypass values emit wildcard `exec:subprocess`
   grants. Default or ambient modes emit nothing.

Reeve does not attach these grants to a specific remote MCP component unless a
future fixture proves that ownership relation. Today they belong to Cowork
session approval state as a separate evidence component.

Grant evidence references use
`claude-cowork://local-agent-mode-session#<field>` rather than raw local paths,
so account/session directory names are not published as grant evidence.

## Rationale

ADR-0008 makes saved approvals a first-class capability source. Cowork session
approval fields are saved authority: they describe tools, folders, network
destinations, or commands the app can use without asking again.

The boundary remains narrow because scanners are an attack surface. This
decision does not decrypt safeStorage, parse LevelDB, infer connector grants, or
turn remote-MCP inventory into approval evidence. It adds only plaintext fields
that can be represented by the existing AIBOM capability taxonomy.

## Plain-language summary

Cowork session files can contain two different kinds of useful facts. One kind
is inventory: which remote MCP servers and tools were present. The other kind is
saved authority: which tools, folders, domains, or commands were allowed.

Reeve now separates those facts. Remote server listings stay as inventory. The
specific plaintext approval fields become grant evidence.

The output does not publish the raw session path, user email, prompt text, cwd,
or OS username. Filesystem grant paths keep the useful scope but redact the home
segment, for example `/Users/<redacted-home>/LegalDocs`.

This still is not full Cowork approval coverage. Encrypted approval caches and
opaque app databases remain out of scope until a later ADR and fixtures prove a
safe format.

## Consequences

- **This decision commits the project to:** Cowork session grant evidence from
  fixture-proven plaintext fields only; standalone grant-state components; and
  redacted grant paths/references.
- **This decision unblocks:** Cowork approval launch coverage for macOS (#386)
  and Windows (#390), limited to local-agent-mode session JSON.
- **This decision forecloses:** claiming grants from `remoteMcpServersConfig`,
  encrypted `dxt:allowlistCache`, IndexedDB, or LevelDB.
- **This decision defers:** per-remote-MCP grant attribution and encrypted or
  binary Cowork approval-store parsing.

## References

- `docs/decisions/0008-granted-source-amendment.md`
- `docs/decisions/0029-claude-cowork-approval-and-remote-connector-state.md`
- `docs/decisions/0030-claude-cowork-named-remote-connector-inventory.md`
- `docs/decisions/0035-claude-cowork-conversation-sensitive-data-boundary.md`
- `docs/scope.md`
