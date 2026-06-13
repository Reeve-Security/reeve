# ADR-0037: Claude Desktop trusted-folder approvals are the only parsed Desktop approval grant

- **Status:** Accepted
- **Date:** 2026-06-05
- **Decides:** Support and claim boundary for Claude Desktop trusted-folder approval parsing
- **Related:** ADR-0008, ADR-0029, ADR-0032, `docs/scope.md`, GitHub issue #318, GitHub issue #319

## Context

Claude Desktop's user config file, `claude_desktop_config.json`, can contain
both MCP registrations and local agent trusted-folder state.

The observed plaintext field is:

- `preferences.localAgentModeTrustedFolders[]`

Anthropic's local-access documentation describes attached workspace folders as
granting Claude file access within those folders. That makes this field useful
approval evidence for inherited-authority inventory.

Nearby Claude app state also contains Cowork approval/cache material such as
`config.json` `dxt:allowlistCache` and Electron IndexedDB/LevelDB records.
ADR-0029 already marks those stores opaque and presence-only because they are
encrypted or implementation-internal.

## Options considered

### A. Continue treating Claude Desktop approvals as fully blocked

Rejected. The trusted-folder field is plaintext, fixture-proven, and directly
maps to filesystem access. Keeping it blocked would hide useful launch evidence.

### B. Parse every Claude app approval-looking store

Rejected. `dxt:allowlistCache`, IndexedDB, and LevelDB state are not a safe
plaintext contract for this release. Parsing them would require decryption or
reverse-engineering opaque app internals and would conflict with ADR-0029.

### C. Parse only `localAgentModeTrustedFolders[]` *(chosen)*

Chosen. Reeve reads the documented Claude Desktop config file and emits grants
only from absolute trusted-folder paths in the plaintext preferences field.

## Decision

Reeve treats each absolute entry in
`preferences.localAgentModeTrustedFolders[]` as Claude Desktop
`granted-permission` evidence.

For each accepted folder path, Reeve emits:

1. `fs:read` with `qualifiers.path`.
2. `fs:write` with `qualifiers.path`.
3. Evidence reference
   `file://<config>#preferences.localAgentModeTrustedFolders[index]`.

Before serialization, `qualifiers.path` follows ADR-0008's saved-grant path
privacy rule: home/user identity is redacted while the absolute grant scope is
preserved. For example, `/Users/alice/LegalDocs` is emitted as
`/Users/<redacted-home>/LegalDocs`, and `C:\Users\alice\LegalDocs` is emitted as
`C:\Users\<redacted-home>\LegalDocs`. This keeps the folder-scope evidence but
does not publish the operator's OS username.

Accepted paths are absolute POSIX paths, Windows drive paths, or Windows UNC
paths. Relative paths are ignored because the schema qualifier must describe a
portable absolute filesystem coordinate.

This support applies to the macOS Claude Desktop config path, the Windows
classic config path, and the Windows Store/UWP package-root config path already
listed in `docs/scope.md`.

Reeve does not decrypt `dxt:allowlistCache`, parse IndexedDB/LevelDB records,
extract tokens, infer Cowork connector grants, or claim full Claude Desktop
approval coverage under this decision.

## Rationale

ADR-0008 makes saved approvals a first-class capability source. A trusted
folder is a saved user decision that affects which local files Claude can reach,
so it belongs in `capabilities.granted[]`.

The boundary is intentionally narrow. The field is plaintext JSON in the same
config file Reeve already reads for MCP registrations. Opaque Cowork stores are
a different risk class and remain presence-only.

## Plain-language summary

Claude Desktop can remember folders the user has trusted. If that folder list
is present in the normal Claude Desktop config file, Reeve records it as saved
read/write authority for those folders. The published path keeps the folder
scope but redacts the user/home segment, so the AIBOM can prove "LegalDocs was
trusted" without revealing which OS account owned it.

That does not mean Reeve now understands every Claude approval. It only parses
the trusted-folder list. Encrypted approval caches, internal app databases,
tokens, and connector records stay out of scope.

## Consequences

- **This decision commits the project to:** Claude Desktop trusted-folder
  grants for macOS and Windows when the plaintext field exists, with
  home/user identity redacted from saved-grant path qualifiers.
- **This decision unblocks:** Claude Desktop approval launch coverage for
  macOS (#318) and Windows (#319), limited to trusted folders.
- **This decision forecloses:** marketing claims that Reeve inventories all
  Claude Desktop or Cowork approvals.
- **This decision defers:** encrypted app-state approval parsing and connector
  grant reconstruction.

## References

- `docs/decisions/0008-granted-source-amendment.md`
- `docs/decisions/0029-claude-cowork-approval-and-remote-connector-state.md`
- `docs/scope.md`
- Claude local access docs: https://claude.com/docs/cowork/3p/local-access
- GitHub issue #318: https://github.com/Reeve-Security/reeve/issues/318
- GitHub issue #319: https://github.com/Reeve-Security/reeve/issues/319
