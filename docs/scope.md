# Filesystem scope

This filesystem scope document is the customer-facing contract for what Reeve reads during a v0.1 MCP scan. It is intentionally path-level: a security reviewer should be able to answer “does Reeve read file X?” by grepping this file.

Reeve reads agent configuration files under the scan target root,
parses MCP server registrations from those files, and then optionally
executes local stdio MCP servers for live self-description or profiles
them inside a sandbox. Default scans do not execute registered MCP
servers. For workspace MCP configs, Reeve may perform bounded directory
metadata traversal under the target root to find specific filenames; it
does **not** read arbitrary home-directory files, source code, or
secrets.

## Scope model

- **Target root:** paths below are relative to the `reeve scan --target <root>` target. For the common case `--target ~`, they resolve under the current user's home directory.
- **Binary location:** discovery does not depend on where `aibom-cli`
  is installed or which directory launched it. `--target` chooses the
  read root; `--output-dir` chooses the artifact write location.
- **Execution context:** per-user agent surfaces live under that user's
  profile. A system/root scheduled task must either enumerate user
  profile roots explicitly or run a per-user scan; otherwise it sees
  only the profile and system paths visible to that process.
- **Built-in protocol adapter:** v0.1 ships one protocol adapter, `mcp`. The surfaces below are MCP configuration surfaces for supported agent products.
- **System-wide custom surface config:** if no explicit
  `--surface-config <path>` is passed, Reeve checks one OS-conventional
  central config path. This is for MDM or endpoint-management deployment
  and stays lower trust than built-in surfaces.
- **Known deterministic roots:** Reeve anchors on the documented and
  observed per-OS surface paths listed in this file. These roots are not
  role-specific; the same read set applies to engineering, HR,
  marketing, finance, legal, and other endpoint archetypes.
- **Workspace search:** only the listed filenames are discovered, only to the listed max depth, and common large/build directories are skipped.
- **Project-level config discovery:** bounded workspace searches are limited to
  documented MCP/approval config filenames. See
  [ADR-0031](decisions/0031-bounded-project-config-discovery.md).
- **Package-root search:** only the listed package-root globs and relative
  child files are discovered. Reeve does not walk arbitrary package
  contents.
- **Variable subdirectories:** package-root and account/org subpaths
  that vary per user are matched with the explicit globs shown in the
  read-set table, not hardcoded to one machine's values.
- **Contents parsed:** Reeve reads only the config file content needed to extract MCP server names, transports, command/args, URLs, headers, metadata fields, and supported saved approval rules.
- **Introspection execution boundary:** default scans do not launch
  discovered stdio MCP servers for `tools/list`. Operators must pass
  `--introspect-execute` and confirm interactively, or pass
  `--introspect-execute-yes` in automation.
- **Profiling boundary:** capability profiling runs the discovered local stdio MCP server in a sandbox. Profiling is separate from config discovery.
- **Traffic boundary:** Reeve is not an MCP proxy and does not route,
  broker, approve, deny, or intercept live MCP calls. See
  [ADR-0022](decisions/0022-config-reader-not-proxy.md).

## MCP discovery read set

| Surface | Agent/config source | OS/scope | Exact path or bounded search | Parsed as | Parsed roots | Surface kind |
|---|---|---|---|---|---|---|
| `claude-desktop` | Claude Desktop user MCP + trusted folders | macOS user | `Library/Application Support/Claude/claude_desktop_config.json` | JSON | `mcpServers`, `preferences.localAgentModeTrustedFolders[]` | user-global |
| `claude-desktop` | Claude Desktop user MCP + trusted folders | Windows user | `AppData/Roaming/Claude/claude_desktop_config.json` | JSON | `mcpServers`, `preferences.localAgentModeTrustedFolders[]` | user-global |
| `claude-desktop` | Claude Desktop Store/UWP user MCP + trusted folders | Windows package root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/claude_desktop_config.json` | JSON | `mcpServers`, `preferences.localAgentModeTrustedFolders[]` | package-root user-global |
| `claude-cowork` | Claude Cowork app-state root | macOS user | `Library/Application Support/Claude/config.json` | JSON | `dxt:allowlistCache` only; sibling `IndexedDB/` and `Local Storage/leveldb/` presence only | user-global app-state |
| `claude-cowork` | Claude Cowork local MCPB extension installs | macOS user | `Library/Application Support/Claude/extensions-installations.json` | JSON | MCPB extension install records, server command/args, signatureInfo.status, declared tools | user-global inventory |
| `claude-cowork` | Claude Cowork local-agent-mode session descriptors | macOS user | `Library/Application Support/Claude/local-agent-mode-sessions/*/*/local_*.json` | JSON | `remoteMcpServersConfig[].{name,uuid,tools[].name}` inventory; plaintext approval fields `enabledMcpTools`, `userSelectedFolders`, `egressAllowedDomains`, `orgCliExecPolicies`, dangerous `permissionMode` values; session metadata `scheduledTaskId`, `sessionType` | user-global session-state |
| `claude-cowork` | Claude Cowork app-state root | Windows user | `AppData/Roaming/Claude/config.json` | JSON | `dxt:allowlistCache` only; sibling `IndexedDB/` and `Local Storage/leveldb/` presence only | user-global app-state |
| `claude-cowork` | Claude Cowork local MCPB extension installs | Windows user | `AppData/Roaming/Claude/extensions-installations.json` | JSON | MCPB extension install records, server command/args, signatureInfo.status, declared tools | user-global inventory |
| `claude-cowork` | Claude Cowork local-agent-mode session descriptors | Windows user | `AppData/Roaming/Claude/local-agent-mode-sessions/*/*/local_*.json` | JSON | `remoteMcpServersConfig[].{name,uuid,tools[].name}` inventory; plaintext approval fields `enabledMcpTools`, `userSelectedFolders`, `egressAllowedDomains`, `orgCliExecPolicies`, dangerous `permissionMode` values; session metadata `scheduledTaskId`, `sessionType` | user-global session-state |
| `claude-cowork` | Claude Cowork local MCPB extension installs | Windows package root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/extensions-installations.json` | JSON | MCPB extension install records, server command/args, signatureInfo.status, declared tools | package-root inventory |
| `claude-cowork` | Claude Cowork local-agent-mode session descriptors | Windows package root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/local_*.json` | JSON | `remoteMcpServersConfig[].{name,uuid,tools[].name}` inventory; plaintext approval fields `enabledMcpTools`, `userSelectedFolders`, `egressAllowedDomains`, `orgCliExecPolicies`, dangerous `permissionMode` values; session metadata `scheduledTaskId`, `sessionType` | package-root session-state |
| `claude-cowork` | Claude Cowork local MCPB extension manifests | Windows package root auxiliary | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/Claude Extensions/*/manifest.json` | JSON | MCPB extension metadata backfill | package-root auxiliary |
| `claude-cowork` | Claude Cowork local MCPB extension enable state | Windows package root auxiliary | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/Claude Extensions Settings/*.json` | JSON | `isEnabled` only | package-root auxiliary |
| `claude-cowork` | Claude Cowork named remote connector installs | Windows package root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_plugins/installed_plugins.json` | JSON | installed plugin ids/names; resolves bundled `.mcp.json` connector manifests | package-root inventory |
| `claude-cowork` | Claude Cowork named remote connector enable state | Windows package root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_settings.json` | JSON | `enabledPlugins`, `disabledPlugins`, `extraKnownMarketplaces` enable-state only | package-root inventory |
| `claude-cowork` | Claude Cowork bundled remote connector manifests | Windows package root auxiliary | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/cowork_plugins/**/*.mcp.json` | JSON | connector name/id, transport, URL, optional declared tools | package-root auxiliary |
| `claude-cowork` | Claude Cowork rpm plugin bundled remote connector manifests | Windows package root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/rpm/plugin_*/.mcp.json` | JSON | connector name/id, transport, URL when connected, installed-but-not-connected state for empty URLs | package-root inventory |
| `claude-cowork` | Claude Cowork rpm plugin metadata | Windows package root auxiliary | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/rpm/plugin_*/.claude-plugin/plugin.json` | JSON | plugin metadata path is in scope; scanner does not emit private plugin metadata values | package-root auxiliary |
| `claude-cowork` | Claude Cowork local MCPB extension npm dependencies | Windows registered extension root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/Claude Extensions/*/package-lock.json` | JSON | npm package names, versions, scopes, PURLs | extension-root dependency inventory |
| `claude-cowork` | Claude Cowork local MCPB extension npm dependencies fallback | Windows registered extension root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/Claude Extensions/*/package.json` | JSON | npm dependency names and exact package versions when present | extension-root dependency inventory |
| `claude-cowork` | Claude Cowork local MCPB installed npm packages fallback | Windows registered extension root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/Claude Extensions/*/node_modules/**/package.json` | JSON | installed npm package names, versions, PURLs | extension-root dependency inventory |
| `cursor` | Cursor workspace MCP | workspace bounded search | filename `mcp.json`, parent `.cursor`, max depth 6 | JSON | `mcpServers`, `servers` | workspace |
| `cursor` | Cursor workspace MCP | workspace bounded search | filename `mcpServers.json`, parent `.cursor`, max depth 6 | JSON | `mcpServers`, `servers` | workspace |
| `cursor` | Cursor user MCP | Linux-style user config | `.config/Cursor/mcp.json` | JSON | `mcpServers`, `servers` | user-global |
| `cursor` | Cursor user MCP | Windows/macOS/Linux home-rooted user config | `.cursor/mcp.json` | JSON | `mcpServers`, `servers` | user-global |
| `cursor` | Cursor project MCP metadata | Windows/macOS/Linux user-global project cache | `.cursor/projects/*/mcps/*.json` | JSON | `mcpServers`, `servers` | user-global cache |
| `cursor` | Cursor project MCP metadata | Windows/macOS/Linux user-global project cache | `.cursor/projects/*/mcps/*/SERVER_METADATA.json` | JSON | top-level `serverName` / `serverIdentifier`, optional transport fields | user-global cache |
| `continue` | Continue MCP config | Windows/macOS/Linux user/workspace | `.continue/config.yaml` | JSON or YAML | `mcpServers`, `mcp_servers` | user/workspace config |
| `continue` | Continue MCP config | Windows/macOS/Linux user/workspace | `.continue/config.yml` | JSON or YAML | `mcpServers`, `mcp_servers` | user/workspace config |
| `continue` | Continue MCP config | Windows/macOS/Linux user/workspace | `.continue/config.json` | JSON or YAML | `mcpServers`, `mcp_servers` | user/workspace config |
| `claude-code` | Claude Code MCP config | target root | `.mcp.json` | JSON | `mcpServers`, `projects.default.mcpServers` | workspace/user config |
| `claude-code` | Claude Code MCP config + auto-edit approval state | Windows/macOS/Linux user | `.claude.json` | JSON | `mcpServers`, `projects.default.mcpServers`, `acceptEdits` | user config |
| `claude-code` | Claude Code MCP config + saved approval state | Windows/macOS/Linux user | `.claude/settings.json` | JSON | `mcpServers`, `projects.default.mcpServers`, `permissions.allow` | user config |
| `claude-code` | Claude Code session-local auto-edit approval state | macOS user | `Library/Application Support/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json` | JSON | `acceptEdits` only; grant evidence emits `fs:write` without raw prompt/session values | user-global session-state |
| `claude-code` | Claude Code session-local auto-edit approval state | Windows user | `AppData/Roaming/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json` | JSON | `acceptEdits` only; grant evidence emits `fs:write` without raw prompt/session values | user-global session-state |
| `claude-code` | Claude Code session-local auto-edit approval state | Windows package root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/.claude/.claude.json` | JSON | `acceptEdits` only; grant evidence emits `fs:write` without raw prompt/session values | package-root session-state |
| `claude-code` | Claude Code workspace MCP config | workspace bounded search | filename `.mcp.json`, any parent, max depth 4 | JSON | `mcpServers`, `projects.default.mcpServers` | workspace |
| `claude-code` | Claude Code project saved approval state | workspace bounded search | filename `settings.local.json`, parent `.claude`, max depth 5 | JSON | `mcpServers`, `projects.default.mcpServers`, `permissions.allow` | workspace |
| `claude-code-desktop` | Claude Code desktop session descriptors | macOS user | `Library/Application Support/Claude/claude-code-sessions/*/*/local_*.json` | JSON | `remoteMcpServersConfig[].{name,uuid,tools[].name}` inventory; plaintext approval fields `enabledMcpTools`, `alwaysAllowedReasons`, `sessionPermissionUpdates`, `userSelectedFolders`, `egressAllowedDomains`, `orgCliExecPolicies`, dangerous `permissionMode`; session metadata `scheduledTaskId`, `sessionType` | user-global session-state |
| `claude-code-desktop` | Claude Code desktop session descriptors | Windows user | `AppData/Roaming/Claude/claude-code-sessions/*/*/local_*.json` | JSON | same fields as macOS Claude Code desktop session descriptors | user-global session-state |
| `claude-code-desktop` | Claude Code desktop session descriptors | Windows package root | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/claude-code-sessions/*/*/local_*.json` | JSON | same fields as macOS Claude Code desktop session descriptors | package-root session-state |
| `codex-cli` | Codex CLI MCP config + saved approval state | Windows/macOS/Linux user | `.codex/config.toml` | TOML | `mcp_servers`, `projects.*.approval_policy`, `projects.*.sandbox_mode` | user-global |
| `codex-cli` | Codex CLI project MCP config + saved approval state | workspace bounded search | filename `config.toml`, parent `.codex`, max depth 5 | TOML | `mcp_servers`, `projects.*.approval_policy`, `projects.*.sandbox_mode` | workspace |
| `codex-app` | Codex App saved tool approvals | Windows/macOS user | `.codex/config.toml` | TOML | `apps.*.tools.*.approval_mode`; evidence references redact local config paths as `codex-app://config#...` | user-global |
| `codex-app` | Codex App full-access global state | Windows/macOS user | `.codex/.codex-global-state.json` | JSON | narrow fields only: `agent-mode`, `sandboxPolicy.type`, `approvalPolicy`, `skip-full-access-confirm`, `active-workspace-roots`; prompt history and other state never emitted | user-global |
| `codex-app-plugin` | Codex App plugin/marketplace inventory | Windows/macOS user | `.codex/config.toml` | TOML | `plugins.*`, `marketplaces.*`; absolute marketplace paths redacted; `projects.*` never emitted | user-global |
| `factory` | Factory MCP config | Windows/macOS/Linux user/workspace | `.factory/mcp.json` | JSON | `mcpServers`, `servers` | workspace/user config |
| `factory` | Factory workspace MCP config | workspace bounded search | filename `mcp.json`, parent `.factory`, max depth 5 | JSON | `mcpServers`, `servers` | workspace |
| `zed` | Zed MCP/context-server config | user | `.config/zed/settings.json` | JSON | `context_servers`, `mcpServers` | user-global |
| `zed` | Zed MCP/context-server config | workspace | `.zed/settings.json` | JSON | `context_servers`, `mcpServers` | workspace |
| `vscode` | VS Code workspace MCP config | workspace | `.vscode/mcp.json` | JSON | `servers`, `mcp.servers`, `mcpServers` | workspace |
| `vscode` | VS Code project MCP config | workspace bounded search | filename `mcp.json`, parent `.vscode`, max depth 5 | JSON | `servers`, `mcp.servers`, `mcpServers` | workspace |
| `vscode` | VS Code user MCP config | Linux-style user config | `.config/Code/User/mcp.json` | JSON | `servers`, `mcp.servers`, `mcpServers` | user-global |
| `vscode` | VS Code user settings MCP config | Linux-style user config | `.config/Code/User/settings.json` | JSON | `servers`, `mcp.servers`, `mcpServers` | user-global |
| `vscode` | VS Code user MCP config | Windows user | `AppData/Roaming/Code/User/mcp.json` | JSON | `servers`, `mcp.servers`, `mcpServers` | user-global |
| `vscode` | VS Code user settings MCP config | Windows user | `AppData/Roaming/Code/User/settings.json` | JSON | `servers`, `mcp.servers`, `mcpServers` | user-global |
| `antigravity` | Google Antigravity user MCP | Windows/macOS/Linux user | `.gemini/antigravity/mcp_config.json` | JSON | `mcpServers` | user-global |

Claude Cowork support includes local MCPB extension inventory in
`extensions-installations.json`, plus sibling manifests and `Claude Extensions
Settings/*.json` files observed to contain only `isEnabled` enable-state data.
For registered extension install roots only, Reeve also reads
`package-lock.json`, root `package.json`, or installed package manifests under
that extension's own `node_modules` tree to emit npm dependency PURLs and
CycloneDX dependency edges from the parent extension.

For named Cowork remote connectors, Reeve reads
`local-agent-mode-sessions/*/*/cowork_plugins/installed_plugins.json`, resolves
installed plugin ids to bundled `cowork_plugins/**/*.mcp.json` manifests, and
emits connector names, transport type, and URL. Reeve also reads
`local-agent-mode-sessions/*/*/rpm/plugin_*/.mcp.json` so Cowork rpm plugin
bundles that contain `mcpServers` / `servers` maps are inventoried by connector
name. Empty rpm connector URLs are reported as installed-but-not-connected, not
as live endpoints. Reeve reads sibling `cowork_settings.json` only for
`enabledPlugins`, `disabledPlugins`, and `extraKnownMarketplaces`
enable-state.

For Cowork app-internal state, Reeve records presence only:
`LocalCache/Roaming/Claude/config.json` `dxt:allowlistCache` is reported as an
encrypted approval cache, and candidate Electron state stores under
`LocalCache/Roaming/Claude/IndexedDB/**/*` and
`LocalCache/Roaming/Claude/Local Storage/leveldb/*` are reported as opaque
remote-connector stores. Reeve
does not decrypt the Electron safeStorage/DPAPI approval blob, parse
IndexedDB/LevelDB records, extract tokens, or emit Cowork `granted`
capabilities from these opaque stores. Connector names/URLs are inventoried
only from plaintext bundled `.mcp.json` manifests under `cowork_plugins` and
`rpm/plugin_*`, not from encrypted or LevelDB stores. Reeve also does
not walk arbitrary `node_modules` outside registered extension roots or crawl
marketplaces. See
[ADR-0027](decisions/0027-claude-cowork-local-mcpb-inventory.md) and
[ADR-0028](decisions/0028-ai-harness-extension-npm-dependency-inventory.md)
for local MCPB inventory and scoped extension dependencies, and
[ADR-0029](decisions/0029-claude-cowork-approval-and-remote-connector-state.md)
for the approval-state and remote-connector boundary.

For Cowork plaintext session approvals, Reeve reads only
`local-agent-mode-sessions/*/*/local_*.json` files. `remoteMcpServersConfig`
is inventory only. Fixture-proven plaintext approval fields emit
`granted-permission` evidence: `enabledMcpTools` as `mcp:cowork-tool:*`,
`userSelectedFolders[]` as `fs:read` / `fs:write`, `egressAllowedDomains` as
`net:egress`, `orgCliExecPolicies` as `exec:subprocess`, and only dangerous
`permissionMode` bypass values as wildcard `exec:subprocess`. Relative folder
paths and ambient fields emit no grants. Grant evidence references use
`claude-cowork://local-agent-mode-session#...`, not raw session file paths. See
[ADR-0039](decisions/0039-claude-cowork-plaintext-session-approval-boundary.md).

Claude Code desktop session descriptors are tracked separately as
`claude-code-desktop`, because the desktop app's `claude-code-sessions/*/*`
store is distinct from the Claude Code CLI's `.claude/settings.json` and
`.claude.json` files. The desktop session parser reuses the same plaintext
session-field boundary as Cowork but emits `mcp:claude-code-desktop-tool:*`
for approved tools and records `scheduledTaskId` / `sessionType` as session
metadata, not as proof of safety. See
[ADR-0040](decisions/0040-claude-code-desktop-session-surface.md).

For Claude Code `.claude.json`, Reeve treats `acceptEdits` as saved auto-edit
approval state and emits a `fs:write` grant. It reads the user-global
`.claude.json` plus session-local
`local-agent-mode-sessions/*/*/.claude/.claude.json` files, including the
Windows Store package-root equivalent. Reeve does not emit raw prompt/session
values from these files. See
[ADR-0041](decisions/0041-claude-code-accept-edits-grant.md).

For Codex App full-access state, Reeve reads `.codex/.codex-global-state.json`
only for narrow grant fields: `agent-mode`, `sandboxPolicy.type`,
`approvalPolicy`, `skip-full-access-confirm`, and `active-workspace-roots`.
Prompt history and all other global-state payload fields are out of scope and
must not be serialized. See
[ADR-0042](decisions/0042-codex-app-global-state-full-access.md).

For Claude Desktop, `preferences.localAgentModeTrustedFolders[]` in
`claude_desktop_config.json` is parsed as plaintext trusted-folder approval
state. Each absolute POSIX, Windows drive, or Windows UNC path emits
`granted-permission` evidence and `fs:read` / `fs:write` granted
capabilities for that folder. Every host path serialized into AIBOM/CDX
output — not just saved grants — redacts the OS user segment before
serialization, for example `/Users/<redacted-home>/LegalDocs` and
`C:\Users\<redacted-home>\LegalDocs`; non-home absolute scopes stay absolute.
See [ADR-0045](decisions/0045-username-free-aibom-output.md). Reeve does not
treat this as full Claude approval coverage, does
not infer permissions from relative paths, and does not decrypt or parse Cowork
`dxt:allowlistCache`, IndexedDB, or LevelDB records for grants. See
[ADR-0037](decisions/0037-claude-desktop-trusted-folder-approval-boundary.md).

Zed has no Windows build, so Reeve does not add a Windows Zed read path.

## System-wide custom surface config

When no explicit `--surface-config <path>` is provided, Reeve checks
one system-wide custom-surface config path:

| OS | Path | Behavior |
|---|---|---|
| Linux | `/etc/reeve/surfaces.yaml` | Loaded when present; missing is not an error |
| macOS | `/Library/Application Support/Reeve/surfaces.yaml` | Loaded when present; missing is not an error |
| Windows | `%PROGRAMDATA%\Reeve\surfaces.yaml` | Loaded when present; missing is not an error |

Precedence is:

1. Explicit `--surface-config <path>`.
2. System-wide config path.
3. No custom surface config.

Use `--no-system-config` to disable the system-wide lookup for testing
or debugging. Workspace-rooted `.reeve/surfaces.yaml` and
`~/.reeve/surfaces.yaml` are deliberately not auto-discovered in this
phase; they remain available only through the explicit flag until signed
surface-config bundles land.

Signed bundles are supported for both explicit and system-wide custom
surface configs. If `surfaces.yaml.sigstore.json` exists next to the
config, Reeve verifies that bundle before parsing the config. Failed
verification refuses the config. Missing signatures warn by default and
fail closed when `--require-signed-config` is set. Use
`--signer-identity-regexp` or build-time
`REEVE_SURFACE_CONFIG_SIGNER_IDENTITY_REGEXP` to pin the deployer OIDC
identity.

### Bounded workspace search skips

For `claude-code`, `codex-cli`, `factory`, and `vscode` workspace searches,
Reeve skips these directory names while walking:

```text
.cache, .git, .idea, .next, .venv, .vscode-insiders, build, coverage, dist, node_modules, out, target, venv
```

No other directory names are treated as discovery roots.

## Sandbox profiling read/write boundary

Default scans do not enter this section. This section applies only when
`reeve scan --profile` is set. If a scan also needs live declared
capabilities from MCP `tools/list`, use `--introspect-execute` as a
separate opt-in.

When `reeve scan --profile` profiles a local stdio MCP server:

- Reeve creates a dedicated temporary profiler directory and sets an isolated profiler home below it.
- macOS uses `sandbox-exec` with default deny and denied-action logging.
- Linux uses Landlock filesystem enforcement and seccomp network denial when supported. `strace` collects syscall evidence from that enforced run. If kernel enforcement is unavailable, Reeve reports the explicit observational fallback per ADR-0009.
- Windows profiling is observational under ADR-0017. Reeve may capture
  filesystem, network, and process behavior evidence through Windows
  event tracing when available, and emits explicit telemetry-gap evidence
  when the runner cannot provide usable events. That observation is not
  sandbox enforcement and AppContainer remains deferred.
- The macOS profile allows reads for the server executable, symlink-resolved executable path, package/runtime paths needed to launch the server, `/dev/null`, `/dev/random`, `/dev/urandom`, and the profiler tempdir.
- The Linux profile allows reads for the server executable, symlink-resolved executable path, package/runtime paths needed to launch the server, `/dev/null`, `/dev/random`, `/dev/urandom`, and the profiler tempdir.
- The macOS profile allows writes only below the profiler tempdir.
- The Linux and macOS profiles allow writes only below the profiler tempdir.
- Network access is deliberately not allowed by the sandbox profile; egress/listen attempts are denied and logged as observed capability evidence.
- macOS subprocess execution is allowed only for the initial executable paths needed to launch the server; later unrelated subprocess attempts are denied and logged. Linux records subprocess execution as observed capability evidence; fuller subprocess prevention is deferred in ADR-0009.
- Sensitive passwd paths are explicitly re-denied after runtime baseline rules so reads are captured as denied evidence: `/etc/passwd`, `/private/etc/passwd`, `/private/etc/master.passwd`.

## What Reeve never reads in v0.1

Reeve v0.1 does not read or scan:

- arbitrary files in the home directory;
- source code outside the exact config paths and bounded workspace searches listed above;
- custom role-specific or user-invented layouts that are not listed in
  this read set, unless an operator supplies them through
  `--surface-config`;
- conversation logs or session stores unless the operator explicitly opts
  into the separate sensitive-data report flags described below;
- documents, browser profiles, email, notes, calendars, photos, or chat history;
- SSH private keys, cloud credential files, keychains, password-manager stores, or shell history;
- network shares or other users' home directories;
- model weights, training data, vector databases, or non-AI SBOM package trees;
- runtime traffic payloads or live IDE/editor buffers.

Config files may contain references to secrets such as environment variable names or command arguments. Reeve treats those as config references for inventory evidence; it does not resolve secret values from secret stores.

## Opt-in conversation-log inventory

Conversation-log and session-store scanning is outside the default v0.1
read set. `reeve scan` does not touch those files unless the operator
passes one of these explicit flags:

- `--include-conversation-metadata` inventories only metadata for the
  supported conversation-store roots: redacted path, file count, total
  bytes, and last-modified timestamps.
- `--scan-conversation-secrets` enables a second opt-in: Reeve reads the
  file contents under those same roots and runs the bundled
  secret-pattern rules plus any operator suppressions file.
- `--conversation-rules-file <path>` extends
  `--scan-conversation-secrets` with a customer rule pack that validates
  against `schema/secret-rule-pack-v0.1.0.json`. Reports record the pack
  id, version, digest, and canonical id, but never serialize regex
  content or matched values.

Both paths emit a separate sensitive-data report rather than
embedding findings in the AIBOM. The AIBOM remains the broad authority
and capability artifact. The sensitive-data report is for tighter-access
privacy review and may require separate retention and ACL handling.
For GitHub Actions-style CI annotation, add `--sensitive-data-sarif`
with either opt-in flag. Reeve then writes a companion
`*.sensitive-data.sarif.json` file over the same redacted findings:
rule ids, redacted locations, severity, confidence, match counts, and
suppression state. The SARIF output follows the same privacy boundary as
the JSON report and excludes raw conversation content, raw secret
values, surrounding text, and secret hashes.

Current opt-in conversation-store roots are:

| Surface | Exact path relative to `--target <root>` | Metadata-only flag | Content-read flag |
|---|---|---|---|
| `claude-desktop` | `Library/Application Support/Claude/projects/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-desktop` | `AppData/Roaming/Claude/projects/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-code` | `.claude/projects/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-code-desktop` | `Library/Application Support/Claude/claude-code-sessions/*/*/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-code-desktop` | `AppData/Roaming/Claude/claude-code-sessions/*/*/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-code-desktop` | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/claude-code-sessions/*/*/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-cowork` | `Library/Application Support/Claude/local-agent-mode-sessions/*/*/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-cowork` | `AppData/Roaming/Claude/local-agent-mode-sessions/*/*/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-cowork` | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/local-agent-mode-sessions/*/*/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-cowork` | `Library/Application Support/Claude/IndexedDB/*.leveldb/*.log` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-cowork` | `AppData/Roaming/Claude/IndexedDB/*.leveldb/*.log` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `claude-cowork` | `AppData/Local/Packages/Claude_*/LocalCache/Roaming/Claude/IndexedDB/*.leveldb/*.log` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `cursor` | `.cursor/projects/*/agent-transcripts/*/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `codex-app` | `Library/Application Support/Codex/archived_sessions/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `codex-app` | `.codex/sessions/**` when `.codex/config.toml` contains App plugin or marketplace state | `--include-conversation-metadata` | `--scan-conversation-secrets` |
| `codex-cli` | `.codex/sessions/**` | `--include-conversation-metadata` | `--scan-conversation-secrets` |

Claude Cowork support is limited to plaintext files under
`local-agent-mode-sessions/*/*/**` plus IndexedDB LevelDB `.log` WAL files
under the bounded Claude app-state roots listed above. Reeve does not decrypt
safeStorage/DPAPI data, parse LevelDB records, read Snappy-compressed `.ldb`
SSTables, or treat `Local Storage/leveldb/` as a conversation store. See
[ADR-0043](decisions/0043-cowork-leveldb-log-sensitive-data-boundary.md).

Cursor support is limited to plaintext `.cursor/projects/*/agent-transcripts/*/**`
JSONL transcript files. Reeve does not parse Cursor SQLite, IndexedDB,
or VS Code-style app-state databases as conversation stores.

When the shared `.codex/sessions/**` store has a Codex App
plugin/marketplace marker, Reeve labels it `codex-app` and does not also
emit a duplicate `codex-cli` surface.

The metadata-only path does not read conversation bodies. The
content-pattern path may read file contents to classify likely secret
matches, but the serialized report still excludes raw conversation
content, surrounding text, raw secret values, embeddings, screenshots,
searchable indexes, and hashes of secret values. Pattern findings are
evidence that needs human review, not proof of a confirmed leak.

Example CI-oriented invocation:

```bash
reeve scan --target "$HOME" \
  --scan-conversation-secrets \
  --conversation-suppressions-file .reeve/sensitive-suppressions.json \
  --sensitive-data-sarif \
  --output-dir reeve-out
```

## Report generation

`reeve report --aibom <path>` is an offline rendering step. It reads
only the AIBOM file passed on the command line and writes the requested
HTML, PDF, or flattened JSON report to `--output <path>`. It does not
perform endpoint discovery, read additional config files, contact agent
processes, or re-run sandbox profiling.

`reeve fleet-report --evidence-dir <path>` is an offline static
aggregation step. It recursively reads existing `*.aibom.json` evidence
files under the directory passed on the command line and writes a
single-file HTML, Markdown, or flattened JSON fleet summary to
`--output <path>`. It does not run discovery, scan endpoints, contact a
hosted service, use a database, or change scanner behavior.

## Worked example: Mac developer with Cursor + Claude Desktop + Codex

For `reeve scan --target ~` on macOS where the user has Cursor, Claude Desktop, and Codex CLI, Reeve may touch exactly these discovery paths if they exist:

```text
~/Library/Application Support/Claude/claude_desktop_config.json
~/.cursor/mcp.json
~/.cursor/mcpServers.json
~/projects/*/.cursor/mcp.json
~/projects/*/.cursor/mcpServers.json
~/.cursor/projects/*/mcps/*.json
~/.cursor/projects/*/mcps/*/SERVER_METADATA.json
~/.codex/config.toml
```

If `--profile` is also set, Reeve may launch discovered local stdio MCP servers inside the profiling sandbox described above. The sandboxed server may attempt its own reads; Reeve records allowed/denied observed behavior as evidence. Reeve itself still does not expand discovery beyond the listed config paths.

## Change-control rule

Any PR that adds or changes an MCP discovery surface must update this document in the same PR. CI runs `scripts/check-scope-docs.py`, which checks that every built-in `SurfaceSpec` name, literal path, glob path, workspace-search filename, and parser root remains represented in `docs/scope.md`.

The machine-readable form of this same static contract is:

```bash
reeve scope list --format json
```

The output includes an `osPaths` catalog for macOS, Linux, Windows, and workspace-relative paths. Windows discovery is config-file discovery only. ADR-0017 defines Windows observational profiling as observation rather than enforcement; Windows profiling and Windows sandbox enforcement remain separate product claims.

Custom MCP surfaces are lower trust. If an operator passes
`--surface-config <path>`, that explicit file has precedence. Otherwise
Reeve checks the system-wide path above unless `--no-system-config` is
set. The file's relative paths/globs are added to `reeve scope list` and
`reeve scan --dry-run`; Reeve rejects absolute custom paths and `..`
escapes. User-defined discoveries are marked `source: "user-defined"`
in AIBOM v0.2 per ADR-0011.

For a host-specific preview before reading config contents or writing scan artifacts, use:

```bash
reeve scan --dry-run --target ~
```

Related docs:

- `README.md` links here for security reviewers.
- `docs/adapter-roadmap.md` defines v0.2+ Adapter expansion roadmap gates for non-MCP surfaces; it does not expand the v0.1 filesystem read set.
- `docs/positioning.md` explains bounded scope as part of Reeve's market positioning.
- `SECURITY.md` describes filesystem read-scope issues as part of the vulnerability policy.
