# ADR-0011: User-defined custom MCP surfaces

- **Status:** Accepted 2026-04-27; amended 2026-04-28 for system-wide config lookup and signed bundles
- **Decides:** Custom MCP surface configuration and lower-trust component source labeling
- **Related:** ADR-0002 (versioning), ADR-0008 (granted source amendment), issue #35

## Context

Reeve ships reviewed, built-in MCP discovery surfaces for known desktop and CLI tools. Enterprise users also run proprietary internal agent stacks whose MCP config paths are unknowable at Reeve build time. Without an extension point, those agents require a fork or remain invisible to the AIBOM.

A custom surface is lower trust than a built-in surface. It is user-supplied configuration that tells Reeve which files to read and which object roots to parse. That can help inventory internal agents, but it must not become an arbitrary filesystem scanner or blur the trust boundary between reviewed Reeve code and local configuration.

## Decision

Reeve supports explicit custom MCP surfaces through `--surface-config <path>`. The file declares one or more surfaces with:

- `name`: a policy/AIBOM surface identifier.
- `paths`: relative config paths below the scan target.
- `glob-paths`: optional relative glob paths below the scan target.
- `format`: `json`, `json-or-yaml`, or `toml`.
- `roots`: object paths to parse for MCP server registrations; defaults to `mcpServers`.

The first implementation was explicit-only. As of the 2026-04-28
amendment, Reeve also checks one system-wide custom-surface config path
when no explicit `--surface-config <path>` is passed:

| OS | Path |
|---|---|
| Linux | `/etc/reeve/surfaces.yaml` |
| macOS | `/Library/Application Support/Reeve/surfaces.yaml` |
| Windows | `%PROGRAMDATA%\Reeve\surfaces.yaml` |

Precedence is explicit flag first, then system-wide path, then no
custom surface config. `--no-system-config` disables the system-wide
lookup for testing and debugging.

Reeve still does **not** implicitly read `~/.reeve/surfaces.yaml` or
repo-root `.reeve/surfaces.yaml`. Workspace and user-home auto-discovery
remain deferred even after signed system bundles. A malicious workspace
should not be able to change Reeve's scan behavior merely by planting a
local `.reeve/surfaces.yaml` file.

Signed surface-config bundles are covered by ADR-0013. When an adjacent
`surfaces.yaml.sigstore.json` exists, Reeve verifies the bundle before
parsing the config. `--require-signed-config` makes missing signatures
fail closed.

Any provider discovered through a custom surface is marked in AIBOM v0.2 as `source: "user-defined"`. Providers found only through built-in surfaces are marked `source: "built-in"` when v0.2 output is selected. Policies can use this field to apply stricter checks to user-defined inventory.

## Path-boundary rules

Custom surface paths must be relative to the scan target. Reeve rejects:

- absolute paths such as `/etc/shadow`,
- parent-directory escapes such as `../other-user/config.json`,
- empty paths,
- NUL-containing paths,
- matched paths that canonicalize outside the scan target, such as through a symlink.

Before reading a matched custom-surface file, Reeve canonicalizes both the scan target and the matched path. This keeps custom surfaces inside the selected scan root. Operators who need to scan another root must make that root the scan target explicitly.

## CLI behavior

- `reeve scan --surface-config <path>` discovers matching user-defined MCP registrations and emits AIBOM v0.2 when custom surfaces are present.
- `reeve scan` checks the system-wide custom-surface path when no
  explicit `--surface-config <path>` is passed, unless
  `--no-system-config` is set.
- `reeve scan --dry-run --surface-config <path>` lists the custom files that would be opened and marks the surface as lower trust.
- `reeve scan --dry-run` and `reeve scope list` report the system-wide
  config path they consulted and whether it was applied, missing, or
  disabled.
- `reeve scan --require-signed-config` and
  `reeve scope list --require-signed-config` refuse unsigned custom
  surface configs.
- `reeve scope list --surface-config <path>` includes custom surfaces in a distinct lower-trust section.

Custom surfaces reuse the existing MCP parser and sandbox/profiling path. They do not add a new protocol adapter and do not bypass the three-layer architecture.

## Plain-language summary

Reeve cannot know every company's private agent config paths. This decision lets an enterprise point Reeve at those paths with a YAML file instead of forking Reeve.

Because that YAML file is user-supplied or deployer-supplied, Reeve
labels anything it finds there as `user-defined`. That tells auditors
and policies: "this came from local configuration, not from a reviewed
built-in Reeve adapter." Reeve also refuses absolute paths and `..`
escapes so the feature cannot silently scan arbitrary system files.

System-wide lookup lets MDM or endpoint-management tooling deploy one
config file per machine without requiring every employee or scheduled
task to pass `--surface-config`. Reeve does not trust the file more
because it lives in a system path; it is still lower-trust inventory.

## Consequences

- **This decision commits the project to:**
  - a first-class lower-trust source label for custom-surface discoveries,
  - explicit dry-run visibility before custom config files are read,
  - relative-path-only custom surface definitions.
  - system-wide config precedence that is visible in `scope list` and
    `scan --dry-run`.
- **This decision unblocks:**
  - issue #35 custom adapter paths for internal enterprise agent stacks,
  - policy rules that require stricter checks for `source: "user-defined"`.
- **This decision defers:**
  - implicit user/workspace config lookup,
  - workspace/user-home signed surface-config auto-discovery,
  - interactive `surface add` helpers,
  - non-MCP protocol adapters.

## References

- [ADR-0002: Schema versioning policy](0002-schema-versioning-policy.md)
- [ADR-0008: Granted source amendment](0008-granted-source-amendment.md)
- `docs/adapter-roadmap.md`
- `schema/aibom-v0.2.0.json`
