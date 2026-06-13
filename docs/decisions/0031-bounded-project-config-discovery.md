# ADR-0031: Bounded project config discovery for known MCP surfaces

- **Status:** Accepted
- **Date:** 2026-05-26
- **Decides:** Discover known per-project MCP and approval config filenames under the scan target with depth and skip limits
- **Related:** `docs/scope.md`, GitHub issue #246, ADR-0011, ADR-0022

## Context

Reeve already reads fixed home-rooted MCP config surfaces such as
`.claude/settings.json`, `.codex/config.toml`, and `.vscode/mcp.json`. Several
agents also store riskier project-scoped config below arbitrary project
directories:

- Claude Code `.mcp.json`
- Claude Code `.claude/settings.local.json`
- Codex `.codex/config.toml`
- VS Code `.vscode/mcp.json`
- Factory `.factory/mcp.json`

Those locations are "known filename, unknown parent." A blind full-disk crawl
would be noisy and risky, especially around `node_modules`, `.git`, build
trees, and plugin catalogs.

## Options considered

### A. Keep only fixed home-rooted paths

Rejected. Project-scoped approvals and MCP registrations are often more
permissive than user-level defaults, so keeping only fixed paths leaves a known
blind spot.

### B. Add unbounded recursive globs

Rejected. Unbounded `**` globs under a home directory can walk dependency
trees, vendored fixtures, build outputs, and marketplace catalogs. That expands
the read set beyond the customer-facing scope contract.

### C. Add registry-driven bounded workspace searches *(chosen)*

Chosen. Each built-in surface can declare exact project-level filenames,
optional required parent directory names, max depth, and skip directory names.
Discovery still reads only known config filenames under the scan target.

## Decision

Reeve adds registry-driven bounded workspace searches for project-level MCP and
approval config. These searches are default within the operator-selected scan
target, but they are constrained by filename, parent directory when applicable,
max depth, and the common skip list documented in `docs/scope.md`.

For grant-only Claude Code or Codex project config files, Reeve emits a
grant-state provider so `permissions.allow`, `approval_policy`, `sandbox_mode`,
and app tool `approval_mode` evidence is not dropped merely because no MCP
server registration appears in the same file.

## Rationale

This matches Reeve's config-reader boundary from ADR-0022. The scanner does not
inspect arbitrary source code, dependency packages, or endpoint runtime state.
It only opens declared config filenames under a bounded traversal. The registry
keeps this behavior visible in `reeve scope list`, `reeve scan --dry-run`, and
`docs/scope.md`.

Grant-only project config needs a provider anchor because AIBOM capabilities are
emitted per discovered component. Without that anchor, saved approvals in
project-level files would parse correctly but never reach the report when no MCP
server lives beside them.

## Plain-language summary

Reeve now looks inside project directories for the small set of agent config
files users actually put there. It does not search every file in a repo.

If a project has a Claude or Codex file that says "auto-approve this risky
command" but does not register an MCP server, Reeve still reports the approval.
That is the evidence security teams need.

## Consequences

- **This decision commits the project to:** bounded workspace searches for
  documented built-in MCP surfaces, with depth caps and skip directories.
- **This decision unblocks:** detecting project-level Claude Code, Codex, VS
  Code, and Factory MCP registrations and saved approvals under arbitrary
  project parents below the scan target.
- **This decision forecloses:** using unbounded recursive config globs for
  built-in project discovery.
- **This decision defers:** registry-derived project path discovery from IDE
  recent-workspace databases and any future explicit `--scan-projects` CLI
  ergonomics.

## References

- `docs/scope.md`
- `crates/aibom-scanner/src/mcp/discovery/mod.rs`
- GitHub issue #246: https://github.com/Reeve-Security/reeve/issues/246
