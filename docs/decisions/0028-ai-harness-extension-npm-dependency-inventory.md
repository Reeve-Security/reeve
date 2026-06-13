# ADR-0028: AI harness extension npm dependencies are rooted at registered extensions

- **Status:** Accepted
- **Date:** 2026-05-25
- **Decides:** Scope and output shape for AI harness extension npm dependency inventory
- **Related:** ADR-0001, ADR-0026

## Context

Claude Cowork MCPB extensions can bundle npm dependencies inside the local
extension install root. Those dependencies are part of the AI tool supply
chain, but scanning arbitrary endpoint `node_modules` trees would turn Reeve
into a generic SBOM scanner and violate the v1 MCP adapter boundary.

Reeve needs dependency evidence only when it is tied to a registered AI harness
extension. The parent relation matters: consumers need to see endpoint ->
harness surface -> extension -> dependency, not an undifferentiated package
list.

## Options Considered

### A. Crawl all endpoint `node_modules`

This would find many packages, but most would be unrelated to AI harnesses. It
widens v1 into generic SBOM scanning and makes scope review hard.

### B. Add custom AIBOM dependency relationship fields

This would keep all relationships in the sidecar, but it requires schema work
before the first dependency slice can ship.

### C. Use registered extension roots plus CycloneDX dependency graph *(chosen)*

Read `package-lock.json`, root `package.json`, or installed
`node_modules/**/package.json` manifests only under discovered AI harness
extension install roots. Emit each npm package as a CycloneDX library component
with an npm PURL and a `dependencies[]` edge from the parent extension
component. Add matching AIBOM sidecar components so the CDX component remains
hash-linked to the AIBOM evidence package.

## Decision

Reeve inventories npm dependencies only under registered AI harness extension
roots. It does not crawl arbitrary `node_modules`, marketplace caches, or
non-AI project dependencies. The first implementation covers Claude Cowork
MCPB extension roots discovered by ADR-0027.

For MCPB extensions, the installed extension directory is the dependency root.
That matches Anthropic's MCPB `${__dirname}` contract: runtime paths are
resolved relative to the unpacked extension directory. Cowork's app-internal
registry may identify an install record generically, so sibling
`Claude Extensions/<id>/manifest.json` paths are authoritative when present.

Dependency identity is represented with npm PURLs in CycloneDX library
components. Parentage is represented with CycloneDX `dependencies[]` edges from
the extension component to its dependency components. The AIBOM sidecar carries
matching components with empty capability arrays, preserving the
CycloneDX/AIBOM hash-linked pair without adding a new schema relationship in
this slice.

## Rationale

CycloneDX already has a dependency graph. Using it avoids a schema bump while
still preserving the relationship consumers need. Rooting reads at registered
AI harness extensions keeps the feature inside Reeve's MCP adapter scope and
keeps it out of generic package scanning.

## Plain-Language Summary

Reeve now records npm packages bundled inside installed AI extensions, starting
with Claude Cowork MCPB extensions.

It only looks inside extension folders it already discovered as AI tool
registrations, including their installed `node_modules` trees. It does not scan
every `node_modules` directory on the machine.

The output says: this extension depends on these npm packages. Existing SBOM
tools can read that from the CycloneDX dependency graph, while Reeve's AIBOM
sidecar remains linked to the same components.

## Consequences

- **This decision commits the project to:** extension-root scoped npm
  dependency reads, including installed package manifests under the extension's
  own `node_modules`, and CycloneDX dependency edges for parentage.
- **This decision unblocks:** Desktop Commander/Cowork dependency inventory
  and later equivalent collectors for Codex, Zed, Factory, Antigravity, and
  other AI harness extension roots.
- **This decision forecloses:** generic endpoint `node_modules` crawling as
  part of v1 MCP discovery.
- **This decision defers:** vulnerability database lookups and richer AIBOM
  relationship fields.

## References

- `docs/decisions/0001-cyclonedx-extension-strategy.md`
- `docs/decisions/0027-claude-cowork-local-mcpb-inventory.md`
- `docs/scope.md`
- https://claude.com/docs/connectors/building/mcpb
- https://www.anthropic.com/engineering/desktop-extensions
