# ADR-0047: CycloneDX output is pinned to spec 1.5 with review-gated upgrades

- **Status:** Accepted 2026-06-12
- **Decides:** Which CycloneDX spec version Reeve emits, how that promise is
  enforced, and when/how the version may change
- **Related:** ADR-0001 (sidecar + CycloneDX strategy), issue #474

## Context

Reeve's CycloneDX output is a machine contract: customers feed it into
supply-chain tools they already operate (vulnerability scanners,
SBOM platforms). Issue #474 added a committed regression test that
validates every emitted CDX against the official CycloneDX 1.5 JSON
schema (bundled under `crates/aibom-scanner/tests/data/cyclonedx/`),
proven against a real multi-surface scan including scoped npm purls and
the dependency graph.

That raised the policy question: should Reeve chase the latest CycloneDX
release as the spec evolves?

## Decision

**Pin to CycloneDX 1.5.** The public claim is exactly "emits CycloneDX
1.5", enforced by the #474 schema test in CI.

Upgrades are review-gated, not automatic:

- **Review cadence:** check newer CycloneDX releases quarterly and before
  any major Reeve release.
- **Upgrade only on clear value:** a new field Reeve needs, the consumer
  tool ecosystem has moved, a security fix in the spec, or a concrete
  buyer requirement.
- **Upgrade mechanics:** bump the emitted `specVersion`, swap the bundled
  schema fixtures, update the #474 test and docs, and record the change
  in a follow-up ADR (or an update to this one). The change ships like
  any compatibility-sensitive contract change.

## Why not always-latest

- Standards change faster than consumer tools adopt them; emitting a
  version a customer's scanner cannot parse breaks the core promise.
- Security buyers prefer a stable, boring contract over surprise
  upgrades.
- The AIBOM sidecar (ADR-0001) is where AI-specific evidence evolves;
  CycloneDX can stay conservative precisely because Reeve does not
  depend on it for expressiveness.

## Plain-language summary

Reeve writes its machine-readable inventory in CycloneDX version 1.5, a
widely supported industry format, and a test in our build system proves
every output conforms to that exact version. We deliberately do not jump
to newer versions of the format as they appear: the customers' existing
tools must keep parsing our files. We re-evaluate quarterly and upgrade
only when there is a concrete benefit, with tests and a recorded
decision — never as a side effect.

## Consequences

- **Commits the project to:** keeping the bundled 1.5 schema fixtures and
  the CI validation green; quarterly version reviews.
- **Unblocks:** the public claim "emits CycloneDX 1.5" with a passing
  test behind it.
- **Forecloses:** silently drifting the output format; adopting new spec
  fields without a recorded decision.
- **Defers:** any 1.6+ migration until a review finds clear value.
