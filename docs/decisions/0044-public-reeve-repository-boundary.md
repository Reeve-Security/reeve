# ADR-0044: Public Reeve owns the binary and reproducibility primitives only

- **Status:** Accepted 2026-06-09
- **Decides:** Public repository boundary after Reeve Labs pipeline split
- **Related:** ADR-0025, ADR-0038, `docs/mcp-registry-seed.md`,
  `docs/mcp-registry-api.md`

## Context

Reeve is preparing for a public launch. The public repository must be
easy to explain: it builds and verifies the open-source Reeve binary,
schemas, policies, fixtures, and reusable primitives required to
reproduce or consume Reeve evidence.

Reeve Labs data work now has a separate private operational repository.
That repository can run scheduled capture, persistence, enrichment, and
publication jobs without putting private operations, hosting assumptions,
or tokens in the public binary repository.

## Options considered

### A. Keep all registry data work in Reeve

This keeps every script and workflow in one repository.

Pros: fewer repositories. Cons: public Reeve becomes responsible for
scheduled data production, artifact publishing, and future enrichment
jobs that are not part of the endpoint binary.

### B. Move all registry-related code out of Reeve

This removes every registry command, verifier, fixture, and consumer
contract from the public repository.

Pros: cleanest visual separation. Cons: weakens reproducibility. A user
could not rebuild, inspect, or verify registry-derived artifacts with
public code.

### C. Keep public primitives; move operations out *(chosen)*

Reeve keeps only the parts needed by the binary and by independent
verification: fetch, normalize, sign, verify, consume static lookup
artifacts, and test fixtures. The private pipeline owns scheduled runs,
storage, enrichment jobs, and publication.

Pros: public Reeve stays focused on the binary while preserving
reproducibility. Cons: the boundary must be enforced because similar
registry names appear on both sides.

## Decision

The public `reeve` repository owns the Reeve binary, AIBOM schema,
policy engine, scanner, signing and verification code, public fixtures,
and reusable registry primitives that make external artifacts
reproducible.

The public repository does not own scheduled registry capture, Supabase
storage, data-retention jobs, vulnerability-feed publication, static API
artifact generation, GitHub Pages publishing, cross-repo write tokens, or
Reeve Labs operational workflows.

## Rationale

This preserves the public trust story. Anyone can inspect the code that
the Reeve binary uses, and anyone can verify or reproduce signed
registry-derived artifacts from public inputs. At the same time, the
public repository does not become an operations repository for a hosted
data product.

The split also follows ADR-0038. Public Reeve emits and consumes facts,
evidence, and deltas. Reeve Labs may operationalize those facts in a
separate pipeline, but the binary repository must not imply hosted
service behavior or safety verdicts.

## Plain-language summary

Think of Reeve as the measuring tool. The public repository should hold
the tool, the ruler markings, the tests proving the ruler is accurate,
and the verifier that checks someone else's measurements.

Think of the Labs pipeline as the factory schedule. It decides when to
collect public registry data, where to store raw pages, when to enrich
them, and when to publish generated files. That schedule is useful, but
it is not the Reeve binary.

So public Reeve may include code that says, "given these public pages,
here is the deterministic artifact." It may also include code that says,
"given this artifact source, the scanner can use it as extra lookup
context." It must not include cron jobs, database writes, publish tokens,
or data-product plumbing.

This keeps launch simple: the public repo answers "what is Reeve and how
do I build/run/verify it?" The private pipeline answers "how do we keep
the Labs data updated?"

## Consequences

- **This decision commits the project to:** keeping `mcp-registry-fetch`,
  `mcp-registry-seed`, registry-source consumption, and seed verification
  as public reproducibility primitives.
- **This decision unblocks:** public launch cleanup without losing
  independent verification of registry-derived data.
- **This decision forecloses:** top-level public scripts or workflows
  that generate, enrich, publish, or host Reeve Labs data artifacts.
- **This decision defers:** Supabase schema, raw-page retention policy,
  enrichment cadence, and public data publication to the private pipeline
  repository and later public data repository.

## References

- `docs/mcp-registry-seed.md`
- `docs/mcp-registry-api.md`
- `crates/aibom-cli/src/registry_pagination.rs`
- `scripts/verify-mcp-registry-seed.py`
