# ADR-0018: Empty discovery is valid inventory

- **Status:** Accepted 2026-05-01
- **Decides:** Clean endpoints with no discovered MCP providers produce signed empty AIBOM/CycloneDX artifacts and exit 0
- **Related:** ADR-0001, ADR-0002, ADR-0005, issue #91

## Context

Phase 1 VPS validation found that `aibom-cli scan` failed when discovery
completed successfully but found no MCP providers:

```text
Error: no MCP providers discovered under /home
```

That behavior is wrong for fleet deployment. Many endpoints have no AI
agents installed at scan time. A clean HR laptop, finance laptop, build
runner, or fresh VM is not a scanner failure; it is an inventory result.

The existing v0.2.0 schema still required at least one top-level
component and one top-level evidence record. That matched early fixture
needs, but it does not match real fleet semantics.

## Options considered

### A. Keep failing when no providers are found

This treats absence of AI agents as an error.

- **Pros:** no code or schema change.
- **Cons:** creates false-positive deployment failures on clean
  endpoints; makes systemd timers and SIEM ingestion noisy; forces every
  customer to special-case the normal empty state.
- **Rejected.** Clean inventory is data, not an error.

### B. Emit a synthetic component for "no providers"

This keeps the schema unchanged by adding a placeholder component.

- **Pros:** avoids changing top-level array cardinality.
- **Cons:** lies in the inventory. A component means something exists on
  the endpoint. A synthetic component would pollute diffs, policy input,
  and customer reports.
- **Rejected.** Evidence-not-claims means no fake inventory.

### C. Allow empty top-level `components` and `evidence` arrays *(chosen)*

Discovery success with zero providers emits a valid AIBOM sidecar with
empty top-level arrays, a valid CycloneDX BOM with empty `components`,
and a Sigstore bundle over both artifacts.

- **Pros:** matches SBOM inventory convention; supports fleet-wide
  deployment; preserves exact truth of endpoint state; keeps genuine
  errors fail-closed.
- **Cons:** broadens v0.2.0 schema semantics. Consumers that assumed at
  least one component need to handle the empty case.
- **Accepted.** This is the smallest truthful representation of a clean
  endpoint.

## Decision

Reeve treats empty discovery as successful inventory. The scanner exits
0, writes signed artifacts, and emits v0.2.0 sidecars with empty
top-level `aibom.components` and `aibom.evidence` arrays.

This relaxation applies only to top-level arrays. Capability objects
still require at least one evidence reference. A claimed capability with
no evidence remains invalid per ADR-0005.

## Rationale

Reeve is an inventory tool. Inventory tools must distinguish "scan
failed" from "scan succeeded and found nothing." That distinction is
load-bearing for enterprise deployment because Reeve is meant to run
everywhere, including endpoints that have no AI tools.

CycloneDX and common scanner conventions support empty results. Tools
like package auditors and SBOM generators normally return success with
an empty document when the input has no packages. Reeve should follow
that convention for AI tool inventory.

The design also preserves Reeve's evidence posture. We do not create a
synthetic component or pretend a provider exists. The absence is carried
by the empty arrays and signed scan metadata.

## Plain-language summary

If Reeve scans a laptop and finds no AI agents, that is useful
information. It means "this machine is clean right now," not "the
scanner broke."

Before this decision, Reeve treated that clean state as an error. That
would make a company deployment noisy because many employee laptops will
have no AI tools installed. The monitoring system would see failures
even though the scan worked.

Now Reeve writes an empty-but-valid inventory. The report still has a
timestamp, target metadata, and a signature. It just has zero discovered
components. That is the right shape for audit and fleet reporting.

This does not weaken evidence requirements. If Reeve says a tool has a
capability, that capability still needs evidence. Empty inventory only
means no tools were found.

## Consequences

- **This decision commits the project to:** exit code 0 for successful
  empty discovery; empty top-level AIBOM/CycloneDX arrays; signed
  artifacts for empty scans.
- **This decision unblocks:** Phase 1 deployment templates without
  fixture seeding; clean endpoint fleet scans; issue #91.
- **This decision forecloses:** representing absence through fake
  components or failing timers on clean endpoints.
- **This decision defers:** richer optional "no providers discovered"
  explanatory evidence records. Empty arrays are sufficient for now.

## References

- Issue #91: Scanner errors on empty discovery
- `crates/aibom-scanner/src/mcp/output.rs`
- `schema/aibom-v0.2.0.json`
- ADR-0005: Capability taxonomy
