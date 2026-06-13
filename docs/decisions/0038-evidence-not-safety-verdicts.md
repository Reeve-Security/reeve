# ADR-0038: Reeve records says/can/has-done evidence, not safety verdicts

- **Status:** Accepted
- **Date:** 2026-06-06
- **Decides:** Product and schema boundary for evidence, deviation, and safety
  claims across the CLI, AIBOM, corpus, policy output, and future API surfaces
- **Related:** ADR-0005, ADR-0008, ADR-0017, ADR-0022,
  `docs/positioning.md`, `docs/architecture.md`, `docs/v1-spec.md`,
  `docs/scope.md`

## Context

Reeve's public positioning already says that Reeve produces evidence, not safety
claims. As the corpus and future hosted lookup surfaces grow, that boundary
needs to be a numbered decision rather than a marketing sentence.

The same MCP server behavior can be acceptable in one customer environment and
a breach in another. For example, a database call may be expected for one
operator and forbidden for another. The artifact behavior is reusable evidence;
the safety verdict depends on caller context, local policy, data sensitivity,
and business intent.

This decision also protects the schema-first architecture. Reeve can record
what software claims, what authority it is wired or granted to use, and what it
did under observed conditions. It should not add an intrinsic `safe` field or
publish unqualified labels such as "clean", "trusted", or "approved to run".

## Options considered

### A. Publish intrinsic safety labels

Rejected. A global safety label would collapse customer-specific context into a
single answer Reeve cannot know. It would also create liability when evidence is
incomplete, behavior is environment-gated, or local policy differs.

### B. Treat policy verdicts as Reeve's safety claim

Rejected. Policy verdicts are useful, but they are evaluations against a named
rule bundle and input document. A deny or warn is a reproducible policy result,
not a universal product claim that a tool is safe or unsafe in every context.

### C. Record evidence plus deviation, and leave safety to the caller *(chosen)*

Chosen. Reeve records structured facts about what the software says, can do, and
has done, plus derived deviation between evidence points. Customers, agents,
gateways, SOC workflows, and policy engines decide what those facts mean in
their context.

## Decision

Reeve is the source of truth for three evidence classes:

1. **SAYS:** what the software claims or declares. This includes registry
   metadata, manifest metadata, declared capabilities, declared remotes, and
   declared package coordinates.
2. **CAN:** what authority or reachable surface is present. This includes
   declared capabilities, saved grants, declared remotes, hosted endpoint URL
   digests, and package coordinates already present in MCP metadata. It does
   not include general static reachability analysis or conventional non-AI SBOM
   scanning.
3. **HAS DONE:** what Reeve observed under explicit conditions. This includes
   profiler evidence, profile skips, blocked hosted-remote profiling, platform,
   runner, input, coverage, and other conditions needed to interpret the run.

Reeve may derive and publish **deviation** across these evidence classes, such
as changed metadata, changed declared capabilities, changed package
coordinates, new hosted endpoints, new advisory matches, or observed behavior
that differs from prior evidence.

Reeve must not publish intrinsic safety verdicts. Product surfaces must avoid
unqualified labels such as "safe", "clean", "approved", "trusted", or
"known good" unless the label is explicitly scoped to a named customer policy,
allowlist, signature verification result, or other concrete rule.

Policy output remains in scope, but it must be framed as a rule-bundle result:
"this AIBOM denied under policy X" is valid; "this tool is unsafe" is not.

For hosted remotes, Reeve records endpoint facts and URL-digest joins. It does
not fabricate package coordinates or claim sandbox-observed behavior for code
that Reeve did not run.

## Rationale

Evidence is reusable across customers. Safety is not. A SOC, gateway, agent, or
GRC workflow can combine Reeve evidence with local context and decide whether a
behavior is allowed. Reeve should make that decision easier, not pretend that
the decision is context-free.

This keeps Reeve aligned with SBOM tooling. An SBOM tells you what is present.
Vulnerability scanners, policy engines, auditors, and operators decide what to
do with that inventory. Reeve applies the same pattern to AI agent tools.

This boundary also reduces claim risk. Profiling has coverage limits. Hosted
remote code may not be runnable by Reeve. Public registries may have incomplete
package metadata. Those gaps are acceptable if represented as evidence and
conditions; they are dangerous if hidden behind a clean/safe label.

Finally, this rule protects the three-layer architecture. Protocol adapters,
core, policy, corpus, and future APIs can all exchange canonical evidence
without adding private safety side channels or layer-specific conclusions.

## Plain-language summary

Reeve answers three questions: what does this software say it is, what can it
reach or use, and what did it do when Reeve observed it?

Reeve does not answer "is it safe?" by itself. That answer depends on who is
using the tool, what data it can reach, which environment it runs in, and what
the customer's policy allows.

This is the same reason an SBOM does not say an application is safe. It lists
what is inside. Other systems and people decide what that inventory means.

Reeve can still report deviations. If a tool adds a new remote endpoint, changes
its package coordinates, gains a new grant, or behaves differently under
profiling, Reeve can say exactly what changed. That is evidence a customer can
act on.

Policy verdicts are still useful, but they are scoped. A policy result means
"this document matched this rule bundle", not "Reeve globally declares this
tool safe or unsafe."

## Consequences

- **This decision commits the project to:** evidence-first wording and schema
  design across CLI, AIBOM, reports, corpus artifacts, and future lookup APIs.
- **This decision unblocks:** a stable positioning rule for corpus, Labs, and
  future API design without moving into governance or runtime enforcement.
- **This decision forecloses:** intrinsic `safe` fields, unqualified "clean" or
  "trusted" labels, and hosted-remote behavior claims without observation.
- **This decision defers:** customer-specific governance, runtime blocking,
  hosted dashboards, and commercial API verdict products to later explicitly
  scoped decisions.

## References

- `docs/positioning.md`
- `docs/architecture.md`
- `docs/v1-spec.md`
- `docs/scope.md`
- ADR-0005: `docs/decisions/0005-capability-taxonomy.md`
- ADR-0008: `docs/decisions/0008-granted-source-amendment.md`
- ADR-0017: `docs/decisions/0017-windows-observational-profiling.md`
- ADR-0022: `docs/decisions/0022-config-reader-not-proxy.md`
