# Architecture Decision Records (ADRs)

This directory records design and architectural decisions made for
Reeve. Each ADR captures a single decision: the question that was in
front of us, the options considered, what we chose, why, and what
the decision commits the project to.

ADRs are numbered sequentially (`0001-…`, `0002-…`) and are never
renumbered. Supersession is recorded by updating the superseded
ADR's status and linking forward to the new one.

## Why ADRs exist

Reeve is a product. The documentation is load-bearing for the
business, not just the code. When a customer, auditor, or new
contributor asks "why did you choose X and not Y?", the answer must
be recoverable from the repository — not reconstructed from memory
months after the fact. ADRs are the recovery mechanism.

Every ADR must be understandable to a smart non-expert. The
plain-language summary section is not optional.

## When to write an ADR

Write an ADR any time you make a decision that:

- sets a rule for how future work proceeds (e.g., schema extension strategy),
- chooses one option from a field of two or more that were meaningfully considered,
- will be hard or costly to reverse later,
- shapes the public contract (schema, CLI surface, security properties, build order, distribution),
- should be explainable to a new contributor, customer, or auditor without reconstructing the reasoning from memory.

Day-to-day implementation choices local to a single file do not need
an ADR. Choices that shape the public contract always do.

## Template

Every ADR follows this structure:

```markdown
# ADR-NNNN: <short title, declarative>

- **Status:** Proposed | Accepted YYYY-MM-DD | Superseded by ADR-NNNN
- **Decides:** Q<N> from <file> / <question this resolves>
- **Related:** <other ADRs, docs>

## Context

Why is this decision in front of us? What constraint or requirement
forces a choice?

## Options considered

### A. <name>
Description. Pros. Cons.

### B. <name>
Description. Pros. Cons.

### C. <name> *(chosen)*
Description. Pros. Cons.

List every option that was meaningfully considered, including
options rejected by the dev team or external reviewers. Future
readers need to see the rejected paths to understand the decision.

## Decision

One paragraph stating what was chosen, in plain language. If there
are sub-decisions, list them.

## Rationale

Why this option beat the others. Reference the premises being
honored or the constraints being respected. Quote `schema/SPEC.md`,
`docs/architecture.md`, or `docs/v1-spec.md` sections if the
decision is driven by an existing commitment.

## Plain-language summary

Three to six paragraphs explaining the decision to someone who is
smart but not an expert in this domain. Analogies are welcome and
encouraged. This section exists so the decision can be explained to
a customer, auditor, or new contributor without them needing to
read the technical sections first. **This section is load-bearing
and not optional.**

## Consequences

- **This decision commits the project to:** concrete behaviors, file layouts, required fields.
- **This decision unblocks:** what work can now proceed.
- **This decision forecloses:** what options are no longer available.
- **This decision defers:** what related questions remain open.

## References

Relevant files, external specifications, related ADRs.
```

## Workflow

1. When a design question comes up, identify whether it meets the "when to write an ADR" criteria above.
2. Draft the ADR in parallel with making the decision — not retroactively. The argument and the record are the same work.
3. Number the ADR with the next available integer. Do not skip numbers. Do not renumber.
4. Once accepted, update the index in this README.
5. Update any affected specs (`schema/SPEC.md`, `docs/v1-spec.md`, etc.) to point at the ADR rather than duplicating the rationale inline. ADRs are canonical; specs summarize and link.
6. If a later decision supersedes an earlier one, edit the earlier ADR's status to `Superseded by ADR-NNNN` and link forward. Never delete an ADR.

## Index

- [ADR-0001: Extend CycloneDX via an AIBOM sidecar](0001-cyclonedx-extension-strategy.md)
- [ADR-0002: AIBOM schema uses semantic versioning; pre-1.0 minor bumps are compatibility boundaries](0002-schema-versioning-policy.md)
- [ADR-0003: AIBOM sidecar canonicalization is RFC 8785 JCS plus deterministic array ordering](0003-canonicalization-profile.md)
- [ADR-0004: Sign AIBOM + CycloneDX pair as a DSSE-wrapped in-toto Statement in a Sigstore bundle v0.3](0004-signature-envelope.md)
- [ADR-0005: Capability taxonomy — closed core vocabulary plus namespaced extensions, expressed as structured capability objects](0005-capability-taxonomy.md)
- [ADR-0006: Real signing requires cosign; distribution is documented prerequisite, not bundled](0006-cosign-dependency-strategy.md)
- [ADR-0007: Live Sigstore acceptance runs as a dedicated GitHub Actions workflow, not on every main push](0007-live-sigstore-acceptance.md)
- [ADR-0008: Add `granted` capability source and `granted-permission` evidence kind](0008-granted-source-amendment.md)
- [ADR-0009: Linux profiling uses enforcement when available, with explicit observational fallback](0009-linux-profile-observational-fallback.md)
- [ADR-0010: Release artifacts are signed as keyless cosign bundles](0010-release-artifact-signing.md)
- [ADR-0011: User-defined custom MCP surfaces](0011-custom-surfaces.md)
- [ADR-0012: CI runner substrate is Blacksmith; orchestration stays GitHub Actions](0012-ci-runner-substrate.md)
- [ADR-0013: System-wide surface configs verify adjacent Sigstore bundles](0013-signed-surface-config-bundles.md)
- [ADR-0014: Track 0 adds a Windows release-build target without Windows discovery or profiling](0014-windows-release-track0.md)
- [ADR-0015: Windows binary distribution starts without Windows discovery or profiling](0015-windows-binary-distribution.md)
- [ADR-0016: Windows MCP discovery is config-file only](0016-windows-mcp-discovery-paths.md)
- [ADR-0017: Windows profiling starts as explicit observational evidence](0017-windows-observational-profiling.md)
- [ADR-0018: Empty discovery is valid inventory](0018-empty-discovery-is-valid-inventory.md)
- [ADR-0019: Conversation-log scanning uses a separate opt-in sensitive-data report](0019-conversation-log-sensitive-data-report.md)
- [ADR-0020: Demo fleet is a phased, department-flavored, populated dataset — not the validation fleet](0020-demo-fleet-design.md)
- [ADR-0021: Customer secret rule packs use a versioned public schema](0021-secret-rule-pack-schema.md)
- [ADR-0022: Reeve is a config reader and on-endpoint profiler, not an MCP proxy](0022-config-reader-not-proxy.md)
- [ADR-0023: Demo fleet is a one-shot mixed-platform recording artifact](0023-demo-fleet-recording-scope.md)
- [ADR-0024: GitHub Releases plus Sigstore are the canonical distribution path](0024-release-distribution-strategy.md)
- [ADR-0025: Seed the central corpus from the official MCP Registry first](0025-official-mcp-registry-seed.md)
- [ADR-0026: AIBOM v0.3 accepts absolute Windows filesystem path qualifiers](0026-windows-path-qualifiers.md)
- [ADR-0027: Claude Cowork inventory is limited to local MCPB install state](0027-claude-cowork-local-mcpb-inventory.md)
- [ADR-0028: AI harness extension npm dependencies are rooted at registered extensions](0028-ai-harness-extension-npm-dependency-inventory.md)
- [ADR-0029: Claude Cowork opaque approval and remote connector state reporting](0029-claude-cowork-approval-and-remote-connector-state.md)
- [ADR-0030: Claude Cowork named remote connector inventory from plaintext plugin manifests](0030-claude-cowork-named-remote-connector-inventory.md)
- [ADR-0031: Bounded project config discovery for known MCP surfaces](0031-bounded-project-config-discovery.md)
- [ADR-0032: Codex App plugin/marketplace discovery redacts absolute paths and never reads the opaque Electron store](0032-codex-app-plugin-discovery-privacy-boundary.md)
- [ADR-0033: Codex App conversation scanning stays in the opt-in sensitive-data report](0033-codex-app-conversation-sensitive-data-boundary.md)
- [ADR-0034: Codex App saved tool approvals are distinct from Codex CLI project approvals](0034-codex-app-approval-state-boundary.md)
- [ADR-0035: Claude Cowork conversation scanning stays in the opt-in sensitive-data report](0035-claude-cowork-conversation-sensitive-data-boundary.md)
- [ADR-0036: Cursor conversation scanning stays in the opt-in sensitive-data report](0036-cursor-conversation-sensitive-data-boundary.md)
- [ADR-0037: Claude Desktop trusted-folder approvals are the only parsed Desktop approval grant](0037-claude-desktop-trusted-folder-approval-boundary.md)
- [ADR-0038: Reeve records says/can/has-done evidence, not safety verdicts](0038-evidence-not-safety-verdicts.md)
- [ADR-0039: Claude Cowork plaintext session approval fields are parsed as grant evidence](0039-claude-cowork-plaintext-session-approval-boundary.md)
- [ADR-0040: Claude Code desktop session state is a separate surface](0040-claude-code-desktop-session-surface.md)
- [ADR-0041: Claude Code `acceptEdits` is saved auto-edit grant evidence](0041-claude-code-accept-edits-grant.md)
- [ADR-0042: Codex App global state is parsed only for full-access grant fields](0042-codex-app-global-state-full-access.md)
- [ADR-0043: Cowork LevelDB `.log` files enter only the opt-in sensitive-data report](0043-cowork-leveldb-log-sensitive-data-boundary.md)
- [ADR-0044: Public Reeve owns the binary and reproducibility primitives only](0044-public-reeve-repository-boundary.md)
- [ADR-0045: Every serialized host path in AIBOM/CDX output is username-free](0045-username-free-aibom-output.md)
- [ADR-0046: Registry lookup is purl-first and token search never claims a match](0046-registry-purl-first-matching.md)
- [ADR-0047: CycloneDX output is pinned to spec 1.5 with review-gated upgrades](0047-cyclonedx-version-pin.md)
