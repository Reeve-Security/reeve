# Reeve docs index

Design documents, specifications, and supporting notes. Schema,
policies, and crates live outside this folder; pointers below.

## Recommended reading order

1. [positioning.md](positioning.md) — what Reeve is and the evidence-not-claims thesis.
2. [architecture.md](architecture.md) — three-layer adapter / core / policy boundary and rationale.
3. [build-order.md](build-order.md) — schema-first v1 build order and dependency layering.
4. [v1-spec.md](v1-spec.md) — full v1 specification: collectors, evidence pipeline, signing, policy.
5. [../schema/SPEC.md](../schema/SPEC.md) — human-readable AIBOM schema spec; canonical contract.
6. [decisions/](decisions/) — numbered ADRs recording why each design choice was made.

## Strategy and vision

- [positioning.md](positioning.md) — Reeve as a system of record for the AI supply chain.
- [scope.md](scope.md) — filesystem scope contract for what Reeve reads.
- [pillar-launch-audit.md](pillar-launch-audit.md) — launch-safe and forbidden claims for the three product pillars.
- [reeve-product-brief.md](reeve-product-brief.md) — version-agnostic overview of operation and deployment.

## Architecture and specs

- [architecture.md](architecture.md) — three-layer architecture and inter-layer contracts.
- [v1-spec.md](v1-spec.md) — full v1 product specification.
- [signing.md](signing.md) — plain-language walkthrough of signing outputs.
- [integrations.md](integrations.md) — fitting Reeve into existing SBOM and vulnerability tooling.

## Build and release

- [build-order.md](build-order.md) — schema-first sequencing of layers.
- [release-readiness.md](release-readiness.md) — minimal path to declare a release ready.
- [public-launch-cutover.md](public-launch-cutover.md) — clean public repository cutover procedure.
- [releases/](releases/) — per-version capability appendices and verification recipes.

## Adapters and deployment

- [adapter-roadmap.md](adapter-roadmap.md) — post-v0.1 adapter expansion decomposition.
- [deployment-scenarios.md](deployment-scenarios.md) — operational flow at three scales.
- [demo-archetypes.md](demo-archetypes.md) — background archetype catalog for lab fleet planning.
- [demo-script.md](demo-script.md) — one-shot mixed-platform recording script.
- [lab-infra.md](lab-infra.md) — trusted-branch CI capacity and lab plan.

## Decisions

ADRs are numbered and live in [decisions/](decisions/); see
[decisions/README.md](decisions/README.md) for the index and template.

## Marketing and GTM

- [marketing/](marketing/) — deck options, landing pages, and marketing-asset workspace.
- [gtm/](gtm/) — go-to-market sales, messaging, persona, and objection-handling notes.

## Audits and research

- [audits/](audits/) — periodic project audits (schema, crates, policies, docs).
- [research/](research/) — bounded research notes such as the sigstore-rs maturity gate.

## Schema and policies

- [../schema/](../schema/) — AIBOM JSON Schema, error codes, and fixture corpus.
- [../policies/](../policies/) — default Rego policy catalog and policy tests.

## For contributors

Read [CONTRIBUTING.md](../CONTRIBUTING.md) before opening a pull request, and
[CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) for community expectations.
Security researchers should review [SECURITY.md](../SECURITY.md) and
[THREAT_MODEL.md](../THREAT_MODEL.md) for the disclosure process and the
in-scope attack surface.
