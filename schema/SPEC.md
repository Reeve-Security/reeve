# AIBOM Schema

This directory contains the JSON schemas and fixture contracts for Reeve's
AI Bill of Materials output.

## Files

- `aibom-v0.1.0.json`, `aibom-v0.2.0.json`, `aibom-v0.3.0.json`:
  immutable AIBOM sidecar schemas.
- `sensitive-data-report-v0.1.0.json`: schema for the opt-in
  sensitive-data report.
- `secret-rule-pack-v0.1.0.json`: schema for custom sensitive-data
  detection rules.
- `error-codes.md`: human documentation for validator error codes.
  Runtime truth lives in the Rust `ErrorCode` enum; CI checks this file
  stays in sync.
- `fixtures/`: canonical positive and negative contract fixtures used by
  the validator and policy test suites.

## Output Model

Reeve emits a CycloneDX 1.5 SBOM plus an AIBOM sidecar.

CycloneDX carries standard software inventory fields: components,
versions, purls, hashes, dependencies, and external references.

The AIBOM sidecar carries AI-agent evidence that CycloneDX does not model
directly:

- scan metadata;
- component identity and source;
- declared, observed, and granted capabilities;
- evidence records;
- policy verdicts;
- provenance and transparency references.

The CycloneDX document links to the sidecar with an external reference and
hash. Consumers that only understand CycloneDX still get a valid SBOM.
Consumers that understand AIBOM can read the AI-agent evidence.

## Versioning

Schema files are immutable once published. New structural behavior gets a
new schema file. Reeve supports `0.1.0`, `0.2.0`, and `0.3.0` sidecars
and selects the schema version required by the evidence it emits. Older
schema files stay in the tree for fixture and compatibility tests.

## Canonicalization

AIBOM sidecars are serialized with deterministic JSON ordering before
hashing and signing. Set-like arrays use stable sort keys so equivalent
documents produce the same bytes.

## Capability Sources

Capabilities are grouped by source:

- `declared`: what the agent or server reports through configuration or
  protocol metadata;
- `observed`: what Reeve saw during explicit profiling;
- `granted`: saved approvals or standing permissions Reeve can parse from
  local agent state.

Reeve reports evidence. It does not label a tool safe or unsafe.

## Sensitive-Data Report

Default scans do not read conversation logs. Sensitive-data reporting is a
separate opt-in artifact. It must not serialize raw conversation content,
raw secret values, snippets, embeddings, screenshots, or hashes of secret
values.

Findings are pattern matches that need human review, not confirmed-leak
claims.

## Validation

The fixture suite is part of the public contract. CI regenerates fixtures
and fails if generated output drifts unexpectedly.

`SPEC.md` is the human overview, not the machine source of truth. The
JSON schemas, Rust validator, and fixtures are authoritative. CI checks
this overview for concrete drift: listed schema files must exist, fixture
paths must match the tree, and every documented error code must match the
Rust enum.
