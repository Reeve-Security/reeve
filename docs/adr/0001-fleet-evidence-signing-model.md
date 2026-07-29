# ADR 0001: Fleet Evidence Signing Model

Status: Accepted for naming and trust-boundary guidance.

Date: 2026-07-29

## Context

Reeve produces evidence at an endpoint, can roll endpoint evidence up into
fleet views, and signs its release artifacts. Those are related but separate
trust boundaries.

Issue #70 needs stable wording for fleet evidence so docs, CLI help, and future
implementation work do not overstate what a signature proves. In particular,
collector-side signing can make a fleet artifact or ingestion receipt
tamper-evident after collection, but it does not prove that the endpoint itself
signed the original scan output.

This record follows the current README wording and the current CLI behavior in
`crates/aibom-cli/src/main.rs`.

## Current Shipped Truth

- Reeve release archives and installers are Sigstore-signed.
- Scan output is signable. `aibom-cli scan --sign-mode real` requires real
  signing and fails if real signing is unavailable. Fixture behavior is used
  for `--sign-mode fixture`, for `--skip-sign`, and for `--sign-mode auto` when
  real signing is unavailable.
- Fixture Sigstore bundles are deterministic placeholders for tests and demos.
  They are not signed provenance.
- `fleet-report` is a local rollup/report surface over endpoint AIBOM sidecars.
  It does not create signed provenance.
- `fleet-manifest` is the current collector-side manifest primitive. It indexes
  endpoint evidence artifacts and may carry a real or fixture Sigstore bundle
  for the collector-side artifact.
- A real `fleet-manifest` bundle signs the collector-side manifest artifact. It
  does not make the indexed endpoint artifacts endpoint-signed evidence.
- Endpoint and MDM/deploy template scans using `--skip-sign` remain unsigned for
  provenance purposes.

## Decision

Reeve documentation and future implementation work will use three evidence
signing tiers.

### 1. Unsigned or Fixture Endpoint Output

This tier covers endpoint scan output produced with `--skip-sign`,
`--sign-mode fixture`, or `--sign-mode auto` when real signing is unavailable.
It also covers endpoint and MDM/deploy template scans that intentionally use
`--skip-sign`.

Allowed names include "unsigned endpoint output", "fixture endpoint output",
and "endpoint output without signed provenance".

This tier must not be described as signed provenance. A fixture bundle may be
useful for exercising verification paths, but it does not establish a
cryptographic claim about who produced the endpoint evidence.

### 2. Collector-Signed Fleet Evidence / Signed Ingestion Receipt

This tier covers a collector-side artifact, such as a fleet manifest or
ingestion receipt, that indexes endpoint evidence artifacts and is signed by a
collector identity.

Allowed names include "collector-signed fleet evidence" and "signed ingestion
receipt".

This tier proves only that the collector identity signed the collector-side
statement over the artifact set it received or recorded. It can make the
collector's inventory tamper-evident after collection, but it does not prove
that the endpoint generated the bytes, that the scan ran on the stated endpoint,
or that the bytes were protected before the collector signed them.

Collector-signed evidence must never be described as endpoint-signed evidence.

### 3. Endpoint-Signed Evidence

This tier covers endpoint scan output signed at the endpoint, at scan time, by
an endpoint-controlled signing identity.

Allowed names include "endpoint-signed evidence" and "endpoint-signed scan
output".

This tier is the only tier that can claim the endpoint signing boundary. Its
strength depends on how the endpoint identity is issued, protected, and mapped
to the endpoint or workload that ran the scan.

## Recommended Roadmap

Prioritize collector-signed receipts first. They fit the current
`fleet-manifest` primitive, avoid endpoint signing identity rollout as an
initial dependency, and still give operators a tamper-evident record of what a
collector accepted.

Add endpoint signing later. Fleet-grade endpoint signing needs a clear endpoint
identity model, deployment integration, freshness controls, and verification
policy before Reeve should rely on it as the stronger claim.

## Risks and Limits

- A collector-signed receipt has a MITM/transit caveat: if unsigned endpoint
  evidence is modified before it reaches the collector, the collector can sign
  the modified bytes. Mitigations include authenticated transport, secured
  staging, endpoint-local hashing before upload, nonces or freshness windows,
  host identity checks, append-only receipt storage, and strict collector
  signing identity policy.
- A real Sigstore bundle proves a signing identity and signed bytes, not that
  the scanner observed a complete or uncompromised endpoint state.
- Fixture bundles intentionally do not prove provenance. They must remain
  visibly named and documented as fixture output.
- `fleet-report` output is useful for review, but it remains a report surface
  rather than a provenance artifact.
- Endpoint identity mistakes can turn endpoint-signed evidence into a false
  assurance. Endpoint signing needs issuance, rotation, revocation, and
  verification rules that are outside the current shipped fleet report path.

## Consequences

- Reeve docs and CLI descriptions should reserve "endpoint-signed evidence" for
  evidence signed at the endpoint boundary.
- `fleet-manifest` may be described as the collector-side manifest primitive and
  as a basis for collector-signed fleet evidence or signed ingestion receipts.
- `fleet-manifest` must not be described as producing endpoint-signed evidence.
- `fleet-report` remains a local report and rollup surface, not signed
  provenance.
- This ADR does not introduce code changes, tests, workflow changes, remote
  attestation, endpoint key provisioning, MDM deployment behavior, or a new
  signing protocol.
