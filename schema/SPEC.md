# AIBOM Schema Specification

**Status:** v0.1.0, v0.2.0, and v0.3.0 are immutable schema contracts.

This directory holds the formal AIBOM schema spec, its JSON Schema
definition(s), and example AIBOM documents.

## Intended contents

- `aibom-v<version>.json` — formal JSON Schema (Draft 2020-12).
- `SPEC.md` — this file, expanded as the schema is drafted.
- `examples/` — example AIBOM documents that validate against the
  schema.

## Design premises

- The schema **extends CycloneDX 1.5 / 1.6**. CycloneDX 1.6 introduced
  an `ml-model` component type, but it covers model provenance and
  does not address protocol-adapter metadata, declared-vs-observed
  capabilities, or sandbox-derived behavioral evidence. Reeve's
  extension fills that gap under an `aibom` namespace.

- The schema is the **public contract**. v2 adapters, downstream
  policy engines, dashboards, and auditors consume this schema
  directly. Breaking changes require a version bump.

- Entries are **protocol-agnostic at the top level**. A consumer
  that only speaks CycloneDX sees a valid CycloneDX document. A
  consumer that understands the `aibom` namespace gets the
  additional evidence fields.

## What each entry must encode

Per `docs/architecture.md`, each AIBOM entry carries six layers of
evidence. The schema must express each as a first-class, validatable
field group:

1. **Identity** — package source, name, version, hash algorithm,
   hash value.
2. **Provenance** — Sigstore certificate, OIDC identity claim,
   signature verification status, Fulcio chain reference.
3. **Transparency** — Rekor log UUID, log URL, inclusion-proof
   reference.
4. **Capabilities** — a `declared` set and an `observed` set, with
   syscall / network / filesystem granularity on the observed side.
   Capability delta is derivable, not stored.
5. **Known vulnerabilities** — CVE, GHSA, and OSV identifiers with
   status and reference URLs.
6. **Reputation** — publisher identifier, first-seen timestamp,
   install-base counters. Population deferred to v2+; field space
   reserved in v1 so consumers need not re-parse.

Plus top-level metadata:

- **Policy verdicts.** Per-policy status (allow / deny / warn),
  justification string, VEX reference.
- **Scan metadata.** Scanner identity and version, target
  description, scan timestamp, scan duration, adapter identity and
  version.

## Resolved decisions

Full decision records live in `../docs/decisions/`. Summaries here.

### Q1 — CycloneDX extension strategy: CycloneDX sidecar

AIBOM ships as a **sidecar document** alongside a minimal CycloneDX
document. The CycloneDX document carries identity fields only
(package name, version, hash, publisher) and references the sidecar
via `externalReferences[]` with `type: "bom"` and a content hash.
The sidecar carries typed evidence, policy verdicts, scan metadata,
and provenance references.

Sub-choice: one sidecar per scan, not per component. Component-level
anchors inside the sidecar map back to CycloneDX `bom-ref` values.

See: [ADR-0001](../docs/decisions/0001-cyclonedx-extension-strategy.md)
for the full rationale, rejected alternatives (property extension,
new component type), plain-language summary, and consequences.

### Q2 — Schema versioning: semver with 0.x minor = compatibility boundary

AIBOM schema uses **semantic versioning**. Every document carries two
fields: `$schema` (URL pinning the exact schema file) and
`aibom.schemaVersion` (human version string). Schema URLs are
**immutable** — any byte change produces a new URL.

**Before 1.0:** PATCH = clarification only; MINOR = compatibility
boundary (may be breaking); consumers pin exact major.minor.

**At 1.0 and later:** PATCH = compatible fix; MINOR = additive only;
MAJOR = breaking.

See: [ADR-0002](../docs/decisions/0002-schema-versioning-policy.md)
for the full rationale, rejected alternatives (CalVer, hybrid),
plain-language summary, the consumer negotiation rule, and
consequences.

### Q3 — Canonicalization: RFC 8785 JCS plus deterministic array ordering

Sidecar canonicalization is **JCS (RFC 8785)** plus schema-defined
**deterministic array ordering** for set-semantics collections. The
sidecar artifact referenced from CycloneDX is distributed in
canonical bytes; pretty-printed JSON is a non-authoritative view
only. Arrays are tagged in the schema as `set` (sort by the rule in
ADR-0003) or `sequence` (natural order preserved).

See: [ADR-0003](../docs/decisions/0003-canonicalization-profile.md)
for the full rationale, rejected alternatives (custom profile,
DSSE-only), distribution rule, per-array ordering rules,
plain-language summary, and consequences.

### Q4 — Signature envelope: DSSE-wrapped in-toto Statement in a Sigstore bundle v0.3

Reeve signs the CycloneDX + AIBOM sidecar pair as one in-toto
Statement v1 with two subjects (CDX digest + sidecar digest),
wrapped in a DSSE envelope (`payloadType =
application/vnd.in-toto+json`), distributed as a Sigstore bundle
v0.3. Keyless Sigstore via Fulcio + OIDC; Rekor v2 `dsse` inclusion
proof **required** for v0.1 production.

Verifier separates **verified facts** (Sigstore identity, Rekor
integrated time, bundle version) from **claimed facts** (sidecar
content). Rego policies consume verified facts for trust decisions;
`aibom.publisher` and similar claimed fields are display-only for
trust purposes. Five failure modes (missing, stale, mismatched,
untrusted identity, invalid statement) are fail-closed; overrides
refused by strict/production profiles.

See: [ADR-0004](../docs/decisions/0004-signature-envelope.md) for
the full rationale, rejected alternatives (plain JWS, CycloneDX
native JSF), Statement shape and structural invariants, identity
allowlist, verifier fail-closed behavior, Rego input schema,
plain-language summary, and consequences.

### Q5 — Capability taxonomy: closed core + namespaced extensions, structured objects

Capabilities are structured objects `{id, qualifiers, source,
evidence[]}`. The **core vocabulary** (closed, v0.1 = eight ids:
`fs:read`, `fs:write`, `net:egress`, `net:listen`,
`exec:subprocess`, `env:read`, `secret:read`, `ipc:connect`) has
schema-defined qualifier keys per id. **Extension ids** use either a
registered adapter namespace (v0.1 registers only `mcp`) or a
reverse-DNS namespace (two+ DNS labels); single-label namespaces
outside the registry are reserved. Declared, observed, and (in
v0.2+) granted capabilities live in separate arrays per component;
the delta is derived, not stored. Evidence is required
(`minItems: 1`). Schema rejects core-looking unregistered ids and
source/array mismatches.

Declared capability evidence can cite either `mcp-registration` when
the value came from static config identity, or `mcp-tools-list` when
the operator explicitly enabled live MCP introspection execution.

Starting with v0.2.0, the **top-level** `aibom.components` and
`aibom.evidence` arrays may be empty when discovery succeeds but finds
no providers. This represents a clean endpoint, not a scanner failure.
Capability-level `evidence[]` still requires at least one entry. See
[ADR-0018](../docs/decisions/0018-empty-discovery-is-valid-inventory.md).

AIBOM v0.2 also adds component-level discovery trust source for
custom surfaces: `source: "built-in"` means the provider came from a
reviewed Reeve surface in the signed binary, while
`source: "user-defined"` means the provider came from a user-supplied
custom surface config. See
[ADR-0011](../docs/decisions/0011-custom-surfaces.md).

AIBOM v0.3 keeps the v0.2 document shape and expands filesystem
`qualifiers.path` from POSIX-only absolute paths to a cross-OS absolute
path grammar: POSIX absolute paths, Windows drive absolute paths, and
Windows UNC roots. See
[ADR-0026](../docs/decisions/0026-windows-path-qualifiers.md).

**Consequence:** a new default policy `no-unknown-extension-
capability` (Policy #11) is appended to `policies/README.md`; the
existing ten default policies keep their numbers unchanged.

See: [ADR-0005](../docs/decisions/0005-capability-taxonomy.md) for
the full rationale, rejected alternatives (fully closed; fully
freeform), core registry and qualifier semantics, extension
grammar (with regex), merging and ordering rules, deferred items
(confidence field, glob grammars, additional core ids),
plain-language summary, and consequences. Windows absolute path
grammar for filesystem `qualifiers.path` is added by
[ADR-0026](../docs/decisions/0026-windows-path-qualifiers.md) in
the v0.3.0 schema contract.

## Open questions for the drafting pass

All v0.1 schema design questions resolved. Remaining work moves to
JSON Schema authoring, fixture drafting, and the evidence-record
ledger structure — these are implementation steps, not open
questions.

## Non-goals for v0.1

- Adapters beyond MCP (v2+ adapters will extend the schema, not
  rewrite it).
- Runtime-telemetry fields (v4).
- Model-weight and training-data lineage (v2 / v3).
- SPDX equivalents (CycloneDX only in v1).

## Sensitive-data report v0.1.0

ADR-0019 defines a separate report for opt-in conversation/session-store
sensitive-data inventory. This report is not an AIBOM sidecar and does
not change the AIBOM schema. It exists because AIBOM answers "what AI
authority exists?" while sensitive-data inventory answers "where may
secrets or sensitive records already sit in local assistant history?"

The first report schema is
`schema/sensitive-data-report-v0.1.0.json`.

Customer-supplied content rules use
`schema/secret-rule-pack-v0.1.0.json`. Rule packs require
`rulePackId`, `rulePackVersion`, and `rules[]` entries with `ruleId`,
`patternClass`, `confidence`, `description`, and Rust-regex-compatible
`regex`. The scanner rejects malformed packs and regex features outside
Rust's linear-time regex engine before reading conversation content.

### Privacy boundary

Default Reeve scans do not read conversation logs. A report exists only
when the operator enables metadata inventory. Content pattern scanning
requires a second opt-in. The exact CLI flag names are deferred to the
implementation issue, but user-facing language should prefer
"conversation" over "AI log".

The report must never serialize:

- raw conversation content;
- raw secret values;
- surrounding text;
- embeddings;
- screenshots;
- searchable indexes;
- hashes of secret values.

Findings are rule matches that require human review. They are not claims
that a secret was confirmed leaked.

### Report shape

Each report contains:

- `schemaVersion` and immutable `$schema` URL;
- `canonicalization` profile for JCS-canonical bytes;
- `scan` metadata with scanner identity, version, target, and timestamp;
- `inputs` recording metadata/content opt-ins, scanner version, rule-pack
  identity, custom-rules identity (`id`, `version`, `digest`,
  `canonicalId`), and suppressions identity;
- `redaction` metadata documenting default path redaction;
- `surfaces` with per-agent file counts and aggregate byte counts;
- `findings` with agent surface, redacted path, file size, mtime, pattern
  class, rule id, rule-pack version, match count, confidence,
  human-review marker, and evidence/source reference;
- optional `signature` reference to the Sigstore bundle that signs the
  canonical report bytes.

Paths under user-controlled namespaces are redacted by default. Raw
project names, repository names, hostnames, usernames, session
identifiers, and free-form directory names do not belong in default
serialized reports. Operators may choose an explicit unredacted mode for
local debugging, but that is not the default artifact shape.

### Signing story

Sensitive-data reports are signable as their own artifact. The report is
serialized in canonical bytes using
`RFC8785-JCS+reeve-sensitive-data-report-array-order-v0.1`, then signed
through the same Sigstore trust model Reeve uses elsewhere. The report
does not embed the Sigstore bundle by default; it may carry a
`signature.bundleRef` plus SHA-256 digest so evidence pipelines can keep
restricted sensitive-data reports separate from broad AIBOM/SBOM
storage. When Reeve emits the report, the adjacent bundle naming is
`<scan-id>.sensitive-data.sigstore.json` for real signing and
`<scan-id>.sensitive-data.sigstore.fixture.json` for deterministic
fixture/demo output.

### Fixture corpus

Fixtures live under `schema/examples/sensitive-data-report/`:

- positive metadata-only report for Claude Desktop on macOS;
- positive metadata-only report for Claude Code;
- positive content-pattern finding report for Claude Desktop on macOS;
- positive content-pattern finding report for Claude Desktop on Windows;
- positive content-pattern finding report for Codex CLI;
- negative raw-secret serialization attempt;
- negative conversation-content finding serialization attempt;
- negative raw conversation-content serialization attempt;
- negative secret-hash serialization attempt;
- negative content-snippet serialization attempt;
- negative content scan missing rule-pack identity.

Secret-rule-pack fixtures live under
`schema/examples/secret-rule-pack/`:

- positive customer token rule pack;
- negative missing rule-pack version.

These fixtures are schema-level contract tests for #169. Later scanner,
policy, SARIF, and lab-validation issues extend them as implementation
lands.

## Status

Drafting continues in a dedicated conversation. Commit history
tracks the latest schema version.
