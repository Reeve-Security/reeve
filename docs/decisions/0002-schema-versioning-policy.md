# ADR-0002: AIBOM schema uses semantic versioning; pre-1.0 minor bumps are compatibility boundaries

- **Status:** Accepted 2026-04-20
- **Decides:** Q2 from `schema/SPEC.md` — versioning policy
- **Related:** ADR-0001 (sidecar is the versioned artifact); ADR-0003 (canonicalization — pending)

## Context

ADR-0001 established that the AIBOM sidecar is a standalone versioned
artifact. Downstream consumers — policy engines, auditors, CI
tooling, dashboards — need a mechanical way to decide "can I parse
and trust this document without reading release notes?" That decision
rule is what Q2 codifies.

`schema/SPEC.md` §"Design premises" already commits the project to
"breaking changes require a version bump." Q2 specifies *what counts
as a break*, *how the version is carried in the document*, and *how
consumers negotiate compatibility*.

## Options considered

### A. Semantic versioning *(chosen)*

Version the schema `MAJOR.MINOR.PATCH`. Define which kinds of change
bump which digit. Carry the version in the document. Consumers pin
ranges and reject documents outside their supported range.

- **Pros:** matches the existing SPEC.md premise; matches the
  filename convention already in use (`aibom-v0.1.0.json`); matches
  ecosystem expectation (CycloneDX, SPDX, in-toto, JSON Schema, most
  Rust crates all use semver); produces clean range expressions
  policy engines can evaluate (`>=0.1 <0.2`). Pre-1.0 convention is
  well-understood even where it diverges from strict semver.
- **Cons:** pre-1.0 (`0.x`) semver is historically squishy. The
  project must commit to an explicit rule about what `0.x` bumps
  mean, or consumers cannot rely on version negotiation.

### B. Calendar versioning (CalVer: `2026.04.20` or `2026.04`)

Version by release date.

- **Pros:** signals "this spec evolves with the calendar."
- **Cons:** wrong signal for this project. Reeve wants consumers to
  **pin** a version and trust it. CalVer implies that subsequent
  dates deprecate prior dates. There is no native concept of
  "compatibility range" — a consumer cannot look at two CalVer
  strings and know whether they are interchangeable without reading
  release notes. If a v2 adapter ships in 2026.08 but schema changes
  are unrelated, version semantics become incoherent. Rejected.

### C. Hybrid (semver plus dated channels)

Semver for formal versions plus dated channels for pre-release builds.

- **Pros:** flexibility.
- **Cons:** premature complexity for v0.1; no demonstrated need.
  Rejected.

## Decision

**AIBOM schema uses semantic versioning.** The pre-1.0 rule is
stricter than generic semver guidance in order to give consumers a
mechanical rule.

### Before 1.0

- **PATCH** (`0.1.0` → `0.1.1`) — clarification or schema bugfix that
  does not change the structural contract. Any byte change to the
  schema file still produces a new URL (see *Consequences*).
- **MINOR** (`0.1.x` → `0.2.0`) — **compatibility boundary.** May
  contain breaking changes. **Consumers MUST NOT assume a `0.1`
  consumer can read a `0.2` document.** Consumers pin a specific
  `major.minor`, e.g. `>=0.1 <0.2`.
- Semantics: each `0.N` line is effectively its own contract until 1.0.

### At 1.0 and later

- **PATCH** (`1.0.0` → `1.0.1`) — compatible fixes and clarifications.
- **MINOR** (`1.0` → `1.1`) — **backward-compatible additions only.**
  A `1.0` consumer can read a `1.1` document, ignoring unknown fields.
- **MAJOR** (`1.x` → `2.0`) — breaking changes allowed. Consumers
  opt in.

### Where the version lives in the document

Two fields, each serving a different audience:

```json
{
  "$schema": "https://aibom.example/schemas/aibom-v0.1.0.json",
  "aibom": {
    "schemaVersion": "0.1.0"
  }
}
```

- **`$schema`** (top-level JSON Schema convention) — URL identifier
  of the exact schema. JSON Schema validators resolve this URL to
  fetch and validate.
- **`aibom.schemaVersion`** — machine-readable version string for
  consumers (policy engines, dashboards) that do not operate as JSON
  Schema validators.

### Consumer negotiation rule (codified)

```
if major == 0:
    accept only explicitly supported major.minor
else:
    accept same major if minor >= min_supported
    AND all required features present in consumer
```

In words: in `0.x` land, consumers list the exact minors they
support. Post-1.0, consumers declare a minimum minor and accept
anything at or above within the same major.

## Rationale

The prior draft of this policy contained a contradiction: it said
`0.1 → 0.2` was "additive only," *and* it said pre-1.0 bumps "may be
breaking," *and* it said `0.1` consumers could read `0.2` documents.
Those three statements cannot all be true. The dev team flagged the
contradiction; the rule above resolves it by making pre-1.0 minor
bumps explicit compatibility boundaries.

Why this resolution and not a looser one: the six-evidence-layer
schema is structurally rich. Any change to how capabilities are
represented, how Sigstore certificates are embedded, or how Rekor
inclusion proofs are referenced is a structural change. Pretending
those can ship as additive minors in 0.x would mislead consumers.
Treating 0.x minors as compatibility boundaries is honest — and once
the schema stabilizes at 1.0, the industry-standard additive-minor
rule takes over.

The two-field pattern (`$schema` URL plus `aibom.schemaVersion`
string) covers two distinct consumption models: validators resolve
URLs, policy engines read version strings. Neither can do the other's
job efficiently. Having both is the cost of serving both audiences.

## Plain-language summary

A schema is the contract that tells you what shape a document has.
Any tool that reads AIBOM documents — a policy engine, an auditor's
dashboard, a CI pipeline — needs to know whether it can trust the
shape of the document in front of it. That question has to be
answerable from the document alone, not by reading release notes.

The industry answer is semantic versioning: three numbers,
`MAJOR.MINOR.PATCH`.

- **PATCH** bumps fix typos and bugs without changing the shape.
- **MINOR** bumps add new optional fields — old readers keep working.
- **MAJOR** bumps change the shape in ways that break old readers.

Simple enough. But there is a well-known quirk: before version `1.0`,
nothing is truly stable. The community convention is "in `0.x`,
anything might change between minor bumps." That convention is a
warning, not a rule. Reeve makes it a rule. Until we ship `1.0`,
every minor bump (`0.1` to `0.2`, `0.2` to `0.3`) is allowed to break
compatibility. A reader that supports `0.1` should not try to parse a
`0.2` document. Once we hit `1.0`, the normal semver rules kick in
and minor bumps become additive-only.

We carry the version in the document two ways: a URL at the top
called `$schema` that points to the exact schema file, and a plain
string called `aibom.schemaVersion` that policy engines can compare
directly. Two fields because two kinds of tool read them — URL-aware
validators, and everything else.

The URL is **immutable**. Once we publish
`aibom-v0.1.0.json`, those exact bytes never change. If we fix a bug
in the schema, we release `aibom-v0.1.1.json` at a new URL. That way
a validator can cache the schema file forever and never get a
different answer depending on when it happened to fetch the file.
Immutable schema URLs are how JSON Schema reproducibility works
across the whole industry; we are following the norm, not inventing
one.

## Consequences

**This decision commits the project to:**

- Every AIBOM sidecar document carries two version fields:
  `$schema` (URL) and `aibom.schemaVersion` (string). Both are
  required.
- Published schema files are **immutable**. The bytes at
  `https://aibom.example/schemas/aibom-v0.1.0.json` never change once
  published. Any schema-file content change — including patch-level
  bugfixes — produces a new filename and a new URL
  (`aibom-v0.1.1.json` at its own URL).
- Pre-1.0 consumers must declare the exact minor versions they
  support.
- Post-1.0 consumers declare a minimum minor within a major and
  accept anything at or above it.
- Breaking changes in `0.x` are expected to happen on minor bumps,
  not deferred to `1.0`. The schema is allowed to evolve between
  `0.1` and `0.2` without preserving compatibility — but
  compatibility is preserved within a `0.1.x` line (patches only,
  and patches must not change document shape).

**This decision unblocks:**

- Q3 (canonicalization): canonical byte-level form is defined per
  schema version. A `0.1.0` document has one canonicalization
  profile; a future `0.2.0` may adopt a different one.
- Q4 (signature envelope): the version string is part of what gets
  signed.
- Fixture drafting (task #6): fixtures declare
  `aibom.schemaVersion: "0.1.0"` and a placeholder `$schema` URL
  (swapped for the real URL at publication time).

**This decision forecloses:**

- Editing a released schema file in place. Ever.
- Silent breaking changes — every break produces a version digit
  change.
- A single `$schema` URL that evolves over time. URLs are content
  identifiers.

**This decision defers:**

- The production domain for `$schema` URLs. `https://aibom.example/`
  is a placeholder until the project domain is registered (see
  `SECURITY.md` — `security@reeve.dev` is also TBD). The domain
  decision is an ops matter, not a schema matter.
- Long-term-support windows for `0.x` lines. `SECURITY.md` notes
  that formal LTS windows are a 1.0 concern.
- Schema federation — whether v2+ adapter-specific schemas live at
  separate URLs with their own versions, or under a single umbrella
  URL.

## References

- `schema/SPEC.md` §"Design premises" (breaking changes require a version bump)
- `schema/SPEC.md` §"Resolved decisions → Q2"
- ADR-0001 (sidecar is the versioned artifact)
- Semver 2.0.0 specification, and its pre-1.0 note
- JSON Schema Draft 2020-12 (`$schema` keyword semantics)
- CycloneDX `specVersion` field (comparable model: `1.5`, `1.6`)
