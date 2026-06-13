# AIBOM Fixtures

## What this directory is (plain English)

Fixtures are **example files that tell you whether code works.** Think
of a crash-test dummy: a specific dummy, a specific scenario, a
specific expected outcome (it should / should not break in a particular
way). Fixtures do the same job for the AIBOM schema.

Each folder here contains an example AIBOM triplet — a CycloneDX
document, an AIBOM sidecar, and a Sigstore bundle placeholder — plus a
`manifest.json` file that says what the example is testing.

Two kinds of fixtures:

- **Positive fixtures (`positive/`)** are example triplets that are
  **supposed to pass** every validation check. If a tool that reads
  AIBOM rejects any of these, that tool has a bug.
- **Negative fixtures (`negative/`)** are example triplets that are
  **supposed to fail** at one specific check. The manifest says which
  check must reject the file. If a tool accepts a negative fixture,
  or rejects it for the wrong reason, that tool has a bug.

**Why this matters for the project.** The AIBOM schema is a public
contract — other tools read it, produce it, and make decisions on it.
Without a published set of examples, a claim like "our schema is
correct" is unverifiable. With this corpus, anyone writing AIBOM-
compatible code runs it against all 41 fixtures and gets a pass/fail
report. SPDX, CycloneDX, in-toto, and SLSA all ship test corpora for
the same reason — it's what makes a schema into a standard rather
than a blog post.

**The 41 fixtures here cover every validation rule** in ADRs 1–5 plus
the crypto-verification error taxonomy from ADR-0004:
sidecar+CycloneDX linkage, schema versioning, canonical bytes +
deterministic array ordering, signed attestation structure, and the
full capability taxonomy (core vocabulary, extension namespaces,
qualifier rules, and policy-verdict structures. Ten are positive,
twenty-four are negative, and seven are policy fixtures.

The rest of this file is the technical reference for test harness
authors.

---

This directory is the **contract-test corpus** for the AIBOM v0.1
schema. It exists to let any implementation — Reeve's own CLI, a
third-party emitter, a downstream consumer — verify that it emits
and accepts AIBOM documents correctly. Fixtures are the shared
ground truth.

## Layout

```
fixtures/
  positive/            # valid triplets; MUST pass every validation stage
    01-minimal-stdio/
    02-network-egress-match/
    ...
    10-capability-merge/
  negative/            # intentionally broken; MUST be rejected at a named stage
    11-invalid-core-looking-id/
    ...
    22-invalid-attestation-digest-alg/
    ...
    28-invalid-canonicalization-byte-drift/
    29-crypto-fulcio-chain-untrusted/
    ...
    34-crypto-tuf-metadata-stale-or-invalid/
```

Each fixture directory contains a `manifest.json` declaring what
the fixture exercises and what result is expected, plus the JSON
artifacts themselves.

## Per-fixture files

### Positive fixtures (10 total)

```
NN-<slug>/
  manifest.json                         # declarative metadata
  <scan-id>.cdx.json                    # CycloneDX 1.5 document (deterministic emit form)
  <scan-id>.aibom.json                  # AIBOM sidecar (JCS-canonical bytes)
  <scan-id>.sigstore.fixture.json       # structural placeholder bundle (see below)
  canonical-bytes.sha256                # sha256 of the aibom.json canonical bytes
```

### Negative fixtures (24 total)

Each negative fixture contains `manifest.json` plus only the
artifacts needed to reproduce the specific rejection it tests.
For example, a fixture that tests "wrong CycloneDX hash" contains
a valid sidecar and a CycloneDX document whose
`externalReferences[].hashes[]` entry does not match the sidecar's
canonical bytes; it does not need a Sigstore bundle.

## `manifest.json` shape

```json
{
  "name": "11-invalid-core-looking-id",
  "kind": "negative",
  "expected": "schema-reject",
  "rejectStage": "schema-validation",
  "expectedErrorCode": "capability.id.core_unregistered",
  "rejectPointer": "/components/0/capabilities/declared/0/id",
  "invariants": ["Q5.aa"],
  "notes": "optional free-text elaboration"
}
```

Fields:

- `name` — fixture directory slug.
- `kind` — `"positive"` | `"negative"`.
- `expected` — `"schema-valid"` | `"schema-reject"` | `"verify-reject"`.
- `rejectStage` (negative only) — `"schema-validation"` |
  `"semantic-validation"` | `"canonicalization"` | `"hash-match"` |
  `"attestation-shape"` | `"crypto-verification"` |
  `"version-negotiation"`.
- `expectedErrorCode` (negative only) — short dotted identifier
  for the specific failure. Implementations may map to their own
  error codes but MUST surface a failure in the specified category.
- `rejectPointer` (negative only) — JSON Pointer into the invalid
  artifact identifying the violating location. Useful for human
  debugging and for cross-implementation test reporting.
- `invariants` — list of invariant codes from the ADR coverage
  matrix (e.g., `"Q5.aa"`). Lets a test harness run "every fixture
  that exercises ADR-0003 array ordering" as a filter.
- `notes` — optional free-text commentary the test harness ignores
  but humans read.

## Stages and expected outcomes

Every positive fixture MUST pass all of these in order:

1. **schema-validation** — `<scan-id>.aibom.json` validates
   against the AIBOM JSON Schema; `<scan-id>.cdx.json` validates
   against CycloneDX 1.5.
2. **semantic-validation** — intra-file and cross-file references
   are consistent: sidecar `bom-ref` values are unique and exist in
   CycloneDX, evidence IDs are unique, every evidence reference
   points at a ledger record, and the CycloneDX sidecar URL matches
   the distributed AIBOM filename.
3. **canonicalization** — the bytes of `<scan-id>.aibom.json`
   match the ADR-0003 JCS-canonical form (lex key order, no
   whitespace, UTF-8; deterministic array ordering for set-
   semantics arrays).
4. **hash-match** — the sha256 in
   `<scan-id>.cdx.json`'s `externalReferences[].hashes[]` equals
   the hash of `<scan-id>.aibom.json`'s canonical bytes.
5. **attestation-shape** — the in-toto Statement inside
   `<scan-id>.sigstore.fixture.json`'s `dsseEnvelope.payload`
   satisfies every structural invariant from ADR-0004 (DSSE
   `payloadType` exactly `application/vnd.in-toto+json`;
   Statement `_type` exactly `https://in-toto.io/Statement/v1`;
   `predicateType` exactly the AIBOM v0.1 URI; `subject[]` length
   2 with unique names; all digests `sha256`; `artifactRoles`
   with exactly one `cyclonedx` + one `aibom-sidecar`; subject
   names match role keys bijectively).

Negative fixtures MUST fail at the stage named in their
`rejectStage` field and MUST pass all prior stages. This is
important: a fixture for "bad hash" must have a valid sidecar and
a valid CycloneDX doc except for the hash; anything else would
mask what's being tested.

## Positive fixtures validate the schema

Positive fixtures are the "yes" corpus. An implementation that
emits AIBOM MUST be able to produce documents byte-equivalent to
the positive fixtures given the same inputs. An implementation
that consumes AIBOM MUST accept every positive fixture.

## Negative fixtures intentionally fail

Negative fixtures are the "no" corpus. An implementation that
emits AIBOM SHOULD never produce a document that matches any
negative fixture. An implementation that consumes AIBOM MUST
reject each negative fixture at the specified `rejectStage` with
an error mapping to the specified `expectedErrorCode`.

## Signature fixtures are structural

Files named `*.sigstore.fixture.json` are **not** real Sigstore
bundles. They are structural placeholders. Their internal
`dsseEnvelope.payload` carries a real in-toto Statement
(base64-encoded, structurally valid), so the attestation-shape
tests exercise real fields. But the surrounding cryptographic
materials (Fulcio certificate bytes, Rekor inclusion proof,
signature) are placeholders marked with `_fixture_note` keys.

**Never rename `*.sigstore.fixture.json` to `*.sigstore.json`.**
The extension is the test harness's signal that cryptographic
verification is out of scope for this fixture. A harness that
encounters `_fixture_note` anywhere in a bundle MUST refuse to
report "cryptographically verified"; at most it reports
"structurally valid placeholder." This prevents fixtures from
accidentally producing false greens when a future keyless
pipeline runs against them.

Crypto-negative fixtures 29-34 use real bundle shape with surgical
fixture markers for Fulcio / OIDC / Rekor / TUF failure modes. They
are deterministic and do not contact Sigstore public-good services.
Live Fulcio / Rekor fixtures are covered by ignored online smoke tests
so offline CI stays deterministic.

## Sensitive-data report fixtures

`sensitive-data-report/` is a separate fixture corpus for ADR-0019's
opt-in conversation/session-store sensitive-data report. These fixtures
do not live under `fixtures/` because they are not AIBOM triplets and do
not pair with CycloneDX sidecars.

Layout:

```
sensitive-data-report/
  positive/
    claude-cowork-pattern-finding.json
    claude-code-metadata-only.json
    codex-app-pattern-finding.json
    codex-cli-pattern-finding.json
    cursor-pattern-finding.json
    metadata-only.json
    pattern-finding.json
    windows-claude-desktop-pattern-finding.json
  negative/
    raw-secret.json
    conversation-content.json
    raw-conversation-content.json
    secret-hash.json
    content-snippet.json
    pattern-scan-missing-rulepack.json
```

Positive fixtures MUST validate against
`schema/sensitive-data-report-v0.1.0.json`. Negative fixtures MUST fail
schema validation. They protect ADR-0019's privacy boundary:
conversation content, raw secret values, surrounding snippets, and
secret hashes are not valid serialized report fields.

`secret-rule-pack/` is a separate fixture corpus for ADR-0021 customer
conversation secret rules:

```
secret-rule-pack/
  positive/
    customer-token.json
  negative/
    missing-version.json
```

Positive fixtures MUST validate against
`schema/secret-rule-pack-v0.1.0.json`. Negative fixtures MUST fail
schema validation. Loader tests cover the additional safe-regex guard.

The positive fixture set now includes the currently supported
conversation-store surface shapes on `main`: Claude Desktop on macOS,
Claude Desktop on Windows, Claude Code, Claude Cowork, Cursor, Codex CLI,
and Codex App.

## Canonical bytes

`<scan-id>.aibom.json` MUST be JCS-canonical per ADR-0003:
lexicographic key order, no insignificant whitespace, UTF-8 byte
output, deterministic array ordering for set-semantics arrays.

`canonical-bytes.sha256` in each positive fixture directory
records the sha256 of the canonical bytes. This lets a CI check
detect any unintended byte drift.

### Fixture generator

Fixtures are regenerated with `schema/examples/tools/regenerate.py`.
The generator is standard-library Python and is the source of truth
for the committed fixture bytes until a Rust generator replaces it.

- Hand edits to `<scan-id>.aibom.json` SHOULD NOT happen. Change
  fixture data in the generator and re-run it so
  `canonical-bytes.sha256`, CycloneDX external-reference hashes,
  and Sigstore fixture Statements are updated together.
- CI SHOULD run the generator and fail if it produces a diff.
- A future Rust fixture generator MAY replace the Python script,
  but must preserve the byte-level outputs or explain each
  intentional fixture change in the same PR.

### Interim hash placeholders

The `externalReferences[].hashes[].content` field in positive
CycloneDX fixtures is the sha256 of the matching aibom.json
canonical bytes. The fixture generator computes these hashes
against the exact bytes of the committed `<scan-id>.aibom.json`
file. CI must verify this hash on every pull request.

## Known gaps (deferred to later fixture additions)

- **Real Sigstore bundles.** Fixtures covering live Fulcio
  certificates, Rekor inclusion proofs, and trust-root
  verification are added once `sigstore-rs` / `cosign` integration
  lands. Until then, the placeholder convention above documents
  the shape the fixtures will take.
- **Q4 verifier crypto failures.** Missing bundle, stale Rekor,
  untrusted OIDC issuer / subject, cert/Rekor time skew — these
  require real bundles to fixturize and are scheduled with the
  Sigstore integration milestone.
- **Q4 Statement-shape variants beyond the three in fixtures
  20–22.** Wrong `_type`, wrong `artifactRoles` count, subject-
  name / role-key mismatch, duplicate subject names — covered by
  verifier unit tests rather than per-file fixtures, since the
  rejection path is identical to fixtures 20–22.
- **Q5 confidence-field rejection under a non-schema-enforced
  relaxation.** Fixture #19 exercises the schema-enforced case;
  a companion fixture exercising a permissive-validator regression
  is possible but not in scope for v0.1.

## Relationship to ADRs

Every fixture targets specific invariants from the five accepted
ADRs. The `invariants` array in each `manifest.json` lists the
ADR clauses exercised. For the full coverage matrix, see the
decision-records index at `../../docs/decisions/`.
