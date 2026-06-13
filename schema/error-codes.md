# AIBOM Validator Error Codes

This document is the **authoritative enum** of validator error codes
for the AIBOM schema line (v0.1 through v0.3). Error codes are stable
and additive across schema versions; version-specific behavior is noted
inline. Every `expectedErrorCode` in a fixture manifest MUST
be a value in this enum. Every implementation of the AIBOM validator
(Reeve's own, any third-party port) MUST surface errors using these
exact codes, not raw JSON Schema library error messages, not prose
strings, not free-form identifiers.

Stable error codes are part of the AIBOM public API. Consumers
(dashboards, SIEM queries, automated triage pipelines) bind to them.
Breaking changes to the enum require a schema-version bump.

## Format

All codes are lowercase dotted identifiers with the shape
`<section>.<field>.<violation>`. Sections correspond to the
validator stage that emits the code.

## The enum

### Stage: `schema-validation`

Emitted by the JSON Schema validator when the AIBOM sidecar or the
CycloneDX document fails structural validation.

| Code | Meaning |
|---|---|
| `aibom.version_mismatch` | `$schema` URL and `aibom.schemaVersion` do not both match the version pinned by this schema file. |
| `capability.id.core_unregistered` | Capability `id` looks like a core-namespace id (single-label namespace matching `^[a-z]+:`) but is not in the v0.1 core registry. |
| `capability.id.namespace_reserved` | Capability `id` uses a single-label namespace that is neither the core namespace nor a registered adapter namespace (v0.1 registers only `mcp`). Reverse-DNS namespaces require two or more DNS labels. |
| `capability.qualifiers.key_not_in_allowed_set` | A qualifier key under a core id is not in that id's allowed set. |
| `capability.qualifiers.path_invalid` | A filesystem capability `qualifiers.path` is not valid for the artifact schema version. v0.1/v0.2 require POSIX absolute paths; v0.3 also accepts Windows drive-absolute and UNC paths. |
| `capability.evidence.min_items` | Capability `evidence` array is empty (schema requires `minItems: 1`). |
| `capability.source.array_mismatch` | A capability's `source` field does not match the array it lives in (an entry in `declared[]` has `source: "observed"`, or vice versa). |
| `capability.additional_property` | Capability object carries a property outside the v0.1 allowed set (e.g., `confidence`, which was deferred from v0.1). |
| `cdx.externalReferences.duplicate_type_url` | A CycloneDX component's `externalReferences[]` array contains two or more entries with identical `(type, url)` pairs. |
| `schema.generic_violation` | Any other JSON Schema violation not covered by a specific code above. Reserved; emitters SHOULD map to the specific codes when possible. |

### Stage: `semantic-validation`

Emitted after `schema-validation` passes but before `canonicalization`.
Covers intra-file and cross-file consistency rules that JSON Schema
Draft 2020-12 cannot express (uniqueness of a sub-field across array
items, cross-file references, cross-artifact bindings).

| Code | Meaning |
|---|---|
| `aibom.components.bom_ref_duplicate` | Two entries in `aibom.components[]` share the same `bom-ref`. |
| `aibom.evidence.id_duplicate` | Two entries in `aibom.evidence[]` share the same `id`. |
| `aibom.evidence_ref.dangling_reference` | Any field that declares a reference into the evidence ledger (`capability.evidence[]`, `vulnerabilities[].evidence[]`, `policyVerdicts[].evidence[]`, or `provenance.sigstoreCertRef` / `transparency.inclusionProofRef` when those fields carry an evidence id) points to an id that does not appear in the top-level `aibom.evidence[]` ledger. Harness checks every ledger-ref-carrying field, not only `capability.evidence[]`. |
| `aibom.component.bom_ref_missing_in_cdx` | A sidecar component `bom-ref` does not appear in the companion CycloneDX document's `components[].bom-ref` values. |
| `cdx.externalReferences.url_mismatch` | A CycloneDX `externalReferences[].url` does not resolve to the distributed sidecar filename. Even if the hash is correct, the URL-to-filename binding must match. |

### Stage: `canonicalization`

Emitted by the canonical-bytes check when the AIBOM sidecar file's
bytes do not match its JCS-canonical form (lex key
order, no whitespace, deterministic array ordering, UTF-8 encoding).

| Code | Meaning |
|---|---|
| `canonicalization.byte_drift` | The bytes of `<scan-id>.aibom.json` on disk do not equal the bytes a JCS canonicalizer would produce from the same JSON value. Possible causes: wrong key order, stray whitespace, wrong number formatting, set-semantics array emitted out of deterministic order, duplicate entries that should have been merged per the merging rule. |

### Stage: `hash-match`

Emitted when cross-file hash references disagree with computed hashes.

| Code | Meaning |
|---|---|
| `cdx.externalReferences.hash_mismatch` | A CycloneDX `externalReferences[].hashes[].content` value does not equal the computed sha256 of the canonical bytes of the referenced AIBOM sidecar. |

### Stage: `attestation-shape`

Emitted by the Sigstore bundle structural check. These codes cover
the signed-attestation shape invariants. Full public Sigstore proof
(Fulcio chain, DSSE signature, Rekor inclusion proof, TUF trust root)
is verified with `cosign verify-blob`, outside the AIBOM validator.

| Code | Meaning |
|---|---|
| `attestation.payloadType_mismatch` | DSSE `payloadType` is not exactly `application/vnd.in-toto+json`. |
| `attestation.statement_type_mismatch` | in-toto Statement `_type` is not exactly `https://in-toto.io/Statement/v1`. |
| `attestation.predicateType_mismatch` | in-toto Statement `predicateType` is not exactly the AIBOM predicateType URI for the schema version being verified. |
| `attestation.predicate_schemaVersion_mismatch` | `predicate.schemaVersion` does not match the version of the AIBOM sidecar it covers. |
| `attestation.subject_count` | `subject[]` array length is not exactly 2. |
| `attestation.subject_name_duplicate` | Two or more `subject[]` entries share the same `name`. |
| `attestation.digest_algorithm` | Any subject digest object uses an algorithm other than `sha256`. |
| `attestation.artifactRoles_mismatch` | `predicate.artifactRoles` does not contain exactly one `cyclonedx` role and exactly one `aibom-sidecar` role. |
| `attestation.subject_role_mismatch` | Subject names and `artifactRoles` keys do not form a bijection. |
| `attestation.payload_decode` | `dsseEnvelope.payload` cannot be base64-decoded, or the decoded bytes are not valid JSON. |

### Stage: `crypto-verification`

Emitted by Reeve's opt-in structural Sigstore-bundle pre-screen after
`attestation-shape` passes. This stage checks bundle shape, fixture
rejection, subject/allowlist facts, and Reeve-recorded error flags. It is
disabled by default for the fixture set and enabled via CLI flags or
crypto-specific negative fixtures. Use `cosign verify-blob` for full
Fulcio, DSSE-signature, Rekor, and TUF verification.

| Code | Meaning |
|---|---|
| `crypto.fulcio_chain_untrusted` | Certificate material is missing or marked as fixture/untrusted by Reeve's structural pre-screen. |
| `crypto.oidc_issuer_not_allowed` | OIDC issuer claim is absent from the consumer-configured issuer allowlist. |
| `crypto.oidc_subject_not_allowed` | OIDC subject / SAN claim is absent from the consumer-configured publisher allowlist. |
| `crypto.rekor_inclusion_invalid` | Bundle carries a Reeve-recorded invalid Rekor inclusion flag. |
| `crypto.rekor_time_outside_cert_window` | Bundle carries a Reeve-recorded timestamp-outside-certificate-window flag. |
| `crypto.tuf_metadata_stale_or_invalid` | Bundle carries a Reeve-recorded TUF metadata error flag. |

### Stage: `version-negotiation` (reserved)

Reserved for a future stage that handles version-negotiation failures
the schema-validation stage cannot express. Not populated in v0.1
because version-mismatch is fully caught at schema-validation via
`const` pinning of `$schema` and `aibom.schemaVersion`.

## Validator behavior requirements

A compliant AIBOM validator:

1. Processes fixtures in stages, in the order defined above. A
   failure at stage N aborts processing; later-stage errors are not
   reported for the same fixture.
2. Emits exactly one error code per failed stage (the most specific
   applicable code).
3. For every error, also surfaces a JSON Pointer into the offending
   artifact identifying the violating location. The JSON Pointer is
   the same form used in `manifest.rejectPointer`.
4. MUST NOT leak raw JSON Schema library error strings. Those are
   implementation details; the error code is the API.

## Deprecation policy

Adding a new code in a later v0.x minor version is a compatibility
boundary. Consumers that pin `0.1` MUST be prepared to
receive unrecognized codes from a `0.2` validator without crashing
(treat unknown codes as generic-violation for forward-compat). Codes
are never removed; a retired code's row in this table is marked
"DEPRECATED" and remains for reference.
