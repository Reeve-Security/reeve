# ADR-0003: AIBOM sidecar canonicalization is RFC 8785 JCS plus deterministic array ordering

- **Status:** Accepted 2026-04-21
- **Decides:** Q3 from `schema/SPEC.md` — canonicalization profile
- **Related:** ADR-0001 (sidecar is hash-linked from CycloneDX); ADR-0002 (sidecar is a versioned artifact); ADR-0004 (signature envelope — pending)

## Context

ADR-0001 commits the project to distributing AIBOM sidecar documents
alongside a minimal CycloneDX document, hash-linked via
`externalReferences[]`. ADR-0002 commits the sidecar to being a
versioned artifact with immutable schema URLs.

Two operations over the sidecar require byte-reproducibility:

1. **Hash-linking.** The CycloneDX `externalReferences[].hashes[]`
   entry must match the hash a consumer computes after fetching the
   sidecar. Two emitters producing semantically-equivalent sidecars
   must produce identical bytes, or the hash lock fails.
2. **Signature verification.** Whatever envelope Q4 picks, the signed
   artifact ultimately covers a specific byte sequence. Consumers
   re-verifying that signature must be able to reconstruct those
   bytes.

JSON per RFC 8259 permits multiple byte encodings of the same logical
document (key order, whitespace, number format, unicode escapes). Q3
selects the rule that collapses all valid encodings to one.

## Options considered

### A. RFC 8785 JCS (JSON Canonicalization Scheme) *(chosen)*

IETF standard. Rules: lexicographic UTF-16 code-unit object key
ordering; no insignificant whitespace; UTF-8 byte output; ES6
number-to-string algorithm for numeric values; strict JSON escape
rules.

- **Pros:** the only standardized canonicalization for JSON.
  Reference implementations in every major language (Rust:
  `serde_jcs`; Go, Python, JavaScript, Java all mature). Already used
  by in-toto statements, Sigstore predicate formats, OpenID 4
  Verifiable Credentials — ecosystems Reeve interoperates with.
  Known edge cases (numeric precision above 2^53, exotic unicode) do
  not affect AIBOM payloads — hashes and UUIDs are strings, not
  numbers; evidence fields are closed enums or well-formed text.
- **Cons:** canonicalizes object keys only; does not sort arrays.
  Requires a supplemental rule for arrays whose semantics are sets
  (see decision text).

### B. Custom canonicalization profile

Define Reeve's own deterministic JSON profile.

- **Pros:** theoretical flexibility.
- **Cons:** perpetual spec maintenance with no external
  implementations. The end result would mirror JCS 95%. Forfeits the
  ecosystem compatibility that motivated schema-first in
  `docs/build-order.md`. No requirement drives it. Rejected.

### C. No document canonicalization; rely on signing envelope to cover opaque bytes

Emit whatever bytes the emitter chooses and let the signing envelope
(DSSE or similar) sign exactly those bytes. Consumers verify against
the same bytes they received.

- **Pros:** simpler at signing time. DSSE is designed to sign opaque
  payloads and does not itself require JSON canonicalization.
- **Cons:** does not solve hash-linking. CycloneDX
  `externalReferences[].hashes[]` is defined as the hash of the
  resource at the referenced URL. Any proxy, registry, or
  pretty-printer that re-serializes the sidecar between emission and
  consumption breaks the hash. Envelope signing is document-integrity
  in transit, not document-reproducibility across emitters or tools.
  Rejected.

## Decision

**AIBOM sidecar canonicalization is RFC 8785 JCS plus deterministic
array ordering for schema-defined unordered collections.** The
CycloneDX-referenced sidecar is distributed in canonical bytes;
pretty-printed JSON is a non-authoritative view.

### Distribution rule

- The sidecar artifact referenced from CycloneDX MUST be **stored and
  distributed** as JCS-canonical JSON bytes.
  `externalReferences[].hashes[]` hashes those exact bytes. No other
  form is the referenced artifact.
- Pretty-printed sidecars MAY be produced for human review, but MUST
  NOT be the artifact referenced by CycloneDX or covered by the
  content hash or signature, unless separately hashed and signed.
  Pretty is a non-authoritative view, not a sibling artifact.

### Array ordering rule

JCS sorts object keys; it does not sort arrays. For arrays whose
semantics are **sets** (membership matters, order does not), emitters
MUST produce elements in deterministic order:

- `capabilities.declared` and `capabilities.observed`: lexicographic
  by capability id.
- Component / evidence entries: by CycloneDX `bom-ref` ascending.
- Vulnerabilities: by `id` ascending, then `source` ascending as
  tiebreaker.
- Policy verdicts: by policy id ascending, then referenced `bom-ref`
  ascending, then verdict stable `id` ascending. Verdicts MUST carry
  a stable `id` field in the schema (required for reproducibility
  when a single policy fires multiple verdicts against the same
  component — e.g., a policy that emits both a deny and a warn with
  different justifications). Defensive fallback when `id` is absent
  (should not occur under schema conformance): tiebreak by `status`
  then by `justification` as a last resort.
- `externalReferences[]`: by `type` ascending, then by URL
  ascending as tiebreaker. The schema **forbids duplicate
  `(type, url)` pairs** within a single document; two references
  with the same type and URL must be merged into one entry at emit
  time, not disambiguated by `comment` or other metadata.
- `hashes[]`: by `alg` ascending, then by `content` as tiebreaker.

Arrays whose semantics are **sequences** (e.g., Fulcio certificate
chains, Rekor inclusion-proof paths) retain their meaningful order.
The schema explicitly marks each array as `set` or `sequence` so
there is no ambiguity.

## Rationale

JCS is the only standardized JSON canonicalization scheme and has
mature implementations in every ecosystem Reeve will touch. AIBOM
payloads do not hit JCS's known edge cases: no floating-point math,
no high-precision decimals, no exotic unicode in evidence fields;
hash values and UUIDs are strings, not numbers. The fit is clean.

The distribution rule exists because CycloneDX
`externalReferences[].hashes[]` is defined as the hash of the
resource at the referenced URL. Any rule that lets the URL serve
pretty-printed JSON while the hash covers JCS bytes would produce a
silent verification failure for generic CycloneDX verifiers.
Canonical bytes must be the artifact, not an internal representation.

The array ordering rule exists because JCS does not sort arrays — it
cannot, since JSON arrays are ordered per RFC 8259. A correct JCS
implementation preserves emitter array order. Two emitters that
discover the same capabilities in a different order would produce
semantically equal but byte-different documents. The schema must
specify ordering for set-semantics arrays to close this gap.

Rejecting Option C (DSSE-only) was principled: DSSE provides envelope
integrity for a payload in flight. It does not solve the problem of
two independent emitters or tools agreeing on what bytes are the
payload in the first place. That is canonicalization's job.

## Plain-language summary

Two computers can produce JSON that looks the same and means the same
thing, but has different bytes. Different key order, different
whitespace, different ways of writing the same number. Cryptography
does not care about meaning — it cares about bytes. Two byte-different
files produce two different hashes, two different signatures.

**Canonicalization** is the rule that says: "before you hash or sign
this document, rearrange it into one true form, so every computer
gets the same bytes."

We chose **JCS (RFC 8785)** — the only standardized way to do this
for JSON. Every language has a library for it. Big names in the
security ecosystem (Sigstore, in-toto, OpenID 4 Verifiable
Credentials) already use it. Its one known wart (weird handling of
very precise numbers) does not touch our data, because our data is
strings, integers, and enums — no floating-point math.

Two tightenings were needed before committing to JCS alone.

**One: canonical bytes are the real artifact.** The first draft of
this decision had a trap. It said "on disk you can keep a
pretty-printed sidecar; the hash always covers the canonical bytes."
Sounds reasonable — humans want to read the file. But CycloneDX's
hash-link rule is "here is a URL, here is the hash of the file at
that URL." If the URL serves pretty JSON, and the hash is over
canonical JSON, every standard CycloneDX verifier says "tampered."
The fix: the file at the URL *is* the canonical bytes. A pretty
version can exist as a separate copy for review, but it is never the
thing being referenced or signed. The canonical bytes are the only
authoritative artifact.

**Two: JCS does not sort arrays — it cannot, because JSON arrays are
ordered in the specification.** But some of our arrays (the set of
capabilities, the set of policy verdicts) have no meaningful order.
If emitter A lists capabilities in alphabetical order and emitter B
lists them in discovery order, JCS canonicalizes the object keys
identically but leaves both arrays in their original order.
Different bytes. Different hashes. The schema must explicitly
specify how to sort each set-array so every emitter arrives at the
same bytes. Sequences that have meaningful order (like a certificate
chain) keep their natural order; the schema tags each array as "set"
or "sequence" so there is no ambiguity.

Together these two rules close the gap between "the document is
semantically correct" and "the document is byte-reproducible."

## Consequences

**This decision commits the project to:**

- Sidecar artifacts are distributed as JCS-canonical UTF-8 bytes.
- CycloneDX `externalReferences[].hashes[]` always hashes those exact
  bytes.
- The schema tags every array field as either `set` (ordering rule
  applies) or `sequence` (natural order preserved).
- Set-semantics arrays use the ordering rules listed in the Decision
  section.
- Rust implementation uses `serde_jcs` (or equivalent JCS serializer)
  for canonical output; pretty output is a derived, non-authoritative
  view produced for review only.

**This decision unblocks:**

- Q4 (signature envelope): the bytes signed are well-defined —
  JCS-canonical sidecar plus canonical/defined CycloneDX bytes — so
  Q4 can pick DSSE, JWS, or CycloneDX native without reopening
  canonicalization.
- Fixture drafting (task #6): fixtures emit JCS-canonical bytes by
  default; any pretty-printed fixture is explicitly a derived copy
  and is not the artifact referenced from a CycloneDX document.

**This decision forecloses:**

- Pretty-printed JSON as the `externalReferences[]` target.
- Emitter-defined array ordering for set-semantics collections.
- Any sidecar canonicalization that depends on the signing envelope
  to provide integrity. Integrity at the hash-link layer is
  canonicalization's job, not Q4's.

**This decision defers:**

- Canonicalization of the CycloneDX document itself. CycloneDX has
  its own signing and hashing story; Q4 will decide whether Reeve
  uses CycloneDX's native container or cross-signs the pair with
  DSSE. Q3 is about the sidecar only.
- Handling of future fields with numeric precision needs. If v2+
  adds such a field, it is encoded as a string to remain inside
  JCS's safe range.

## References

- RFC 8785 — JSON Canonicalization Scheme (JCS)
- RFC 8259 — JSON specification (array ordering is meaningful)
- `serde_jcs` Rust crate
- `schema/SPEC.md` §"Resolved decisions"
- ADR-0001 (externalReferences hash linking)
- ADR-0002 (versioned artifact)
- in-toto Statement specification (JCS usage precedent)
- Sigstore predicate format conventions (JCS usage precedent)
