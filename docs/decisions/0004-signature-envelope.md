# ADR-0004: Sign AIBOM + CycloneDX pair as a DSSE-wrapped in-toto Statement in a Sigstore bundle v0.3

- **Status:** Accepted 2026-04-21
- **Decides:** Q4 from `schema/SPEC.md` — signature envelope
- **Related:** ADR-0001 (paired artifacts); ADR-0002 (versioned artifact); ADR-0003 (sidecar canonicalization); ADR-0005 (capability taxonomy — pending)

## Context

ADR-0001 commits the project to producing two artifacts per scan: a
CycloneDX document and an AIBOM sidecar, hash-linked. ADR-0003
commits the sidecar to being distributed as RFC 8785 JCS-canonical
bytes with deterministic array ordering. Q4 decides how those
artifacts are signed, what identity is bound to the signature, how
transparency is enforced, and how a verifier fails closed.

Two properties the envelope must deliver:

1. **Single signing event covers both artifacts.** The pair is the
   authoritative unit (see `docs/positioning.md` §"Audit-ready
   output"); a split-signature scheme where the two files can be
   separated introduces a class of downgrade attacks.
2. **Keyless Sigstore integration.** Long-lived signing keys are an
   operational liability for open-source distribution; modern
   supply-chain tooling converges on Sigstore keyless (short-lived
   Fulcio certs + Rekor transparency log).

## Options considered

### A. DSSE envelope wrapping an in-toto Statement, packaged in a Sigstore bundle v0.3 *(chosen)*

- DSSE (Dead Simple Signing Envelope, `secure-systems-lab/dsse`
  v1.0.2) signs a payload under a strictly defined pre-authentication
  encoding (PAE). The envelope carries `payloadType`, base64-encoded
  `payload`, and one or more signatures.
- The wrapped payload is an **in-toto Statement v1**: a JSON document
  with top-level `subject[]` (array of `{name, digest}` pairs),
  `predicateType` (URI identifying the semantic claim), and
  `predicate` (the claim body).
- The Statement is packaged in a **Sigstore bundle v0.3**
  (`application/vnd.dev.sigstore.bundle.v0.3+json`) along with the
  signer's short-lived Fulcio certificate and a Rekor v2 inclusion
  proof.
- **Pros:** multi-subject native (one Statement covers both
  artifacts); PAE binds the signature to a specific payload type so
  envelopes cannot be cross-substituted; Sigstore keyless is
  first-class; `sigstore-rs` supports bundle creation and
  verification; tooling interop with cosign.
- **Cons:** verifier must implement DSSE PAE plus in-toto Statement
  parsing plus Sigstore bundle plus Rekor inclusion-proof
  verification. All four are well-specified and have mature Rust
  libraries; bounded cost.

### B. Plain JWS (JSON Web Signature) over canonical bytes

- **Cons:** no native multi-subject support — the paired-artifact
  model from ADR-0001 would require either two JWS signatures (double
  verification, possible split attacks) or a bespoke wrapper object
  (reinventing DSSE). JWS has no `payloadType` namespace binding.
  Sigstore treats JWS as second-class; attestations are canonically
  DSSE. Rejected.

### C. CycloneDX native `signature` field (JSF-based)

- **Cons:** JSON Signature Format (JSF) is a pre-JCS draft by Anders
  Rundgren, never ratified, effectively superseded by JCS + JWS/DSSE.
  Few consumers implement it. Covers only the CycloneDX document, not
  the sidecar, requiring a second signing layer and producing the
  worst of both options. No Sigstore keyless integration. No Rekor.
  Rejected.

## Decision

**Reeve signs the CycloneDX + AIBOM sidecar pair using DSSE wrapping
an in-toto Statement, distributed as a Sigstore bundle v0.3.**

### Envelope structure

- **DSSE `payloadType`:** `application/vnd.in-toto+json` (standard;
  this is what Sigstore bundle DSSE requires).
- **DSSE `payload`:** the base64-encoded in-toto Statement v1 bytes
  described below.
- **DSSE PAE:** per DSSE v1.0.2 —
  `"DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload`.

### in-toto Statement shape

One DSSE envelope signs one in-toto Statement. The Statement has two
subjects: the CycloneDX artifact digest and the AIBOM sidecar digest.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "<scan-id>.cdx.json",   "digest": {"sha256": "<hex>"}},
    {"name": "<scan-id>.aibom.json", "digest": {"sha256": "<hex>"}}
  ],
  "predicateType": "https://aibom.example/attestation/aibom/v0.1",
  "predicate": {
    "schemaVersion": "0.1.0",
    "canonicalization": "RFC8785-JCS+aibom-array-order-v0.1",
    "artifactRoles": {
      "<scan-id>.cdx.json": "cyclonedx",
      "<scan-id>.aibom.json": "aibom-sidecar"
    }
  }
}
```

- Subjects belong to the Statement, **not** the predicate.
- The `predicate` body is intentionally minimal. It identifies schema
  version, the canonicalization rule, and which artifact plays which
  role. Scan metadata (adapter identity, scan duration, claimed
  publisher) lives in the AIBOM sidecar, which is itself a signed
  subject. Bundle-layer data (cert, signing time, Rekor proof) lives
  in the Sigstore bundle. No duplication.

**Structural invariants the verifier MUST enforce:**

- `subject` array contains **exactly two** entries.
- Subject `name` values are **unique** within the array.
- Each subject `digest` object uses **`sha256` only** for v0.1; other
  algorithms are rejected until a future schema version adds them.
- `predicate.artifactRoles` contains **exactly two** entries with
  **exactly one** `cyclonedx` role and **exactly one**
  `aibom-sidecar` role.
- The two subject names MUST match the two `artifactRoles` keys
  (same scan-id-derived file names on both sides).

### Subject digests

- **AIBOM sidecar digest** is taken over the ADR-0003
  JCS-canonical bytes. No ambiguity.
- **CycloneDX digest** is taken over the exact distributed
  CycloneDX artifact bytes. Reeve's emitter SHOULD produce
  CycloneDX JSON deterministically (stable key order, no
  insignificant whitespace, stable array order where semantically
  defined), but arbitrary re-serialization of the CycloneDX document
  by an external tool requires re-signing. ADR-0003 does not apply
  to the CycloneDX document; expanding JCS coverage to CycloneDX
  would require defining CycloneDX-specific array ordering and is
  out of Q4 scope.

### Identity binding (keyless Sigstore via Fulcio + OIDC)

- Signing produces a short-lived Fulcio certificate (lifetime ~10
  minutes) with an OIDC SAN encoding the signer's identity.
- **v0.1 OIDC issuer allowlist (Sigstore public-good instance):**
  - `https://token.actions.githubusercontent.com` — GitHub Actions
    (CI-signed release artifacts)
  - `https://accounts.google.com` — interactive developer signing
  - Microsoft / Entra issuers deferred to v1.x (Entra uses per-tenant
    issuer URLs of the form
    `https://login.microsoftonline.com/<tenant-id>/v2.0`; the
    allowlist needs a machine-checkable pattern that v1.x will
    define once enterprise demand is concrete).
  - Self-hosted OIDC issuers (SPIFFE, private Dex) deferred to v1.x.
- **Sigstore trust roots (Fulcio CA, Rekor log key) are obtained
  via Sigstore TUF metadata.** Not hardcoded. Verifiers refresh TUF
  metadata on the Sigstore-recommended cadence.

### Transparency: Rekor REQUIRED for v0.1

Not optional. The keyless Sigstore security model depends on
trusted signing time. A short-lived Fulcio certificate is valuable
only because a verifier can prove "the signature was produced while
the certificate was within its validity window." Rekor (or, in
future, a TSA token; currently Rekor only for v0.1) provides that
proof.

- Rekor version: **Rekor v2** (current). Entry type: `dsse`. The
  older `intoto` entry type was removed in Rekor v2 and is not
  supported.
- The Rekor inclusion proof is bundled in the Sigstore bundle v0.3.
- Verifiers verify the proof offline against the Rekor log root
  retrieved from TUF metadata.

### Bundle version

- **Reeve v0.1 emits Sigstore bundle v0.3**
  (`application/vnd.dev.sigstore.bundle.v0.3+json`).
- **Verifiers MUST support v0.3.**
- Verifiers MAY accept older v0.2 bundles only if the linked
  Sigstore SDK provides that compatibility transparently.
- **Verifiers MUST NOT blindly accept future bundle major or minor
  versions without SDK support** — a new bundle version can carry
  new security-relevant fields whose validation the old verifier
  does not implement.

### Separation of verified vs. claimed facts (Rego policy input)

The Reeve verifier runs before the Rego policy engine. It produces
**verified facts** from the Sigstore bundle and passes them
alongside the AIBOM document to Rego.

Rego input schema for signature-related policies:

```json
{
  "signature": {
    "verified": true,
    "issuer": "<OIDC issuer URL>",
    "subject": "<OIDC SAN / subject claim>",
    "integratedTime": "<Rekor integratedTime, RFC 3339>",
    "bundleVersion": "application/vnd.dev.sigstore.bundle.v0.3+json"
  },
  "aibom": { ...sidecar content... },
  "cyclonedx": { ...cyclonedx content... }
}
```

**Rego policies MUST consume `signature.issuer` / `signature.subject`
for publisher-allowlist checks.** Rego policies MUST NOT trust
`aibom.publisher` or equivalent claimed-data fields for allowlist
decisions. Claimed data is input to display and correlation; verified
data is input to trust.

This separation is the Policy #2 ("Publisher allowlist enforcement")
and Policy #1/#10 ("Signature required") implementation path.

### Detached artifact naming and co-location

Per scan, three files are produced and MUST be co-located:

- `<scan-id>.cdx.json` — CycloneDX document (deterministic bytes).
- `<scan-id>.aibom.json` — AIBOM sidecar (JCS-canonical bytes).
- `<scan-id>.sigstore.json` — Sigstore bundle v0.3 (DSSE-wrapped
  Statement, Fulcio cert, Rekor proof).

The Statement references the first two by filename in `subject[].name`.

### Verifier fail-closed behavior

All five failure modes fail verification by default. No "warn and
continue" in production. `aibom verify` exits non-zero; the policy
engine refuses to evaluate a document whose verification failed.

1. **Missing.** No bundle file present, or bundle not fetchable at
   the co-located path. `aibom verify` returns `FAIL: signature
   missing`.
2. **Stale.** Rekor `integratedTime` outside the Fulcio certificate
   validity window, or older than a consumer-configured max age
   (default: unbounded for release artifacts; configurable for
   scan-time freshness checks — Policy #5 territory). `FAIL:
   signature stale`.
3. **Mismatched.** Any `subject[].digest` in the Statement does not
   equal the digest computed over the corresponding artifact bytes
   (AIBOM sidecar: JCS-canonical; CycloneDX: exact distributed
   bytes). `FAIL: digest mismatch`.
4. **Untrusted identity.** OIDC issuer not in the verifier's
   configured allowlist, OR subject claim not in the consumer's
   publisher allowlist (Policy #2). `FAIL: untrusted signer`.
5. **Invalid statement.** The signed Statement does not conform to
   the structural invariants above. Any of: DSSE `payloadType` is
   not exactly `application/vnd.in-toto+json`; `_type` is not
   exactly `https://in-toto.io/Statement/v1`; `predicateType` is
   not exactly the AIBOM predicateType URI pinned for this schema
   version; `predicate.schemaVersion` does not parse as a supported
   AIBOM schema version; `subject` array length ≠ 2; subject
   `name` values are duplicated; any subject digest algorithm is
   anything other than `sha256`; `predicate.artifactRoles` does not
   contain exactly one `cyclonedx` and one `aibom-sidecar` role;
   subject names do not match the `artifactRoles` keys one-to-one.
   `FAIL: invalid attestation`.

### Override mechanism

`aibom verify --allow-unsigned` and `aibom scan --skip-sign` exist
for local and development scans only. Both MUST:

- Emit a prominent warning to stderr.
- Record the override in the AIBOM sidecar's scan metadata so
  downstream consumers see it.
- Be refused by `aibom policy check` when the target profile is
  `production` or `strict` (enforced by Policy #1 and Policy #10).

## Rationale

A multi-subject Statement eliminates the paired-artifact downgrade
class entirely: if either file's bytes change, the digest mismatch
in the Statement's `subject[]` surfaces it. Single-subject envelopes
(plain JWS, JSF) would allow an attacker to strip the sidecar and
leave a validly-signed CycloneDX stub in place.

DSSE's `payloadType` binding prevents **envelope-format confusion**
— a DSSE envelope cannot be reinterpreted as a JWS or a raw signed
blob, because DSSE PAE hashes the payloadType into the
pre-authentication encoding. This is a property plain JWS lacks.

DSSE `payloadType` does **not** distinguish AIBOM attestations from
other in-toto predicate types (SLSA provenance, VSA, SCAI, custom
predicates). All of them share
`payloadType = application/vnd.in-toto+json`. **Cross-predicate
replay** — presenting a Reeve-signed SLSA provenance statement as
an AIBOM attestation, or vice versa — is prevented by requiring the
verifier to check that the signed in-toto Statement's
`predicateType` exactly equals the AIBOM `predicateType` URI pinned
for the schema version being verified. Failure to perform this
check would undermine the entire type-safety story; it is enforced
as a structural invariant (fail-closed mode 5: invalid attestation).

Sigstore keyless via Fulcio + Rekor is the mature supply-chain
norm. Long-lived signing keys for an open-source distribution are an
operational and security liability — OIDC-bound short-lived certs
plus transparency-log timestamping are the pattern the broader
ecosystem converged on, used by SLSA, GUAC, cosign, and in-toto.

Requiring Rekor (not making it optional) is the only coherent
position. Keyless Sigstore's entire trust model rests on a
transparent, trusted-time record of when the short-lived
certificate was used. Optional Rekor collapses the model to "we had
a cert once"; mandatory Rekor is the actual security posture.

The verified-vs-claimed split for Rego policy input is the
load-bearing integration point between Q4 and the policy engine.
Without it, Policy #2 becomes tautological: "allow if the document
says it's from an allowed publisher," which an attacker can satisfy
by typing the right string into the document. The verifier computes
verified facts from cryptographic evidence; Rego acts on those.

## Plain-language summary

The two files we produce (CycloneDX receipt + AIBOM sidecar) need
to travel with a tamper-evident wrapper. Without a signature, anyone
in the middle can edit the files and no one downstream can tell.

Think of the signing layer as a FedEx package.

**The envelope is DSSE.** It's a standardized wrapper format that
says "the contents haven't been altered since sealing." The same
wrapper format is used across the Sigstore, in-toto, and SLSA
ecosystems, so every security tool Reeve might interoperate with
already knows how to open one. Inside a DSSE envelope there's a
**payloadType** field that says "a standardized in-toto letter is
inside" — this label is fixed (`application/vnd.in-toto+json`) and
never changes. The fact that the letter happens to be about AIBOM
is a separate concern, handled inside the letter itself.

**Inside the envelope is a short in-toto Statement.** The Statement
is a signed letter that says "I vouch for these specific files, and
here are their exact digital fingerprints." Our letter vouches for
two files: the CycloneDX receipt and the AIBOM sidecar. If anyone
changes even one byte of either file, the fingerprint in the letter
no longer matches the file, and verification fails. The letter also
carries a **predicateType**, which is the letter's own heading —
ours reads "this is an AIBOM attestation version 0.1." Two labels,
two layers: the outer **payloadType** label describes the envelope
contents ("an in-toto letter is inside") and is shared by every
in-toto-based attestation on the planet (SLSA provenance, VSA,
SCAI, and many others). The inner **predicateType** is what tells
you whether the letter is about AIBOM or something else. Because
both labels are part of what gets signed, neither can be altered in
transit, but the verifier's job is to check **both**: the outer
label proves the envelope is a valid in-toto attestation at all,
and the inner label proves it is specifically an AIBOM attestation
and not, say, a SLSA provenance statement that happens to have been
signed by the same party. Skipping the inner check would let an
attacker present a SLSA statement where an AIBOM statement was
expected. The verifier requires an exact match on predicateType or
rejects the attestation outright.

**The letter body (predicate) is deliberately minimal.** It does
not copy-paste scan results. It says: what AIBOM schema version, what
canonicalization rule, and which file plays which role (CycloneDX
vs. sidecar). The real scan content — adapter identity, capabilities,
policy verdicts — lives in the AIBOM sidecar itself, which is one of
the two files the letter vouches for. One source of truth per field.
Otherwise updating scan metadata would mean updating two places and
possibly disagreeing with yourself.

**The whole thing ships as a Sigstore bundle.** A bundle is a
single file that packages the DSSE envelope together with the
signer's temporary ID card and a public delivery receipt. One file
containing the signature material, plus trust roots that the
verifier fetches separately via Sigstore's TUF distribution
channel — Fulcio's current root certificates and Rekor's current
log-signing key. The bundle + the current TUF-distributed trust
roots together are what a verifier needs. The current bundle format
is version 0.3 — we emit v0.3 and require verifiers to support
v0.3. Older versions are only accepted via official Sigstore SDK
compatibility; newer versions aren't blindly accepted because a
future version can carry new security-relevant fields an old
verifier won't know how to check.

**The signer's ID card is a short-lived certificate from Fulcio**
(Sigstore's certificate authority). Instead of long-lived private
keys (which get leaked, rotated, and lost), you log in through OIDC
— your GitHub Actions token, Google account, or Microsoft Entra
account — Fulcio confirms the identity with that provider, issues a
cert valid for about ten minutes with your OIDC identity stamped
into it, and you sign with that cert. Then the cert expires.

**The public delivery receipt is a Rekor log entry.** Rekor is a
public append-only log run by Sigstore. When you sign, your
signature plus its digest are written to Rekor and you get back an
inclusion proof. Rekor's value is **trusted signing time** — the log
entry proves "this signature was produced on this date, and the
cert was alive at the time." Without Rekor, a short-lived cert's
signature has no independent timestamp, and the keyless security
model falls apart. That's why Rekor is required, not optional.

**The most important rule: verified facts versus claimed facts.**
Anyone can type `"publisher": "Anthropic"` into a JSON file. That's
a *claim*. Sigstore's OIDC-bound cert says "the entity that signed
this letter authenticated to GitHub as Anthropic's CI." That's
*verified*. Our verifier extracts the verified identity from the
Sigstore bundle and hands it to the Rego policy engine alongside
the document. Rego makes allow/deny decisions on verified data
only. Policy #2 (publisher allowlist) works on the Sigstore
identity, never on the document's own self-description. This is the
difference between a business card someone hands you and a passport
checked by an immigration officer.

**Everything fails closed.** Missing bundle, stale Rekor time,
mismatched digest, untrusted identity, or a malformed / wrong-type
Statement — all five are fail-closed by default, no "best effort"
mode in production. The last one (invalid attestation) is what
catches attempts to substitute a SLSA provenance statement, a
different AIBOM schema version's statement, or a hand-crafted
payload with the wrong shape. Local development has override flags
(`--allow-unsigned`, `--skip-sign`) that production policies
refuse.

## Consequences

**This decision commits the project to:**

- Producing three files per scan: `<scan-id>.cdx.json`,
  `<scan-id>.aibom.json`, `<scan-id>.sigstore.json`, co-located.
- DSSE `payloadType = application/vnd.in-toto+json`.
- in-toto Statement v1 with two subjects (CycloneDX digest, sidecar
  digest).
- `predicateType = https://aibom.example/attestation/aibom/v0.1`
  (domain placeholder until resolved at publication time).
- Minimal predicate body (schemaVersion, canonicalization rule,
  artifactRoles). No scan metadata in the predicate.
- Sidecar digest over JCS-canonical bytes (ADR-0003). CycloneDX
  digest over exact distributed bytes (Reeve emits deterministically
  but ADR-0003 does not apply to CycloneDX).
- Sigstore keyless signing via Fulcio + OIDC.
- Rekor v2 `dsse` inclusion proof, required for v0.1 production.
- Sigstore bundle v0.3 for emit; v0.3 required for verify; older
  via SDK compat only; future not blindly accepted.
- Sigstore trust roots obtained via TUF metadata.
- Verifier produces verified facts (`signature.issuer`,
  `signature.subject`, `signature.integratedTime`) for Rego input.
  Rego consumes verified facts for trust decisions; claimed fields
  (`aibom.publisher`) are display-only for trust purposes.
- Fail-closed on missing / stale / mismatched / untrusted / invalid.
- **Structural invariant validation** (mode 5, "invalid
  attestation"): exact match on DSSE `payloadType`, Statement
  `_type`, and `predicateType` URI; exactly two subjects with
  unique names; digest algorithm `sha256` only; exactly one
  `cyclonedx` + one `aibom-sidecar` role; subject names ↔ role keys
  bijection. This is what prevents cross-predicate replay (e.g., a
  SLSA provenance statement being accepted where an AIBOM
  attestation is expected).
- Override flags for dev use only, refused by production policies.

**This decision unblocks:**

- Q5 (capability taxonomy): Q4 signs whatever JCS bytes the schema
  emits; Q5 can choose closed-vocabulary or freeform without
  reopening Q4.
- Policy #1 and #10 (signature required for strict/production
  profiles): enforcement hooks are defined.
- Policy #2 (publisher allowlist): verified-fact input schema is
  defined.
- Fixture drafting (task #6): fixtures produce the three-file
  layout; bundle fixtures can be generated with `sigstore-rs` or
  `cosign` in keyless mode.

**This decision forecloses:**

- Custom DSSE payloadType for AIBOM. The in-toto payloadType is
  fixed.
- Scan-metadata duplication between predicate and sidecar.
- Single-subject signatures over the paired artifacts.
- Rekor as optional.
- Hardcoded Sigstore trust roots (TUF only).
- Rego policies trusting `aibom.publisher` for trust decisions.

**This decision defers:**

- Private Fulcio / private Rekor deployment (v1.x; SPIFFE
  integration).
- Timestamp Authority (TSA) tokens as an alternative to Rekor for
  trusted time (TSA is a Sigstore roadmap item; v0.1 uses Rekor
  only).
- Offline Rekor log-root caching strategy for air-gapped verifiers
  (implementation detail).
- Signer identity for private-deployment AIBOM emitters
  (enterprise OIDC issuers beyond the public-good allowlist).

## References

- DSSE protocol v1.0.2 — https://github.com/secure-systems-lab/dsse/blob/v1.0.2/protocol.md
- in-toto Statement v1 — https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- Sigstore bundle documentation — https://docs.sigstore.dev/about/bundle/
- Sigstore verification (reference policy) — https://sigstore.github.io/sigstore-python/policy/
- Rekor v2 GA announcement — https://blog.sigstore.dev/rekor-v2-ga/
- ADR-0001 (paired artifacts)
- ADR-0002 (versioned artifact)
- ADR-0003 (sidecar canonicalization)
- `schema/SPEC.md` §"Resolved decisions"
- `policies/README.md` (Policy #1, #2, #10)
