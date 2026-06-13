# ADR-0001: Extend CycloneDX via an AIBOM sidecar

- **Status:** Accepted 2026-04-20
- **Decides:** Q1 from `schema/SPEC.md` — CycloneDX extension strategy
- **Related:** `docs/architecture.md`, `docs/positioning.md`, ADR-0002 (schema versioning)

## Context

The AIBOM schema must carry structured evidence that CycloneDX was
not designed to express: declared-versus-observed capabilities,
Sigstore certificate chains, Rekor inclusion proofs, per-policy
verdicts with justifications, adapter and scan metadata. See
`docs/architecture.md` §"Evidence layers in an AIBOM entry" and
`schema/SPEC.md` §"What each entry must encode."

Two non-negotiable premises from `schema/SPEC.md` constrain the
answer:

1. A consumer that speaks only CycloneDX must see a document that
   validates against the CycloneDX 1.5 / 1.6 schema.
2. A consumer that understands the AIBOM namespace must get the full,
   typed evidence — not a workaround.

Three structural options exist for fitting our data alongside
CycloneDX.

## Options considered

### A. Property extension (`component.properties[]`)

Embed all AIBOM fields in CycloneDX's sanctioned name/value extension
array, with namespaced keys like `aibom:capability:declared:0` and
JSON-encoded string values.

- **Pros:** single file; single signature; fully valid CycloneDX
  today; zero standards-body dependency.
- **Cons:** `properties[]` values are **strings**. Structured evidence
  (capability arrays, Sigstore cert chain, Rekor inclusion proof) has
  to be JSON-encoded into a string. Inner objects lose native JSON
  Schema validation — consumers must re-parse each string and
  revalidate. The AIBOM schema effectively cannot enforce structure
  on the evidence it defines. Syft and Trivy use this pattern for
  *flat* key-value metadata (e.g., `syft:location:0:layerID`); no
  major SBOM tool uses it for nested structured evidence, because the
  pattern does not scale.

### B. New component type (`aibom:agent-tool`)

Introduce a CycloneDX `type` value for AI agent tool providers, or
piggyback on CycloneDX 1.6's `machine-learning-model` type.

- **Pros:** semantically precise — a CycloneDX-aware consumer can
  filter for agent tools directly.
- **Cons:** the CycloneDX `type` field is a **closed enum** in the
  JSON Schema. Inventing `aibom:agent-tool` produces a document that
  fails CycloneDX validation. `machine-learning-model` was designed
  for model provenance — it does not express protocol-adapter
  metadata, capability deltas, or sandbox evidence.
  `schema/SPEC.md` §"Design premises" already rules the `ml-model`
  shortcut out. Adding a new enum value requires action by the
  CycloneDX Technical Committee — a process measured in months at
  minimum, which would block v1 on a body Reeve does not control.

An earlier review recommended this option. It was reviewed and
rejected once the closed-enum constraint was identified.

### C. Sidecar AIBOM referenced from CycloneDX *(chosen)*

Produce a CycloneDX document that carries only the fields CycloneDX
was designed for (package identity: name, version, hash, publisher).
In parallel produce an `aibom-<uuid>.json` document validated against
Reeve's own JSON Schema. The CycloneDX document links to the sidecar
via `externalReferences[]` with `type: "bom"` and a content hash.

- **Pros:** full schema control on the AIBOM side (JSON Schema
  Draft 2020-12, closed objects, nested types). Consumer A
  (CycloneDX-only) sees a valid CycloneDX document plus an opaque
  external reference — exactly the "protocol-agnostic at the top
  level" premise. Consumer B (AIBOM-aware) dereferences, validates,
  gets structured evidence. **Precedent:** CycloneDX VEX is
  distributed as a separate document referenced via
  `externalReferences[]` — the pattern is already implemented by
  auditors, CI tooling, and SBOM consumers. **Forward-compatible:**
  if the CycloneDX TC later adopts an AIBOM component type (build-
  order step 5), migration is a refactor to inline the sidecar
  fields; the sidecar path does not foreclose that future.
- **Cons:** two files to keep in sync. Real cost, bounded by the hash
  lock in `externalReferences[]` — tampering is detectable. Consumers
  must dereference one extra file to see evidence.

## Decision

**AIBOM extension strategy is a CycloneDX sidecar.** The CycloneDX
document remains valid and minimal: it identifies the package or
component and references the AIBOM sidecar via `externalReferences[]`
with a content hash. The AIBOM sidecar carries typed evidence, policy
verdicts, scan metadata, and provenance references.

**Sub-choice:** one sidecar per scan, not one per component. Better
signing (one artifact), fewer files, easier fixture generation,
simpler verifier UX. Component-level anchors inside the sidecar map
evidence back to CycloneDX `bom-ref` values.

## Rationale

Only option C preserves both `schema/SPEC.md` premises simultaneously.

- Option A preserves premise 1 (valid CycloneDX) but violates the
  spirit of premise 2: evidence is technically present but not
  structurally first-class. Downstream tools would need custom parse
  logic for every evidence field — which defeats the project thesis
  that a citeable schema is the product.
- Option B violates premise 1 today (invalid CycloneDX) and depends
  on a standards committee the project does not control. Ship-
  blocking.
- Option C honors both and matches an existing industry pattern
  (VEX).

Secondary rationale: the project thesis (`docs/positioning.md`) is
that Reeve's schema becomes the format other tools cite. A citeable
schema must be a real, validatable artifact — not a string-soup
extension inside another format. The sidecar is a real artifact.

## Plain-language summary

CycloneDX is a format the security industry already uses to list
"what is inside this piece of software" — a receipt for every
package, version, and checksum. Our receipt is for AI agent tools and
needs extra information CycloneDX was never designed to carry.

There are three ways to fit our extra information in.

**One: scribble in the margins.** CycloneDX has a little notes
section that accepts free-text key-value pairs. We could cram
everything in there. The problem is that the notes section only
accepts plain strings. Our information has real structure — nested
lists, cryptographic certificates, digital proofs. To use the margins
we would have to take that structure, squash it into text, and paste
it in as a string. Anyone reading it would then have to un-squash it
themselves. It is like emailing a spreadsheet by pasting the CSV into
the body of the email. Technically it works. In practice it is
miserable, and the schema cannot meaningfully enforce shape on
string-encoded data.

**Two: invent a new product category.** CycloneDX has a fixed list of
thing-types — applications, libraries, containers, and so on. We
could say "we are adding a new type: agent-tool." The problem is that
the list is actually fixed. Adding to it requires formal approval
from the CycloneDX standards committee, a process measured in months
or years. An earlier review of this option leaned toward it; once the
closed-list constraint was visible, it stopped being viable for a
tool we need to ship soon.

**Three: two receipts stapled together.** We produce a normal
CycloneDX receipt (basic package info only — the thing it was
designed for). Alongside it we produce our own receipt in our own
format, with all the evidence. The CycloneDX receipt contains a line
saying "see also: our-receipt.json, and here is its hash so you can
detect tampering." A consumer who only reads CycloneDX reads the
first receipt, sees a valid document, and is satisfied. A consumer
who understands us reads both and gets the full picture.

We chose option three. It is already how the industry handles this
problem — CycloneDX's own vulnerability-disclosure companion (called
VEX) works exactly this way. It preserves our freedom to design the
schema properly, it does not depend on a standards committee, and if
we eventually do get our format adopted upstream, migrating off the
sidecar is straightforward.

The cost is real but small: two files instead of one, consumers need
to open the second file to see the interesting data, and a content
hash in the first file detects tampering of the second.

## Consequences

**This decision commits the project to:**

- Every `aibom scan` produces **two artifacts**: a CycloneDX 1.5 /
  1.6 document and an AIBOM sidecar document.
- The CycloneDX document carries only identity fields CycloneDX was
  designed for (package source, name, version, hashes, publisher).
  Nothing AIBOM-specific lives in the CycloneDX document itself.
- Each CycloneDX `component` (or the BOM root) carries an
  `externalReferences[]` entry with `type: "bom"`, a URL or relative
  path to the sidecar, and a content hash.
- The AIBOM sidecar is a standalone JSON document validated against
  Reeve's JSON Schema. It carries the six evidence layers plus policy
  verdicts and scan metadata.
- Inside the sidecar, each evidence entry references its corresponding
  CycloneDX component by `bom-ref`, keeping the two documents
  cross-referenceable.
- Signing covers both artifacts (mechanism decided in ADR-0004 when
  Q4 is resolved).

**This decision unblocks:**

- Q2 (schema versioning): the versioned artifact is the sidecar, not
  the CycloneDX document.
- Q3 (canonicalization): canonical bytes are defined per artifact —
  separately for CycloneDX and sidecar.
- Q4 (signature envelope): the signing layer can cover both artifacts
  in one statement.
- Q5 (capability taxonomy): capability fields live in the sidecar
  schema; no CycloneDX compatibility pressure on taxonomy choice.

**This decision forecloses:**

- A single-artifact AIBOM distributed as-if-it-were-CycloneDX. There
  are always two artifacts.
- Runtime extensions of CycloneDX `type` values — Reeve will not
  author non-standard component types.

**This decision defers:**

- Upstream adoption of an AIBOM component type by the CycloneDX
  Technical Committee (build-order step 5). If accepted, a future
  major schema version may inline sidecar fields; ADR-0001 would be
  superseded at that point.

## References

- `schema/SPEC.md` §"Design premises" (top-level protocol-agnosticism)
- `schema/SPEC.md` §"Resolved decisions → Q1"
- `docs/architecture.md` §"The three layers", §"Evidence layers in an AIBOM entry"
- `docs/positioning.md` §"The SBOM analogy"
- `docs/build-order.md` §"1. AIBOM schema spec"
- CycloneDX v1.5 specification, §"External References"
- CycloneDX VEX pattern (referenced via `externalReferences[]` with `type: "bom"`)
