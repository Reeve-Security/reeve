# V1 Build Order

Reeve's v1 is built **schema-first**. The data model is the product;
the CLI is the reference implementation that proves the schema can
be populated from one collector (MCP).

## Why schema-first

SPDX and CycloneDX succeeded because they standardized the data
model first. The tools came after. Syft and Trivy dominate their
category not because of their collectors — plenty of scanners
exist — but because they emit CycloneDX output that the rest of the
ecosystem trusts and consumes.

No comparable format exists for AI agent tool inventory. CycloneDX
1.6 added a thin `ml-model` component type, but it covers model
provenance — not tool inventory, not capability attestation, not
protocol metadata. That is the opening.

If Reeve's schema becomes what the industry cites, every downstream
tool — CI pipelines, policy engines, dashboards, auditors —
consumes Reeve's format. That is the network effect a competing
scanner cannot easily replicate.

## The five build steps

### 1. AIBOM schema spec *(in progress)*

Formal JSON Schema extending CycloneDX 1.5 / 1.6. Versioned.
Published in `schema/`. First artifact, before any Rust code.

Deliverables:

- `schema/aibom-v0.1.0.json` — formal JSON Schema.
- `schema/SPEC.md` — human-readable specification.
- `schema/examples/` — example AIBOM documents validated against
  the schema.

### 2. Evidence pipeline

For each entry the pipeline resolves: package → cryptographic hash →
Sigstore signature verification → Rekor log lookup → optional MCP
handshake introspection (explicit opt-in) → optional sandbox profile →
schema-compliant AIBOM entry.

### 3. Default policies and compliance mappings

Ten Rego policies covering the most common AI supply-chain failure
modes (see `policies/README.md`). Mapping tables translate policy
verdicts into framework controls — **NIST AI RMF** and **EU AI Act
Article 52** ship with v1; SOC 2, FedRAMP, and ISO 42001 follow in
v1.x.

### 4. CLI as reference implementation

Four subcommands per the v1 spec:

- `aibom scan`
- `aibom verify`
- `aibom policy check`
- `aibom diff`

Output formats: CycloneDX 1.5 / 1.6 JSON, a human-readable table,
and SARIF for CI integration.

### 5. Evangelism

Blog post. Hacker News launch. BSides / DEF CON talks. Pull request
to CycloneDX upstream for a formal `aibom` namespace. Outreach to
MCP server maintainers recommending they publish signed AIBOMs
alongside their releases.

## What v1 explicitly does not include

See `docs/v1-spec.md` for the full non-goals list. In short: no
runtime enforcement, no hosted dashboard, no adapters beyond MCP,
no Windows sandbox support, no SPDX output, no model-weight
provenance, no training-data lineage. Each of those belongs to a
later version, and the three-layer architecture exists so they can
be added without rewriting what ships in v1.
