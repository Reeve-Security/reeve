# Architecture

Reeve is organized into three independently versioned layers, each
with a single responsibility. Layers communicate only through the
canonical AIBOM schema and the published adapter interface. A structured
event log is reserved as the future observability channel; until it
exists, layers must not add private side channels. This is the property
that lets future versions add new protocol adapters without modifying
v1 code.

## The three layers

### 1. Protocol adapters

Adapters know how to find AI agent tools in a specific ecosystem.
Each adapter is a plugin that implements the `ProtocolAdapter` trait
and produces canonical AIBOM entries. v1 ships exactly one adapter:
MCP (Model Context Protocol). The v1 MCP adapter discovers common
MCP config surfaces first: Claude Desktop, Cursor, Continue, Claude
Code, Codex CLI, Factory, Zed, and VS Code.

An adapter does not read the AIBOM core's state, and does not know
the policy engine exists. Its contract is input (a scan target) →
output (canonical AIBOM entries).

Each adapter implements four operations:

- `discover` — find tool providers the adapter understands in the
  scan target (filesystem, host, cluster).
- `fingerprint` — compute publisher identity, package hashes, and
  transparency-log verification for a provider.
- `introspect` — list the provider's declared capabilities from its
  self-description when execution is explicitly enabled (for MCP, the
  `tools/list`, `resources/list`, `prompts/list` responses). Default
  scans do not execute discovered stdio MCP servers for introspection.
- `profile` — run the provider briefly in an instrumented sandbox
  and record observed behavior: syscalls, file opens, network
  connections, subprocess launches.

### 2. AIBOM core

The core owns the canonical schema, the hash database, signature
verification against Sigstore and Rekor, and the reporting engine.
It is protocol-agnostic. Given an AIBOM entry, the core does not
know which adapter produced it or what transport the entry
describes.

### 3. Policy engine

Policies are written in Rego and compiled to WebAssembly (`opa build
-t wasm`). The engine evaluates the bundle via Wasmtime against
canonical AIBOM entries, producing allow / deny / warn verdicts with
VEX-style justifications.

Release policy bundles are signed with Sigstore. The default bundle is
compiled to WASM and embedded in the CLI at build time. Runtime loading of
externally fetched or customer-provided bundles is post-launch; today's CLI
does not load external policy bundles.

## The load-bearing rule

No layer reads another layer's internal state. All communication
happens through:

1. The canonical AIBOM schema (data interchange).
2. The reserved structured event log (planned observability surface).
3. The published adapter interface (extension).

Any pull request that would violate this rule is rejected. This
constraint is what makes v2 adapters cheap to add and what keeps
Reeve's security surface auditable.

## Traffic-interception boundary

Per [ADR-0022](decisions/0022-config-reader-not-proxy.md), Reeve is
a bounded config reader and on-endpoint profiler, not an MCP traffic
proxy. Adapters discover documented config surfaces, introspect
declared capabilities, and may run bounded local profiling. Reeve
does not route, broker, approve, deny, or intercept live MCP calls.

This boundary also applies to registry reference-data enrichment.
External MCP intelligence may come from public registries, package
metadata, third-party research, and Reeve-operated lab profiling, but it
does not depend on customer traffic uploads.

## Deployment boundary

Release binaries are location-independent. Installing `aibom-cli` in a
managed tools directory, a platform default binary directory, or an MDM
package path does not change discovery. Runtime behavior is controlled
by the scan target, the output directory, and explicit flags, not by
the binary's own path.

Endpoint inventory is profile-relative. To inventory per-user AI agent
surfaces, Reeve must run with visibility into the relevant user profile
or be given an explicit target root that contains those profiles. See
[deployment scenarios](deployment-scenarios.md#binary-placement-and-execution-context)
for fleet deployment patterns and [filesystem scope](scope.md) for the
exact read set.

## Evidence layers in an AIBOM entry

Each AIBOM entry carries six layers of evidence. The schema must
express each layer as a first-class, validatable field group. See
`schema/SPEC.md` for the formal definitions.

1. **Identity.** Package source, name, version, hash. Checked
   against the registry-published hash.
2. **Provenance.** Sigstore certificate and OIDC identity of the
   signer — e.g., "signed by GitHub Actions in
   `modelcontextprotocol/servers`."
3. **Transparency.** Rekor log UUID and inclusion proof — public
   tamper-evident record.
4. **Capabilities.** Declared (from the tool's own schema) versus
   observed (from the sandbox run). The **delta** is a first-class
   finding.
5. **Known vulnerabilities.** CVE / GHSA / OSV identifiers with
   status.
6. **Reputation.** Publisher history and install base. Emerges from
   cross-customer aggregate (v2+); field-space reserved in v1.

Those six layers feed the policy engine, which produces a verdict.
Compliance mappings then roll those verdicts into framework controls
(NIST AI RMF, EU AI Act Article 52, SOC 2, FedRAMP, ISO 42001).
