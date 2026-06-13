# Adapter expansion roadmap

Issue #34 tracks post-v0.1 adapter expansion. This document is the canonical decomposition point for non-MCP adapter work; it does not expand v1 scope.

## Scope wall

v1 ships exactly one protocol adapter: **MCP**. The rows below are v0.2+ planning targets only. No row authorizes runtime enforcement, hosted dashboards, IDE plugins, model-weight provenance, training-data lineage, or non-AI SBOM scanning.

Every future adapter must preserve the three-layer rule:

1. protocol adapter emits canonical AIBOM entries;
2. AIBOM core consumes only schema/event-log/interface outputs;
3. policy engine consumes verified facts and canonical AIBOM data, not adapter internals.

## Expansion classes

| Class | Examples | Discovery model | Trust-model impact | Required decision before code |
| --- | --- | --- | --- | --- |
| Cloud-config adapters | Bedrock Agents, Vertex AI Agent Builder, Azure AI Studio | Cloud API inventory | Requires opt-in network egress and ambient/cloud auth handling | Cloud-config adapter ADR |
| Framework-introspection adapters | LangChain, LlamaIndex, Haystack, AutoGen, CrewAI | Runtime/framework registry or serialized framework config | May require running framework listing APIs or importing project code; high scanner-attack-surface risk | Framework-introspection ADR |
| Vendor-desktop adapters | ChatGPT Desktop, Gemini Desktop, Mistral Le Chat | Bounded filesystem config paths | Similar to MCP surfaces but vendor-specific schema and privacy review | Surface-specific scope update |
| In-house/custom surfaces | Proprietary internal agent stacks | User-supplied bounded paths | Must not become arbitrary filesystem scanner | ADR-0011 + `--surface-config` |

## Prioritized catalog

| Tier | Adapter target | Follow-up issue | Why | Required evidence before implementation | First shippable slice |
| --- | --- | --- | --- | --- | --- |
| 1 | Bedrock Agents | TBD | AWS-native enterprises; large managed-agent surface | ADR for cloud-config auth/egress/hash semantics; captured API response fixtures | Read-only list/get inventory behind explicit cloud flag |
| 1 | LangChain registry | TBD | Most common agent framework in industry | ADR for framework introspection; fixtures for serialized config and runtime registry output | Offline parser for serialized registry/config before process introspection |
| 2 | LlamaIndex tools | TBD | Common adjacent framework; likely shares LangChain patterns | Framework ADR applies; two captured fixtures | Offline serialized-tool registry parser |
| 2 | ChatGPT Desktop | TBD | Broad consumer/SMB footprint | Privacy review of exact filesystem paths; two captured configs | Bounded config parser only |
| 2 | Gemini Desktop | TBD | Google enterprise shops | Privacy review of exact filesystem paths; two captured configs | Bounded config parser only |
| 3 | Vertex AI Agent Builder | TBD | Large-customer demand vector | Cloud ADR applies; GCP auth/egress threat model; fixtures | Explicit cloud inventory command/surface |
| 3 | Azure AI Studio | TBD | Microsoft enterprise shops | Cloud ADR applies; Azure auth/egress threat model; fixtures | Explicit cloud inventory command/surface |
| 4 | AutoGen | TBD | Smaller but relevant multi-agent framework | Framework ADR applies; fixtures | Offline config/parser slice |
| 4 | CrewAI | TBD | Smaller but visible orchestration framework | Framework ADR applies; fixtures | Offline config/parser slice |
| 4 | Haystack | TBD | Smaller enterprise/search-agent footprint | Framework ADR applies; fixtures | Offline config/parser slice |

## Decomposition rules

When one catalog row becomes active, create a dedicated implementation issue with:

- one adapter target only;
- adapter class and scope version;
- exact discovery source (filesystem path, cloud API endpoint, or framework registry call);
- required ADR reference if cloud-config or framework-introspection;
- at least two captured fixtures listed in the issue;
- docs/scope.md update requirement;
- `reeve scope list` registration requirement if it becomes a built-in surface;
- tests that assert externally observable behavior in the same PR.

Do not combine cloud-config and framework-introspection work in one implementation PR. They have different trust models.

## Cloud-config adapter gates

Before the first cloud adapter ships:

1. Write an ADR for opt-in network egress, auth source handling, and API-response hashing.
2. Define how cloud API responses become canonical evidence without leaking secrets.
3. Define failure behavior for missing credentials and rate limits.
4. Add fixtures that do not contain live account IDs, tokens, ARNs, resource IDs, or tenant IDs unless redacted.
5. Ensure policy input separates verified cloud facts from claimed adapter facts.

Cloud scans must be explicit opt-in. Default local scans must stay offline.

## Framework-introspection adapter gates

Before the first framework-introspection adapter ships:

1. Write an ADR for importing/running framework code versus parsing serialized config.
2. Prefer offline serialized config parsing before executing or importing project code.
3. If any framework listing code must run, profile it as untrusted code and document sandbox behavior.
4. Add fixtures for at least two real-world config shapes.
5. Keep adapter output canonical; do not let policy engine read framework internals.

## Vendor-desktop adapter gates

Before adding a vendor-desktop surface:

1. Identify exact config paths and parsed roots.
2. Confirm no chat history, prompt history, local documents, browser data, keychain, or secret store is read.
3. Update `docs/scope.md` and `reeve scope list` in the same PR.
4. Add at least two captured config fixtures.

## Relationship to companion issues

- Issue #57 remains MCP-adapter work, not adapter expansion. Its Windows
  profiling slice follows ADR-0017: explicit observational evidence
  first, AppContainer enforcement later.
- `--surface-config` handles bounded in-house/custom filesystem surfaces per ADR-0011; it is not a substitute for cloud or framework trust-model ADRs.
- Effective-authority evidence (#4) may apply to cloud-hosted agents but should not be mixed into first cloud inventory slice unless the ADR says so.
- This roadmap closes when the catalog is decomposed into dedicated implementation/ADR issues or when Bedrock + LangChain ship.

## Plain-language summary

Do not bolt random adapters onto v1. First split future surfaces by trust model: cloud APIs, framework introspection, vendor desktop files, and custom paths. Cloud and framework adapters need ADRs before code. Vendor desktop adapters can be smaller path-bound work. Every adapter still emits the same AIBOM evidence and stays behind the adapter/core/policy boundary.
