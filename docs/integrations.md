# Integrating Reeve with existing SBOM and vulnerability infrastructure

Reeve is not a scanner of everything. It is a scanner of **AI agent
tool registration surfaces** — the places where AI assistants like
Claude Desktop, Cursor, Continue, Codex, and Zed are configured with
tool providers. Reeve emits a signed CycloneDX + AIBOM sidecar per
scan. What you do downstream with that output depends on what question
you are trying to answer.

## Blast radius from Reeve output

**The question:** a CVE drops on an open-source package tomorrow. Which
AI agents across my fleet are exposed?

The answer depends on whether the vulnerable package is the top-level
MCP server or one of its transitive dependencies.

### Direct-package blast radius (works from Reeve output alone)

The CycloneDX document Reeve emits contains, per component:

- `purl` — ecosystem + package name + version (e.g.,
  `pkg:npm/@modelcontextprotocol/server-filesystem@2.3.1`)
- `hashes[].content` — sha256 of the installed package bytes
- `publisher` + Sigstore-verified publisher identity (from the
  companion bundle)
- `bom-ref` — scan-local identifier
- the agent / config surface binding (captured in the sidecar's scan
  metadata and per-component references)

Given these fields, an enterprise that aggregates Reeve's CycloneDX
output into a standard SBOM platform (Dependency-Track, Snyk, Wiz,
Orca, JFrog Xray, or a SIEM with SBOM ingest) can answer "which
scans mention `pkg:npm/@modelcontextprotocol/server-filesystem@2.3.1`
at version ≤ X?" in seconds. The CVE-to-purl correlation is a
standard SBOM pipeline operation — those platforms already query
OSV.dev, GHSA, NVD, and other advisory feeds.

**No additional work required from Reeve users. The CycloneDX half of
the output is already in the format those tools expect.**

### Transitive-package blast radius (requires composition)

If the vulnerable package is a transitive dependency — e.g.,
`node-fetch@3.3.1` buried four levels inside a pnpm tree under
`@modelcontextprotocol/server-fetch` — Reeve's v0.1 output does not
list it. Reeve reports the top-level MCP server package; the
transitive tree is not re-enumerated.

**This is a deliberate v0.1 scope boundary.** Reeve is not in the
business of being a second Syft. Enumerating transitive deps across
npm, pnpm, yarn, uv, pip, pipx, Homebrew, Cargo, and Go modules is
the core job of tools like Syft, and the AI-agent-tool inventory
problem is orthogonal.

To compose Reeve's output with existing SBOM tooling for transitive
blast radius:

1. Reeve produces `<scan-id>.cdx.json` + `<scan-id>.aibom.json` +
   `<scan-id>.sigstore.json` (per-scan file triplet).
2. For each component Reeve identifies, run Syft against the
   installed package on disk. Example:

   ```bash
   syft dir:/usr/local/lib/node_modules/@modelcontextprotocol/server-fetch \
       -o cyclonedx-json > server-fetch.syft.cdx.json
   ```

3. Merge Reeve's `cdx.json` with Syft's `cdx.json` by matching on
   `bom-ref`. Any CycloneDX-aware aggregator (Dependency-Track,
   OpenSSF Depsy) does this merge natively when fed multiple BOMs
   for the same application.
4. Let the aggregator's existing vulnerability pipeline (OSV.dev,
   Grype, Snyk scan) handle CVE correlation against the merged graph.

**Result:** full transitive blast-radius coverage, with Reeve doing
what Reeve is specialized for (AI-agent-tool identification + signed
capability evidence) and existing supply-chain tools doing what they
are specialized for (transitive graphs + vuln enrichment).

### Future: optional native dependency graph

Reeve may emit transitive dep graphs natively in a v1.x release if
customer demand shows the composition-with-Syft pattern is too much
friction. That decision is **deferred, not committed**. A future ADR
(post-v1) would cover:

- Which lockfile formats Reeve's adapters parse directly.
- Whether Reeve ships its own lockfile parser, or shells out to Syft
  and embeds Syft's output.
- Schema changes to the AIBOM sidecar or CycloneDX document for
  transitive inclusion.

None of this blocks v1. v1's CycloneDX output is sufficient for
direct-package blast radius out of the box, and composes with
industry-standard tooling for transitive coverage.

## Capability-truth as the unique Reeve contribution

Conventional SBOM tooling answers "what is installed and is it
vulnerable." Reeve answers additional questions those tools cannot:

- **Declared vs. observed capabilities.** What the MCP server's
  self-description claimed it would do (from `tools/list`,
  `resources/list`, `prompts/list`, when introspection execution is
  explicitly enabled) versus what it was observed doing during opt-in
  profiling (syscalls, network connections, file opens). macOS and
  supported Linux hosts use enforcement boundaries; Windows evidence is
  observational only. The delta is a
  first-class finding from Reeve that nothing else produces.
- **Publisher identity as verified fact, not claim.** The AIBOM
  sidecar carries the tool's claimed publisher; the Sigstore bundle
  carries the OIDC-verified identity of whoever signed the evidence.
  Rego policies consume the verified identity, not the claim. (See
  ADR-0004 §"Separation of verified vs. claimed facts".)
- **Capability-addressable policy verdicts.** Each of the eleven
  default policies is written against stable capability ids from
  the ADR-0005 core vocabulary. Downstream systems can subscribe
  to capability-delta alerts the same way they subscribe to CVE
  alerts.

**Plugging Reeve into existing SBOM infra is the expected deployment
pattern, not a workaround.** Reeve is an input to your existing
stack, not a replacement.

## Reference architecture (simplified)

```
┌─────────────────┐
│ Employee laptop │
│ Claude Desktop  │
│ Cursor          │
│ Continue, etc.  │
└────────┬────────┘
         │ `aibom scan`
         ▼
┌─────────────────────────────────────────────────────┐
│ Reeve output (per scan, signed)                     │
│ - <scan-id>.cdx.json                                │
│ - <scan-id>.aibom.json  (capabilities, evidence)    │
│ - <scan-id>.sigstore.json                           │
└─────────────┬───────────────────────────────────────┘
              │
              ├────────────────────────────┐
              ▼                            ▼
  ┌────────────────────┐       ┌──────────────────────┐
  │ SBOM aggregator    │       │ Policy engine / SIEM │
  │ (Dependency-Track, │       │ (consumes capability │
  │ Snyk, Wiz, etc.)   │       │ delta, signed        │
  │ - direct CVE match │       │ publisher identity)  │
  │ - composed with    │       └──────────────────────┘
  │   Syft for         │
  │   transitive       │
  └────────────────────┘
```

## What Reeve does not do (v0.1)

- Enumerate transitive dependency graphs. (Compose with Syft.)
- Query vulnerability feeds. (Let Dependency-Track / Grype do it.)
- Run continuously as a daemon or service. (Scan-on-demand CLI.)
- Monitor running application processes. (APM tooling's job.)
- Watch endpoint kernel events. (EDR tooling's job.)

## What Reeve uniquely does

- Parse AI-agent tool-registration surfaces (Claude Desktop, Cursor,
  Continue, Codex CLI, Zed, VS Code MCP extension configs).
- Sandbox-execute discovered MCP servers and produce a structured
  capability ledger (declared vs. observed) with cryptographic
  evidence.
- Emit a Sigstore-signed CycloneDX + AIBOM sidecar that slots into
  existing SBOM and SIEM pipelines.
- Ship a Rego-compiled-to-WASM policy engine with eleven default
  policies covering capability-creep, transport rules, publisher
  allowlists, and signature requirements.

The moat is AI-agent-tool awareness plus capability truth, not
reinventing dep graphs or vuln feeds.
