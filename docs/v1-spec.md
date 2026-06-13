# AIBOM CLI — v1 Specification

*Working title. Real name TBD — see "Naming" below.*

## Purpose

An open-source command-line tool that produces an **AI Bill of Materials (AIBOM)** for a scanned environment, with cryptographic verification, capability introspection, and policy evaluation. v1 ships with the **MCP protocol adapter** as the first supported agent-tool surface. Future versions add adapters for other protocols (OpenAI function-calling, LangChain tools, Google A2A, custom agent frameworks) without modifying v1 code.

## Non-goals for v1 (the scope wall)

Explicitly **not** in v1:

- Runtime enforcement or blocking (deferred to v4).
- Model-weight provenance (v2).
- Training-data lineage (v3).
- Hosted dashboard, multi-tenant web UI, or commercial tier (v5).
- Auto-remediation, IDE plugins, real-time monitoring.
- Conventional SBOM scanning for non-AI code.
- SPDX output (CycloneDX only in v1).
- Adapters for any protocol other than MCP.
- Windows sandbox support (Linux + macOS only in v1).

If a feature doesn't fit cleanly into the three layers below, it belongs in a later version.

## The three layers

1. **Protocol adapters.** Plug-ins that discover tool providers in a target environment and produce canonical AIBOM entries. v1 ships exactly one adapter: MCP.
2. **AIBOM core.** Canonical schema, hash database, signature verification against Sigstore/Rekor, reporting engine. Protocol-agnostic. Does not know which adapter produced an entry.
3. **Policy engine.** WASM-sandboxed rule evaluator. Rules written in Rego (OPA), compiled to WASM, evaluated against AIBOM entries, producing allow/deny/warn decisions with VEX-style justifications.

### Architectural rule (load-bearing)

No layer reads another layer's internal state. Layers communicate **only** through:

- the canonical AIBOM schema (data interchange),
- a reserved structured event log (planned observability surface),
- the published adapter interface (extension).

The event log is not a shipped runtime surface yet. Until it exists, layers must
not add private side channels to compensate.

This is the property that lets v2 add new protocols without touching v1 code. Every pull request against v1 that would violate this rule is rejected.

## Protocol adapter interface (Rust)

```rust
#[async_trait]
pub trait ProtocolAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str;

    async fn discover(&self, target: &Target) -> Result<Vec<ToolProvider>>;
    async fn fingerprint(&self, p: &ToolProvider) -> Result<ProviderIdentity>;
    async fn introspect(&self, p: &ToolProvider) -> Result<Capabilities>;
    async fn profile(&self, p: &ToolProvider, opts: &ProfileOptions) -> Result<BehaviorProfile>;
}

pub enum Transport {
    Stdio(StdioConfig),
    HttpSse(HttpConfig),
    WebSocket(WsConfig),
}
```

- `discover` — finds tool providers the adapter understands in a scan target (filesystem, machine, k8s cluster).
- `fingerprint` — computes publisher identity, package hashes, transparency-log verification.
- `introspect` — lists declared capabilities (the provider's self-description).
- `profile` — runs the provider briefly in an instrumented sandbox to record observed behavior.

`ToolProvider` is opaque to the core; all other types are canonical across adapters. `Transport` is an `enum` so adding a new transport in v1.x is a new variant + compiler-enforced exhaustiveness checking, not a runtime type assertion.

## AIBOM schema (extends CycloneDX 1.5)

One entry per discovered tool provider:

```yaml
- id: aibom:mcp:filesystem@2.3.1
  protocol: mcp
  transport: stdio
  package:
    source: npm
    name: "@modelcontextprotocol/server-filesystem"
    version: 2.3.1
    hashes:
      sha256: <hex>
    sigstore:
      rekor_uuid: <uuid-or-null>
      verified: true
  publisher:
    claimed: "anthropic"
    verified: true
    transparency_ref: <rekor-log-url>
  capabilities:
    declared: [fs:read, fs:write]
    observed: [fs:read, fs:write, net:egress:api.example.com]
  policies:
    - id: no-unexpected-egress
      status: warn
      justification: "observed egress to api.example.com not in declared capabilities"
  last_scanned: 2026-04-20T10:00:00Z
```

Distributed as a paired **CycloneDX 1.5 / 1.6 document + AIBOM sidecar JSON**, linked via CycloneDX `externalReferences[]` with a content hash. The CycloneDX document is valid against the standard schema; the AIBOM sidecar carries the extended evidence fields (capabilities, vulnerabilities, provenance refs, transparency refs, reputation-reserved, policy verdicts, scan metadata). The pair is signed together via a DSSE-wrapped in-toto Statement in a Sigstore bundle. See ADR-0001 (`docs/decisions/0001-cyclonedx-extension-strategy.md`) for the extension-strategy decision and ADR-0004 (`docs/decisions/0004-signature-envelope.md`) for the signing envelope.

## MCP adapter (v1 scope)

**Discover.** Parses config files for Claude Desktop, Claude Cowork local MCPB extension inventory (ADR-0027), Cursor, Continue, Claude Code, Codex CLI, Factory, Zed, VS Code, and Google Antigravity MCP extension settings. Discovery covers primary user-level configs, Store/UWP Claude package-root configs, Cursor per-project MCP configs, Claude Code workspace `.mcp.json` files, and Factory `.factory/mcp.json` configs under the scan target. Resolves `command`/`args` for stdio transport (`npx -y <pkg>`, `uvx <pkg>`, `pipx run <pkg>`, bare binaries). Resolves `url` entries for HTTP/SSE transport.

**Fingerprint.** For stdio: locates the installed package (npm global, pnpm store, uv cache, pipx venv, system path), hashes both the published artifact and the resolved entry point, queries Sigstore Rekor for publisher claims. For HTTP/SSE: captures TLS leaf certificate fingerprint and the `serverInfo` handshake.

**Introspect.** Default scans do not execute discovered stdio MCP
servers. When explicitly enabled, Reeve speaks the MCP handshake; issues
`tools/list`, `resources/list`, `prompts/list`; and derives declared
capabilities from returned schemas (fs, net, exec, subprocess, db).

**Profile.** Launches the stdio server in an OS-constrained profiler (macOS: `sandbox-exec` profile; Linux: Landlock filesystem enforcement + seccomp network denial when supported). Linux still uses `strace` to collect syscall evidence from the enforced run; if kernel enforcement is unavailable, it falls back to an explicitly labeled observational mode and records that warning in profile evidence; see ADR-0009 (`docs/decisions/0009-linux-profile-observational-fallback.md`). Invokes each declared tool once with neutral inputs. Records syscalls, file opens, network connections, subprocess launches. Flags capabilities observed that exceed the declared set.

## Policy engine (v1)

- Policies are Rego files under `./policies/`.
- `opa build -t wasm` compiles them to a single WASM bundle at build/install time. The bundle is signed with Sigstore before distribution.
- CLI evaluates the bundle via **Wasmtime** (Rust-native, Bytecode Alliance reference implementation).
- Policy bundles are signed with Sigstore before distribution.
- Ships with 12 default policies (catalog in `policies/README.md`):
  1. Signature required for stdio servers in production targets.
  2. Publisher allowlist enforcement.
  3. Declared capabilities match observed (no silent capability creep).
  4. Transport allowlist (e.g., block WebSocket in federal profile).
  5. Maximum age since last scan (default 7 days).
  6. No egress to non-declared hosts.
  7. No `exec` or `subprocess` without explicit capability.
  8. Package source is in trusted registry list.
  9. No version downgrade across scans.
  10. No unsigned MCP server when target profile is `strict`.
  11. No unknown extension capability (warn default, deny in `strict`) — appended by ADR-0005 to enforce the namespaced-extension vocabulary.
  12. Risky granted permission — flags high-risk saved approvals from `capabilities.granted[]` (destructive commands, elevation primitives, wildcard subprocess approvals, `curl | sh` install paths, broad filesystem write grants, secret-path read/write). Evaluates persisted approval state; does not claim runtime enforcement. Appended by ADR-0008.

## CLI surface (v1)

```
aibom scan [--target <path|host|k8s>] [--adapters mcp] [-o aibom.json]
aibom verify <aibom.json> [--against sigstore,publisher-allowlist]
aibom policy check <aibom.json> [--policies ./policies]
aibom diff <before.json> <after.json>   # planned — not in v0.2.x
```

Output formats: `--format human` (default), `--format json`,
`--format yaml`. General AIBOM SARIF is planned, not shipped.
Sensitive-data scans can emit a companion SARIF 2.1 file with
`reeve scan --scan-conversation-secrets --sensitive-data-sarif` for CI
annotations.

## Success criteria for v1

- Scans a developer laptop and produces a valid AIBOM in under 60 seconds.
- Detects MCP installations across all eight supported config locations with ≥95% recall against a hand-curated fixture of 50 public MCP servers.
- CycloneDX output validates against the 1.5 schema.
- The 12 default policies catch seeded test failures with zero false negatives on the fixture.
- First-time user can install, scan, and read results in under 5 minutes following the README.
- Published on GitHub with: Rust crate (`Cargo.toml`), CI matrix covering macOS/Linux x86_64 + ARM64, unit + integration tests, README, LICENSE (Apache 2.0 recommended), SECURITY.md, example policies directory, `cargo-dist` or `cargo-binstall` release pipeline for single-binary downloads.

## Scope-creep guard rules

Read these before accepting any proposed feature into v1.

1. Does it fit cleanly into exactly one of: adapter, core, policy engine, CLI surface? If no → defer.
2. Does it require any layer to know another layer's internals? If yes → rejected or redesigned.
3. Is it listed in non-goals above? If yes → automatic defer.
4. Does it require an adapter beyond MCP? → v2 at earliest.
5. Does it perform runtime blocking or real-time enforcement? → v4.

## Engineering choices (first-principles, pushback welcome)

- **Language: Rust.** Picked because (1) memory safety is table stakes for a security tool whose thesis is "scanners are an attack surface," (2) Wasmtime embedding is first-class, (3) it's the only serious option for the future v4 in-process agent embedded in JVM/CLR/Node/Python without a full rewrite, (4) the adapter interface is union-shaped data that Rust's enums/traits express cleanly, and (5) greenfield security OSS is increasingly Rust-native. *Not* picked because of developer familiarity — picked because it's the right tool for this job.
- **WASM runtime: Wasmtime.** Bytecode Alliance reference implementation; industry-leading spec coverage, performance, and Component Model support; used in production by Fastly, Shopify, Fermyon, Cosmonic.
- **Policy language: Rego compiled to WASM.** Rego is OPA's declarative rule language — already understood by the buyer community (Kubernetes, Netflix, federal AppSec). Compiled to WASM so policy bundles are portable, sandboxed, and signable. Preserves the WASM-as-policy-brain thesis from the January docs.
- **CLI framework: `clap`.** Standard Rust CLI library; clean subcommand ergonomics, derive macros, shell completion generation.
- **Serialization: `serde` + `serde_json`.** Standard; handles the CycloneDX 1.5 schema and AIBOM extensions with derive macros.
- **Signing / transparency: `sigstore-rs` where mature; shell out to `cosign` as a bridge where it isn't.** `cosign` is the official Sigstore CLI — trusted, not a hack.
- **Sandbox mechanisms: Landlock + seccomp on Linux and `sandbox-exec` profile on macOS.** OS-native; no external dependency; Windows AppContainer deferred to v1.1. Linux uses `strace` as the evidence collector, not the enforcement boundary; unsupported kernels fall back to explicit observational mode; see ADR-0009.
- **License: Apache 2.0.** Permissive; compatible with most OSS security tooling; doesn't poison a later commercial tier.
- **Distribution: `cargo-dist` for GitHub Release archives and shell installer; release artifacts are Sigstore-signed.** Single-binary download on every supported platform; no runtime dependency on Rust being installed. Homebrew is deferred per ADR-0024.

## Naming

Working title is "AIBOM CLI." Real name should signal the category ("AI Agent Tool Governance" / "AI Supply Chain"), not lock us into MCP. Candidates to workshop: `agentbom`, `toolprov`, `aibom`, `provenant`, `mcptl` (too narrow — avoid).

## Next step

v1 ships on founder conviction plus a public contract-test corpus (see `schema/examples/README.md`). Pre-launch customer-discovery calls are **not** a gate — the operating mode is ship-then-listen, driven by adoption signals, issue reports on the open-source repository, and outbound conversations triggered by the launch surface in build-order step 5 (HN post, BSides / DEF CON talks, direct reach-out to MCP-server maintainers and supply-chain security teams). Telemetry from the launch cycle — install counts, GitHub stars, issue/PR volume, inbound enterprise inquiries — decides whether v1.1 adjusts scope.

Post-launch customer input is a force multiplier, not a ship blocker.
