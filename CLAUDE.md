# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project status

**Active v0.3.x Rust workspace; README is authoritative for current release state.** This repository contains the formal AIBOM schema, a contract-test fixture corpus, Rego policies, a Rust workspace, and git history. `Cargo.toml`, `Cargo.lock`, and crates under `crates/` are intentionally present.

Current implemented surfaces include:

- `schema/aibom-v0.1.0.json` and `schema/examples/fixtures/`.
- `policies/` with 14 default Rego policies, the `00_main` aggregator, and tests.
- Rust crates: `aibom-core`, `aibom-validator`, `aibom-scanner`, `aibom-signer`, `aibom-policy`, and `aibom-cli`.
- MCP discovery for Claude Desktop, Cursor, Continue, Claude Code, Codex CLI, Factory, Zed, and VS Code MCP configs.
- macOS sandbox profiling and Wasmtime-backed policy evaluation.

Do not treat the existence of implementation code or release artifacts as permission to expand v1 scope. New work must still follow the schema-first build order, preserve the three-layer architecture, include tests, and avoid speculative adapters or runtime-enforcement features.

Refer to README.md for the authoritative current status.

## What Reeve is

An open-source CLI that produces an AI Bill of Materials (AIBOM): a cryptographically verifiable inventory of AI agent tools, including identity, provenance, declared vs observed capabilities, and policy inputs.

Reeve produces evidence, not safety claims.

## Build order (schema-first)

Schema-first still applies. Implementation exists, but the schema remains the load-bearing artifact.

## Scope discipline

Do not expand v0.1 scope beyond MCP adapter, CLI, evidence pipeline, and minimal policy support required for release-readiness.

## Architecture boundary

Maintain adapter/core/policy separation. No cross-layer leakage.

## Repository boundary

Per ADR-0044, this repository owns the Reeve binary and public
reproducibility primitives only. Keep official MCP registry
fetch/seed/verify/pagination and registry-source consumer behavior here.
Do not add scheduled capture, Supabase writes, generated data
publication, Pages publishing, external write tokens, or private data
pipeline jobs to this repository.

## Development expectations

- Use standard Rust commands (`cargo build`, `cargo test`, `cargo clippy`, `cargo fmt`).
- Add tests for externally observable behavior changes.
- Keep schema, fixtures, and code aligned.

## Immediate priority

Focus on release readiness (`docs/release-readiness.md`) and public
launch cleanliness (`docs/public-launch-cutover.md`):

- end-to-end CLI flow
- reproducible demo
- signing + verification path
- policy evaluation example

Do not prioritize deeper feature work over release-path completion.

## Decision protocol

1. Does it fit cleanly into exactly one of adapter / core / policy engine / CLI? If no → defer.
2. Does it require any layer to know another's internals? If yes → rejected or redesigned.
3. Is it in the non-goals list? If yes → automatic defer.
4. Does it require an adapter beyond MCP? → v2 earliest.
5. Runtime blocking or real-time enforcement? → v4.

**v1 non-goals (do not relax):** runtime enforcement, model-weight provenance, training-data lineage, hosted dashboard, auto-remediation, IDE plugins, SBOM scanning for non-AI code, SPDX output, adapters other than MCP, Windows sandbox support.

## Schema decisions for v0.1.0

Per `schema/SPEC.md` and `docs/decisions/`.

**Resolved (all five v0.1 questions):**

- **Q1 — CycloneDX extension strategy.** AIBOM sidecar + CycloneDX externalReferences link. See ADR-0001.
- **Q2 — Versioning policy.** Semver with 0.x minor = compatibility boundary; immutable `$schema` URLs. See ADR-0002.
- **Q3 — Canonicalization.** RFC 8785 JCS plus deterministic array ordering for set-semantics collections; sidecar distributed in canonical bytes. See ADR-0003.
- **Q4 — Signature envelope.** DSSE-wrapped in-toto Statement (two subjects: CDX + sidecar) in Sigstore bundle v0.3; keyless Fulcio + OIDC; Rekor v2 required. Verified-vs-claimed fact separation for Rego input. See ADR-0004.
- **Q5 — Capability taxonomy.** Closed core (8 ids) + namespaced extensions (`mcp` registered, reverse-DNS open, single-label reserved). Structured capability objects with required evidence. Adds Policy #11. See ADR-0005.

**Open:** None. All v0.1 schema design questions are resolved. The JSON Schema and fixture corpus now exist. Treat schema changes as compatibility-sensitive contract changes: update `schema/SPEC.md`, fixtures, error-code documentation, and validator behavior together.

## Tech stack (decisions, not suggestions)

These were chosen deliberately in `docs/v1-spec.md` §Engineering choices. Do not substitute without explicit discussion.

- **Language: Rust.** Memory safety is table stakes for a security tool whose thesis is "scanners are an attack surface." Also: first-class Wasmtime embedding, clean expression of the union-shaped adapter interface, viable for the future v4 embedded-agent scenario.
- **WASM runtime: Wasmtime.** Bytecode Alliance reference implementation.
- **Policy: Rego compiled to WASM.** Rego is already understood by the buyer community (Kubernetes, federal AppSec); WASM compilation makes bundles portable, sandboxed, and signable. Runtime loading of external customer policy bundles is post-launch; today's CLI embeds the signed default bundle at build time.
- **CLI: `clap`. Serialization: `serde` / `serde_json`.**
- **Signing / transparency: `sigstore-rs` where mature; shell out to `cosign` where it isn't.** `cosign` is the official Sigstore CLI — a bridge, not a hack.
- **Sandbox: Landlock + seccomp on Linux (via `rust-landlock`); `sandbox-exec` profile on macOS.** Windows AppContainer is v1.1.
- **License: Apache 2.0.** Permissive; compatible with most OSS security tooling.
- **Distribution: `cargo-dist` for GitHub Release archives + shell installer; release artifacts are Sigstore-signed.** Homebrew is deferred per ADR-0024. Apple Developer ID signing/notarization is tracked in issue #147 and is not a launch blocker unless explicitly re-promoted.

## Security thesis (informs every design choice)

Scanners are an attack surface. Reeve's own supply-chain integrity — signed release binaries, source tarball hashes, build provenance — is in scope for its security policy (see `SECURITY.md`). Sandbox escape during capability profiling, signature-verification bypass, and policy-engine verdict misreporting are all in-scope vulnerabilities. When making implementation decisions later, prefer boring, auditable choices over clever ones.

## Repository layout

| Path               | Purpose                                                                |
|--------------------|------------------------------------------------------------------------|
| `docs/`            | `positioning.md`, `architecture.md`, `build-order.md`, `v1-spec.md`.   |
| `docs/decisions/`  | Numbered ADRs (Architecture Decision Records). Canonical why-we-chose. |
| `schema/`          | AIBOM JSON Schema, human spec, error codes, and fixture corpus.         |
| `policies/`        | Default Rego policy catalog, policy modules, and policy tests.         |
| `crates/`          | Rust workspace for core, validator, scanner, signer, policy, and CLI.  |

Recommended reading order for anyone new (from the README): `docs/positioning.md` → `docs/architecture.md` → `docs/build-order.md` → `docs/v1-spec.md` → `schema/SPEC.md` → `docs/decisions/`.

## Decision-recording protocol (load-bearing)

Every design or architectural decision gets a numbered ADR in `docs/decisions/` written **in parallel with the decision, not retroactively**. Template and workflow in `docs/decisions/README.md`. Every ADR must include a plain-language summary so decisions can be explained to non-experts (team, customers, auditors) without reconstructing reasoning from memory. Update `schema/SPEC.md` and other specs to reference the ADR rather than duplicating rationale inline. This is a standing project rule.

## Test-coverage protocol (load-bearing, post-task-#24)

Every new feature ships with at least one test that asserts its externally-observable behavior, **in the same commit as the feature**. No "tests will come later." Applies to CLI subcommands (integration test that runs the command + asserts on output), Rust crate public APIs (test per feature-gating function), schema changes (fixtures positive + negative), Rego policies (`opa test` unit + full-stack fixture), sandbox profile changes (rigged-target exercise), discovery parsers (≥2 captured config fixtures per surface). Manual dev-laptop verification does not count. CI enforces: `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, fixture-regenerator idempotency diff. Red CI blocks merge.

## Build / test / run

The Rust workspace is active. Standard checks:

- `cargo fmt --check`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace`
- `cargo test <name>` for a focused Rust test
- Fixture-regenerator idempotency check via the existing validator test suite

Policy compilation uses `opa build -t wasm -o bundle.wasm policies/` when regenerating policy bundles.

## Current delivery discipline

`docs/v1-spec.md` §Next step now says v1 ships on founder conviction plus the public contract-test corpus. Pre-launch customer discovery is not a gate. Use launch/adoption feedback to adjust v1.1 and later, not to block v0.1 implementation.

Before accepting new work, check whether it advances the remaining v1 build order rather than widening scope. Release pipeline, online signing acceptance, hardening, and documentation are in scope; new protocols, hosted dashboards, IDE plugins, runtime blocking, SPDX output, and Windows sandbox support remain out of scope for v1.

## Public site claim discipline

Public marketing copy may describe only behavior
present on `origin/main` of this repository with at least one passing test
that asserts the externally observable behavior. Strategy documents,
roadmap items, and aspirational scope stay outside this public repository
until code lands.

Demo materials follow the same rule. Videos, screenshots, blog
walkthroughs, demo scripts, and public proof artifacts may claim only
behavior present on `origin/main` with at least one passing test asserting
the externally observable behavior. Cowork surface depth, central corpus
state, and any "Reeve sees X" statement all gate on shipped behavior.

Future service or data-product claims may appear only with explicit
"paid", "coming", or equivalent future-facing qualification and visual
soft-state styling. Do not let roadmap language read as shipped OSS
behavior.

Before pushing site copy, cross-check every product claim against code,
tests, schemas, ADRs, and open/closed issue state. If the test does not
exist on `origin/main`, the public site does not say it.
