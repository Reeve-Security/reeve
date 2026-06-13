# Reeve

Signed inventory for AI agent tools on employee endpoints.

[![CI](https://github.com/Reeve-Security/reeve/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Reeve-Security/reeve/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/Reeve-Security/reeve?sort=semver)](https://github.com/Reeve-Security/reeve/releases/latest)
[![Signed releases](https://img.shields.io/badge/signed%20releases-Sigstore%2FRekor-2ea44f)](docs/signing.md)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

AI assistants inherit the authority of the user running them: local
files, shells, network paths, saved approvals, and MCP servers wired to
internal systems. Reeve reads the documented AI-tool config paths,
records what is registered, and emits signed evidence your existing
security and compliance tools can verify.

Reeve does not claim an endpoint is safe. It produces evidence:
registered tools, declared capabilities, observed behavior when profiling
is explicitly enabled, saved-approval evidence where supported, policy
verdicts, and Sigstore provenance. Your patching, MDM, GRC, SIEM, and
policy process decide what action to take. See
[`THREAT_MODEL.md`](THREAT_MODEL.md) for the inherited-authority
boundary.

Deploy shape is intentionally boring: a signed CLI binary, scheduled by
the endpoint tooling you already run. Jamf, Intune, Workspace ONE,
Ansible, cron, launchd, or Task Scheduler can push and run it. No
gateway, no proxy, no traffic interception, no hosted account.

## 90-second path

### Install

After the repository is public, use the signed shell installer:

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Reeve-Security/reeve/releases/latest/download/aibom-cli-installer.sh | sh
```

During private pre-launch, GitHub release assets require authenticated
download. See [Current private-repo install](#current-private-repo-install).

### Scan

Default scans read config files only; they do not execute MCP servers.

```bash
aibom-cli scan --target ~ --policy-check --output-dir ./reeve-out
```

Explicit execution is opt-in:

```bash
aibom-cli scan --target ~ \
  --introspect-execute --introspect-execute-yes \
  --profile --profile-yes \
  --policy-check \
  --output-dir ./reeve-out
```

### Verify

Release archives and the shell installer are signed in GitHub Actions.
Download the asset and adjacent `.bundle`, then verify before running:

```bash
cosign verify-blob \
  --bundle "${ASSET}.bundle" \
  --certificate-identity-regexp '^https://github.com/Reeve-Security/reeve/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${ASSET}"
```

Generated scan output is a CycloneDX BOM, an AIBOM sidecar, and a
Sigstore bundle. The fixture corpus in
[`schema/examples/fixtures/`](schema/examples/fixtures/) shows positive
and negative evidence shapes until public demo artifacts land.

## Looking for early adopters

Security, platform, and compliance teams testing AI-agent inventory before
public launch can reply in
[#411](https://github.com/Reeve-Security/reeve/issues/411). We offer free OSS
install support and ask for honest feedback on setup, scan output, policy
findings, and trust signals.

## Status

**v0.3.8 released.** The schema is locked (ADRs Q1–Q5 resolved; see
`docs/decisions/`). The contract-test corpus is published under
`schema/examples/fixtures/` plus per-version fixture directories. The MCP scanner discovers nine
built-in AI assistant MCP surfaces across macOS, Linux, and Windows
config paths, including Claude Cowork local MCPB extension installs, opaque
Cowork approval/cache presence, and named Cowork remote connectors from
plaintext `cowork_plugins` and `rpm/plugin_*` manifests, plus project-scoped config discovery,
sensitive-data SARIF output, customer rule packs, npm dependency inventory
normalization, duplicate risky-grant summary dedupe, CycloneDX 1.5 schema
validation, human-readable report rollups, Claude Desktop/Cowork
macOS and Windows launch-surface coverage, Cursor global/project MCP
discovery, and explicit or signed custom MCP surface configs.
macOS sandbox profiling, Linux Landlock/seccomp profiling, policy
evaluation (Rego → WASM → Wasmtime), signed surface-config bundles,
signed empty-inventory scans, Windows observational profiling under ADR-0017,
and the signed `cargo-dist` release pipeline are implemented. AIBOM
v0.3 adds cross-OS filesystem path qualifiers: POSIX absolute paths,
Windows drive paths, and Windows UNC paths. Windows profiling and
sandbox enforcement remain separate: Windows behavior evidence is
observational only, and AppContainer enforcement remains deferred.
"Reeve" is a working title; the name may change before 1.0.

Launch-facing pillar claims are bounded in
[`docs/pillar-launch-audit.md`](docs/pillar-launch-audit.md). Public
demo, blog, and sales language should stay inside that audit until the
linked follow-up issues close.

## Install

### Current private-repo install

The repository is private during pre-launch. Unauthenticated `curl` downloads from GitHub
release URLs will return `404`; use an authenticated GitHub CLI session instead:

```bash
gh auth login

TAG=<release-tag>
ASSET=aibom-cli-x86_64-unknown-linux-gnu.tar.xz
gh release download "${TAG}" \
  --repo Reeve-Security/reeve \
  --pattern "${ASSET}" \
  --pattern "${ASSET}.bundle"

cosign verify-blob \
  --bundle "${ASSET}.bundle" \
  --certificate-identity-regexp '^https://github.com/Reeve-Security/reeve/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${ASSET}"

tar -xf "${ASSET}"
install -m 0755 "${ASSET%.tar.xz}/aibom-cli" "${HOME}/.local/bin/aibom-cli"
```

Use `aibom-cli-aarch64-apple-darwin.tar.xz`, `aibom-cli-x86_64-apple-darwin.tar.xz`,
or `aibom-cli-aarch64-unknown-linux-gnu.tar.xz` for other platforms.

macOS release archives are Sigstore-signed and verifiable with the
`cosign verify-blob` recipe above. Apple Developer ID signing and
notarization are tracked separately in issue #147 and are not yet wired
into releases. If macOS attaches a quarantine attribute to a verified
download and blocks first run, remove that attribute after verification:

```bash
sudo xattr -d com.apple.quarantine /usr/local/bin/aibom-cli 2>/dev/null || true
```

Windows release artifacts begin with `v0.1.3`; `v0.2.0` adds
observational Windows profiling. The Windows archive supports MCP
config-file discovery for the documented Windows paths in `docs/scope.md`
and records filesystem, network, and process behavior evidence when ETW
collection is available. ADR-0017 keeps that evidence observational
until AppContainer exists, and Windows profiling and sandbox enforcement
remain separate product claims.

```powershell
gh auth login

$TAG = "v0.3.8"
$ASSET = "aibom-cli-x86_64-pc-windows-msvc.zip"
gh release download $TAG `
  --repo Reeve-Security/reeve `
  --pattern $ASSET `
  --pattern "$ASSET.bundle"

cosign verify-blob `
  --bundle "${ASSET}.bundle" `
  --certificate-identity-regexp '^https://github.com/Reeve-Security/reeve/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$' `
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" `
  $ASSET

Expand-Archive $ASSET -DestinationPath .\reeve
.\reeve\aibom-cli.exe --help
```

### Shell installer (Linux / macOS convenience)

Use the signed shell installer when you want a single install command
instead of manually downloading and unpacking the release archive:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Reeve-Security/reeve/releases/latest/download/aibom-cli-installer.sh | sh
```

Or download the archive for your platform from the [latest release](https://github.com/Reeve-Security/reeve/releases).

macOS note: Reeve release artifacts are currently Sigstore-signed but not
Apple Developer ID signed or notarized. Verify the archive with cosign
before installing. If a quarantined browser/Finder download is blocked on
first run, remove the quarantine attribute from the verified binary before
moving it into your `PATH`:

```bash
xattr -d com.apple.quarantine ./aibom-cli
```

Homebrew is not an active v0.1 distribution channel. A tap may be added
later as a convenience wrapper around the signed GitHub Release
artifacts, but GitHub Releases plus Sigstore are the canonical release
path. See [ADR-0024](docs/decisions/0024-release-distribution-strategy.md).

### Verify release artifacts

Release archives and the shell installer are signed in GitHub Actions with Sigstore keyless
OIDC. Download the asset and its adjacent `.bundle` file, then
verify it before running or unpacking:

```bash
TAG=<release-tag>
ASSET=aibom-cli-x86_64-unknown-linux-gnu.tar.xz
BASE="https://github.com/Reeve-Security/reeve/releases/download/${TAG}"

curl -LO "${BASE}/${ASSET}"
curl -LO "${BASE}/${ASSET}.bundle"

cosign verify-blob \
  --bundle "${ASSET}.bundle" \
  --certificate-identity-regexp '^https://github.com/Reeve-Security/reeve/.github/workflows/release.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${ASSET}"
```

The same recipe applies to each signed release archive, `aibom-cli-installer.sh`, the release
source tarball, and `${TAG#v}.wasm` when the pre-built policy bundle is
published as a release artifact.

### Build from source

**Prerequisites:**
- Rust stable ([rustup.rs](https://rustup.rs/))
- OPA (`brew install opa` or [download binary](https://www.openpolicyagent.org/docs/latest/#running-opa))
- **cosign** (only if you intend to use `--sign-mode real` or an independent `cosign verify-blob` proof; see [ADR-0006](docs/decisions/0006-cosign-dependency-strategy.md))

```bash
git clone https://github.com/Reeve-Security/reeve.git
cd reeve
cargo build --release -p aibom-cli
# Binary at target/release/aibom-cli
```

**Signing without cosign:** Reeve supports three signing modes:
- `real` — requires a working `cosign` binary and network access to Fulcio/Rekor.
- `fixture` (default) — produces a deterministic placeholder bundle for tests and offline scans. No cosign needed.
- `auto` — signs with cosign when available; otherwise warns and falls back to fixture mode.

For most local scans and CI inventory runs, `fixture` mode is sufficient. Install `cosign` only when you need verifiable Sigstore signatures on production artifacts.

`--verify-crypto` runs Reeve's structural bundle checks: bundle shape, subject hashes,
allowlist facts, and fixture-bundle rejection. It is not a replacement for public
Fulcio/Rekor verification. For auditor-grade transparency proof, use the
`cosign verify-blob` recipe above against the release artifact or scan bundle.

Security reviewers should read [`docs/scope.md`](docs/scope.md) before approving endpoint use. It lists every MCP config path Reeve reads, the sandbox profiling boundary, and the files Reeve explicitly does not read.
For the inherited-authority threat model and security boundaries, read [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Quick start

```bash
# Run the offline 30-second demo from a clean checkout
make demo

# Scan your default MCP configs and run policies without executing MCP servers
aibom-cli scan --target ~ --policy-check --output-dir ./reeve-out

# Explicitly ask local stdio MCP servers for tools/list, then profile them
aibom-cli scan --target ~ \
  --introspect-execute --introspect-execute-yes \
  --profile --profile-yes \
  --policy-check \
  --output-dir ./reeve-out

# Validate the generated artifacts against the AIBOM schema
aibom-cli validate-artifacts --cdx ./reeve-out/*.cdx.json --aibom ./reeve-out/*.aibom.json --bundle ./reeve-out/*.sigstore*.json

# Render a per-machine report for humans
aibom-cli report --aibom ./reeve-out/*.aibom.json --format html --output ./reeve-out/report.html
aibom-cli report --aibom ./reeve-out/*.aibom.json --format pdf --output ./reeve-out/report.pdf
aibom-cli report --aibom ./reeve-out/*.aibom.json --format json --output ./reeve-out/report.json

# Or validate the 37-fixture contract-test corpus
aibom-cli validate schema/examples/fixtures/
```

## What Reeve is

Reeve is an open-source command-line tool that produces an **AI Bill
of Materials (AIBOM)** for a scanned environment — a cryptographically
verified inventory of every AI agent tool registered on that machine
or cluster, with capability introspection, provenance verification,
and policy evaluation. The target can be a developer workstation, an
HR laptop running Claude Desktop, an accounting endpoint using an
AI spreadsheet workflow, or a managed corporate fleet.

v1 ships with a single protocol adapter: **MCP (Model Context
Protocol)**. Future versions add adapters for OpenAI function calling,
LangChain tools, Google A2A, and cloud-hosted agent surfaces — without
modifying v1 code. See `docs/adapter-roadmap.md` for post-v0.1 adapter expansion gates and trust-model boundaries.

## What Reeve is not

Reeve is not a scanner. Reeve is a **system of record** for the AI
supply chain. It produces evidence — cryptographic identity, Sigstore
provenance, declared versus observed capabilities, policy verdicts.
Your policies decide what is safe. Reeve produces the evidence those
policies consume.

Read `docs/positioning.md` for the long version.

## Repository layout

| Path               | Purpose                                                         |
|--------------------|-----------------------------------------------------------------|
| `docs/`            | Architecture, positioning, product brief, build order, v1 specification. |
| `docs/decisions/`  | Numbered Architecture Decision Records (ADRs Q1–Q5).            |
| `schema/`          | AIBOM JSON Schema + error-code enum + 37 example fixtures.      |
| `policies/`        | Default Rego policy catalog (14 default policies + `00_main` aggregator). |
| `crates/`          | Rust implementation — `aibom-core`, `aibom-validator`, `aibom-scanner`, `aibom-signer`, `aibom-policy`, `aibom-cli`. |
| `tools/lab/`       | Lab-only demo/infra scripts; not part of the shipping CLI.      |

## Documentation

Start with the [docs index](docs/README.md) for grouped links across
architecture, schema behavior, deployment, GTM, ADRs, audits, and
release notes.

## Reading order for new contributors

1. `docs/positioning.md` — what Reeve is for and what it claims.
2. `THREAT_MODEL.md` — inherited-authority threat scenario, security
   boundaries, and what Reeve does not claim.
3. `docs/reeve-product-brief.md` — version-agnostic product overview,
   deployment paths, and sales narrative.
4. `docs/releases/` — per-version capability appendices and release
   verification recipes.
5. `docs/architecture.md` — the three layers and the rule that keeps
   them separable.
6. `docs/build-order.md` — why the schema is built before the code.
7. `docs/v1-spec.md` — the full v1 specification.
8. `schema/SPEC.md` — the schema spec with Q1–Q5 resolution summaries.
9. `docs/decisions/` — ADRs 0001–0005 (full rationale, rejected
   alternatives, plain-language summaries).
10. `schema/examples/README.md` — fixture corpus documentation.
11. `docs/integrations.md` — composing Reeve output with existing SBOM
   / vulnerability tooling (direct vs transitive blast radius).
12. `docs/signing.md` — how Reeve signs its outputs, industry context,
   day-to-day operations, hole-poking prompts.
13. `docs/deployment-scenarios.md` — plain-language walkthroughs at
    three scales (solo user, small team, enterprise) + SBOM platform
    ingestion flow (Snyk example).

## License

Apache 2.0 (see `LICENSE`).
