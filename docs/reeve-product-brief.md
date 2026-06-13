# Reeve — product brief

*Evergreen overview. Version-specific capabilities, install commands, and verification recipes live in [`docs/releases/`](releases/).*

This document is the version-agnostic reference for what Reeve is, how it works, what it produces, and how it deploys. For the specifics of any given release — what shipped, how to install it, and what verifying its signature looks like — see the per-version appendix in `docs/releases/`.

The current latest release is tracked in [`docs/releases/README.md`](releases/README.md).

---

## 1. What Reeve is

Modern organizations run AI assistants that have grown teeth. Tools like Claude Desktop, Cursor, Continue, VS Code's MCP integration, and Codex CLI all support a plugin architecture called **MCP** (Model Context Protocol). Each MCP server gives the AI new powers: read files, execute commands, hit network endpoints, query databases, manipulate cloud infrastructure. The plugins install via JSON configs in well-known paths on the employee's machine.

The security and compliance question that follows is uncomfortable: **what AI tools are running on every employee laptop and server in your organization, and what are they actually permitted to do?** Today, most teams cannot answer that question with evidence.

Reeve is the inventory and trust layer that produces the answer. It is an open-source command-line tool that scans a machine and produces a cryptographically signed report — an **AIBOM** (AI Bill of Materials) — capturing three things any third party can verify without trusting Reeve:

1. **Inventory** — every AI agent and every MCP server registered on the endpoint, identified, hashed, and signed.
2. **Behavior** — what each tool actually does when profiling is explicitly enabled, captured under the platform boundary available on that OS and compared against what each tool publicly declared it would do.
3. **Authority** — the persistent approvals Reeve knows how to parse for the installed agent versions: `always approve this command for this project`, `always allow this MCP server to read these files`, and similar saved decisions. This is the accumulated approval state an attacker would inherit if they compromised the user.

The third view is the new attack surface that AI agents created. AI agents persist approvals on the endpoint as durable state. When a user is compromised — phishing, malware, stolen session — the attacker can inherit those saved approvals without prompting again. Traditional endpoint tooling does not inventory this surface today; Reeve models it as `granted-permission` evidence where adapter formats are known. Buyer-facing positioning for this is in [`docs/gtm/inherited-authority.md`](gtm/inherited-authority.md).

The target is not only a developer workstation. The same scanner and AIBOM apply to HR laptops using Claude for resume review, accounting endpoints using AI spreadsheet automation, marketing endpoints using image-generation MCP servers, sales endpoints wired to CRM scripts, legal endpoints reviewing documents, and operations laptops running runbook helpers. Reeve is OS-path-driven, not role-driven.

The output is **evidence, not a safety claim**. Your policies decide what is safe; Reeve produces the evidence those policies consume. That distinction is intentional. Security teams already have tooling investments in SBOM platforms, SIEMs, and policy engines. Reeve plugs into the existing trust chain rather than asking customers to migrate to a new dashboard.

---

## 2. The mental model

Reeve is structured as three independent layers. The separation is not aesthetic; it is a hard architectural rule that protects the security properties.

**Adapter layer.** Knows about the world. Each adapter knows the canonical paths where its kind of agent stores configuration, knows how to parse those configs, knows how to enumerate the tools each config registers, and knows how to introspect each tool to learn its declared capabilities. Adapters never reach into the core's internal representation; they emit a normalized data structure across an interface boundary.

**Core layer.** Knows about the schema. It receives the normalized data from adapters, hashes the relevant artifacts, runs optional profiling to compare declared capabilities against observed capabilities, builds the AIBOM document, signs it, and writes the bundle to disk. The core has no knowledge of any specific agent vendor — it operates on the abstract concept of "an agent and its registered tools."

**Policy layer.** Knows about Rego and Wasmtime. It loads the AIBOM as input, evaluates each policy, returns verdicts. Policies operate on the AIBOM's schema; they never touch adapter or core internals.

The reason to keep these strict: when a future adapter arrives (Bedrock, LangChain, Vertex AI Agent Builder), it slots in without forcing changes elsewhere. When a future schema field arrives, the validator and policies update independently. When a customer wants to ship their own policies, they only need to read the schema — they do not need to read any Rust code. This is the single most important property for adoption: the contract is documented and stable.

The discovery process, end to end, on a target machine:

1. Reeve reads the canonical paths listed in [`docs/scope.md`](scope.md) for each adapter installed in the binary.
2. For each MCP server registered in those configs, Reeve hashes the config and the server binary if reachable.
3. Reeve records config-derived MCP identity by default. When the operator explicitly enables introspection execution, Reeve briefly requests `tools/list` to capture the declared capabilities the server advertises.
4. Reeve parses supported **approval-state fields** within agent configuration — `permissions.allow` arrays, command allow-lists, tool grants, project-scoped permission decisions — and emits them as `granted-permission` evidence. This is the inherited-authority surface. Coverage is adapter-specific and documented per release.
5. When profiling is explicitly enabled, Reeve runs the server under the platform boundary documented for that OS, exercises it with synthetic inputs, and captures behavior evidence. macOS and supported Linux hosts use enforcement boundaries; Windows evidence is observational only until AppContainer support lands.
6. Reeve writes a CycloneDX BOM, an AIBOM sidecar, and a Sigstore bundle to the chosen output directory.
7. Optional: Reeve evaluates the bundle against the configured policy set, including risk-flagging policies that surface destructive command approvals, undeclared elevation primitives, and over-broad path grants. The verdicts join the AIBOM as policy evidence.

The whole run is **stateless**. Reeve does not phone home. It does not maintain a persistent index. It does not run as a daemon. Each scan is a one-shot CLI invocation that produces a self-contained, signed report.

The exact sandbox enforcement available depends on the host OS and the Reeve version — see the per-version appendix.

---

## 3. Output formats and integration

Every scan produces three artifacts in the chosen output directory.

**`scan-<timestamp>.cdx.json`** — a CycloneDX 1.6 Bill of Materials. Each MCP server is a CycloneDX `component`. Each tool registered by an MCP server is a child component. CycloneDX consumers (Snyk, Anchore, GitHub's dependency graph, GitLab's vulnerability platform, every SBOM ingestion tool that already exists) read this file and surface the inventory in their existing dashboards. No special integration is required to get the basic "what AI tools are present" view.

**`scan-<timestamp>.aibom.json`** — the AIBOM sidecar. Conformant to `schema/aibom-vN.M.0.json`. Carries the AI-specific evidence: per-tool **declared / observed / granted** capabilities (the three sources defined in ADR-0008), sandbox profile output (denied vs observed syscalls), source labels (`built-in` vs `user-defined`), `granted-permission` evidence records describing each saved approval and which agent surface produced it, provenance hashes, and the policy verdicts when policies were evaluated. The CycloneDX BOM links to this sidecar via `externalReferences` so a CycloneDX-only consumer still gets a pointer to the deeper evidence.

**`scan-<timestamp>.sigstore.json`** — a Sigstore bundle (v0.3). Inside it: a DSSE envelope, an in-toto Statement with two subjects (the CDX BOM hash and the AIBOM sidecar hash), and the Fulcio certificate proving identity, plus the Rekor inclusion proof. Verifying this bundle establishes the entire chain: the artifacts were produced by a known signing context, the artifacts have not been tampered with since, and the inclusion proof is recorded permanently in Rekor's transparency log.

A consumer that wants to verify a release binary uses the public `cosign verify-blob` recipe. The exact certificate-identity regex depends on the release version — see the per-version appendix for the recipe to use.

---

## 4. The boundary story — what Reeve reads, and what it does not

Customers will ask, before approving Reeve on production endpoints, exactly which files Reeve touches. The answer is documented in three artifacts that together give a security reviewer a complete, machine-verifiable answer:

- [`docs/scope.md`](scope.md) — every path Reeve reads, by adapter, by OS.
- `aibom-cli scope list` — prints the static catalog of canonical paths the binary knows about.
- `aibom-cli scan --dry-run` — for the current machine, prints the exact set of files that would be opened on a real scan, before any file is actually opened.

What Reeve reads:

- The canonical configuration paths for the agent stacks supported in this version (per the per-version appendix).
- For each MCP server detected, the path the config points at — typically a binary or a script.
- Supported **approval-state fields** within agent configuration files — `permissions.allow` arrays, command allow-lists, per-MCP-server tool grants, project-scoped permission decisions. Reeve reads these fields and emits them as `granted-permission` evidence where the adapter format is known. Reeve does not modify them.
- During profiling, the server's own subprocess output and the syscalls it issues during a synthetic exercise.
- User-supplied custom-surface configurations passed via `--surface-config <path>` (when supported in the version). These run with a separate, lower-trust label (`source: user-defined`) so policies can be stricter on inventory derived from them.
- A system-wide custom-surface configuration at the documented OS path
  when no explicit `--surface-config` is supplied. This is the MDM /
  endpoint-management path for deployer-owned configuration; `--no-system-config`
  disables it for testing.
- An adjacent `surfaces.yaml.sigstore.json` bundle when present. Reeve
  verifies the deployer signature before applying the config, and
  `--require-signed-config` makes unsigned config fail closed.

What Reeve does **not** read:

- General filesystem state. Reeve does not walk `/`. It does not glob across `~`. The path list is fixed at compile time.
- Source code, documents, browser history, password manager state, mail.
- Secrets in any form. Where a config references a token or API key, Reeve records the reference (location in the file) but never the value.
- Network traffic, process memory, command outputs other than the synthetic profiling exercise.
- Any path outside the scan target's root after symlink canonicalization. Custom surfaces that try to escape via `..` or absolute paths are rejected at the scope-check stage.

`reeve scan --dry-run` prints, for the current machine, the exact files that would be opened, before any file is actually opened. A security reviewer can pipe this output into the approval workflow and bind their authorization to a specific, reviewable list. This is the conversation a CISO needs to have before approving installation on production endpoints, and it can happen entirely on the security team's terms.

---

## 5. The verification chain, in one paragraph

A customer downloads a Reeve binary from `github.com/Reeve-Security/reeve/releases`. They also download the adjacent `.bundle` file and run `cosign verify-blob` with the public certificate identity regex (specific to the release version). The verification succeeds because the binary was built and signed by a GitHub Actions workflow at `repo:Reeve-Security/reeve:.github/workflows/release.yml@refs/tags/<version>` using a Fulcio short-lived OIDC certificate, and the resulting signature was logged to Rekor's transparency log at the time of release. The customer can read that workflow file on GitHub before running the binary, can confirm the workflow runs `cargo-dist` with no opaque steps, and can therefore reach the conclusion that the binary they hold corresponds to the source code they read.

This conclusion does not require trusting Reese Skye LLC. It requires trusting the Sigstore project, the GitHub OIDC issuer, and Rekor's transparency log — all of which are in widespread enterprise use already.

When the customer in turn runs Reeve and produces an AIBOM, the same chain applies one level down: the AIBOM is signed with the customer's own OIDC identity (or with a fixture key in offline mode), the sidecar's hash is the in-toto subject, and any downstream consumer of the AIBOM can verify it against the customer's keys without trusting the customer's word.

This is the property that makes Reeve sellable into security-conscious environments: the evidence chain is verifiable end to end without anyone in the chain having to be trusted on faith.

---

## 6. Deployment paths

Deployment is a first-class property of Reeve, not an afterthought. Reeve installs through the endpoint-management and scheduling channels security and IT teams already operate — Jamf, Intune, Workspace ONE, Ansible, cron, launchd, Task Scheduler — with no proxy to route through, no resident daemon, and no managed sensor. There is nothing to reroute and nothing to uninstall beyond the binary itself. [`docs/positioning.md`](positioning.md#drop-in-deployment) lays this drop-in shape out against gateway- and EDR-class products in a side-by-side table.

The CLI shape is the same everywhere. What changes is who runs it, on what cadence, and where the output goes.

### 6.1 Solo user

A user downloads the signed binary from GitHub Releases, verifies the
adjacent Sigstore bundle, or uses the signed shell installer on macOS /
Linux. They run a one-liner against their home directory:

```bash
aibom-cli scan \
  --target ~ \
  --profile \
  --policy-check \
  --output-dir ~/reeve-out
```

This produces `scan-<timestamp>.cdx.json`, `scan-<timestamp>.aibom.json`, and `scan-<timestamp>.sigstore.json`. The user can inspect the AIBOM, see which MCP servers were detected, see what each one declared versus what it actually tried to do during opt-in profiling, and see which policies failed.

If they care about provenance, they verify the Reeve binary itself before running it using the cosign recipe in the per-version appendix. That recipe binds verification to the GitHub Actions workflow path on the `Reeve-Security/reeve` repository — a user who does not trust Reese Skye can read the workflow source on GitHub and confirm what the workflow does before trusting any binary it produces.

Time to first AIBOM: under five minutes from `curl install` on a working machine.

### 6.2 Small team (5–50 employees)

A platform engineer, IT admin, or security lead ships Reeve as part of the employee-device setup script. The reference paths live under `tools/deploy/curl-install/` and `tools/deploy/ansible/`. The script installs Reeve, drops the signed `surfaces.yaml` bundle, configures it to run on a daily cron/systemd/launchd timer, and uploads each AIBOM to a shared object store — an S3 bucket, a GCS bucket, an Azure Blob container.

A nightly aggregator script (the team writes this; Reeve does not ship a hosted aggregator) walks the shared bucket, extracts inventory across all employee endpoints, and surfaces unusual patterns: unsigned MCP servers, broad filesystem grants, MCP servers that claim read-only but tried to write, or unexpected network egress from a tool installed outside engineering. The aggregator can be as simple as an `awk` script over the AIBOM JSON, or as sophisticated as a Postgres database fed by a small ingest job.

For a 25-person team this is roughly a half day of platform work and zero ongoing maintenance once the cron is in place. Output is queryable, signed, and reproducible. There is no SaaS subscription, no agent sitting in memory, no dashboard to maintain.

Small non-engineering examples look the same operationally:

- A 50-person law firm scans Claude Desktop document-review configs and proves which local document folders the tools can reach.
- A finance team scans AI spreadsheet workflows and flags undeclared network egress.
- A marketing team scans image-generation MCP servers and records which external services are registered.

### 6.3 Enterprise (large org, security and compliance teams)

The deployment posture changes meaningfully here. Three audiences need to be satisfied:

- **Security engineering** wants the inventory, the policy verdicts, and the signed evidence. They get exactly that. AIBOMs flow into the existing SIEM (Splunk, Datadog, Sentinel) or directly into the SBOM platform (Snyk AppRisk, Anchore Enforce, Endor Labs) as CycloneDX BOMs with the AIBOM sidecar referenced via `externalReferences`. Existing SBOM dashboards already show the inventory; Reeve's contribution is the AI-specific evidence inside the sidecar.
- **Endpoint management** distributes Reeve as a managed package via Jamf on macOS, Intune on Windows, Workspace ONE across mixed fleets, or Ansible / curl-install for no-MDM teams. Reference templates live under `tools/mdm/` and `tools/deploy/`. Schedule the scan via the OS-native scheduler. Push signed surface configs and policy bundles via the same channel as code-signing certificates today.
- **Compliance** wants the audit trail. Every AIBOM is signed with Sigstore keyless, every signature is recorded in Rekor's transparency log, every binary that produced an AIBOM was itself signed by a workflow at a verifiable GitHub Actions path on a known repository. The chain holds without anyone trusting Reese Skye — Sigstore + Rekor + the GitHub OIDC issuer are the trust anchors.

For policy enforcement, an enterprise typically authors a Rego file that captures their internal rules — for example, "no MCP server may declare `secret:read` capability without an explicit grant," or "any MCP server that reads from the filesystem must be signed by an approved publisher." This Rego file plugs into the existing default catalog without forking Reeve. The policy bundle is recompiled with the customer's rules included and signed; the customer's CI distributes the bundle alongside the Reeve binary.

A typical enforcement flow at the enterprise tier:

1. Each managed employee laptop runs `reeve scan --policy-check` daily.
2. AIBOM uploaded to corporate evidence bucket.
3. AIBOMs failing policy trigger a SOAR playbook: notify the endpoint owner or team lead, surface the finding in their next weekly security report, optionally lock the offending MCP server until reviewed.
4. CI pipelines that touch AI infrastructure run a one-shot `reeve scan` of the build environment as a pre-deploy gate; failing AIBOMs block the deploy until resolved.
5. Quarterly: security team queries the bucket for distribution data — which teams run which MCP servers, what publisher concentration looks like, which capability deltas are trending.

The product does not require any of this infrastructure to be hosted by Reese Skye. The customer owns their evidence, their bucket, their dashboards, their policies. Reese Skye sells the agent and (eventually) commercial-tier features around large-fleet aggregation; the OSS CLI is the universal substrate.

### 6.4 CI / CD pipelines

Reeve is well-suited for build-time inventory. A CI job invokes `aibom-cli scan` against the build environment (the runner's filesystem) before the build deploys an AI-touching service. The output AIBOM serves as proof that the runner had a known, policy-compliant set of AI tools at deploy time. This is especially useful for AI-augmented build runners where a tool like Codex or Claude Code is part of the build infrastructure itself — the customer's own deploy logs now include cryptographic proof of what AI was running on the build runner.

For pipelines that require the build to fail when policy fails, the `aibom-cli policy check` exit code drives the gate. No additional tooling is needed.

---

## 7. The sales conversation, in one paragraph

> *"Reeve produces a signed inventory of AI tools registered through documented MCP config surfaces on an employee endpoint, plus signed evidence of the persistent approvals it knows how to parse for those tools. Today it covers eight built-in assistant MCP surfaces across macOS, Linux, and Windows config paths, plus explicit or signed custom MCP surface configs. It reads the same configuration files the AI tools themselves read — nothing else; the path list is enumerated in our public scope documentation. Default scans do not execute MCP servers. With explicit operator consent, Reeve can request `tools/list` and run opt-in profiling; macOS and supported Linux hosts use enforcement boundaries, while Windows evidence remains observational only. It also extracts supported saved approvals — `always approve this command for this project`, `always allow this MCP server to read these files` — so security teams can see the inherited-authority surface that an attacker would acquire by compromising the user. The output is a CycloneDX bill of materials plus an AIBOM sidecar with the AI-specific evidence, signed via Sigstore so any third party can verify it without trusting us. We have policies in Rego that flag the obvious risks — tools claiming to read files but trying to write, undeclared network egress, untrusted publishers, destructive command approvals, undeclared elevation primitives — and you can write your own policies in the same language. Distribution is a signed CLI binary; you install it on managed laptops via your existing endpoint management tool, schedule it on a cron, and ship the output to your existing SBOM platform or SIEM. We do not host anything. We do not phone home. We do not maintain a persistent index. Verification is the public Sigstore chain. Authorization is your existing process. Aggregation is your existing tooling."*

For a non-engineering buyer, the same pitch becomes:

> *"If your HR, legal, finance, or sales teams use Claude Desktop, Cursor, VS Code MCP, or other AI assistants, Reeve gives security a signed inventory of the tools those assistants can call. It does not read employee documents or monitor traffic. It reads the AI-tool config paths listed in the scope document, records the registered MCP servers and their declared versus observed capabilities, and produces signed evidence you can audit."*

The follow-up questions tend to be:

- *"What does the AIBOM look like?"* → show a fixture from `schema/examples/fixtures/`.
- *"How do I verify your binary?"* → run the cosign recipe from the version-specific appendix.
- *"Can you show me a denial?"* → exercise the test fixture where the sandbox denies a forbidden write and the AIBOM marks the event as denied rather than observed.
- *"How do you handle our internal AI tools we built ourselves?"* → walk them through `--add-surface` and the user-defined source label.
- *"What's the licensing posture?"* → Apache 2.0, no source-available-but-not-OSS games, no commercial obligations attached to the OSS CLI.
- *"What do you charge for?"* → today, nothing. Future commercial features around large-fleet aggregation, identity blast-radius analytics, and managed policy bundles are on the roadmap and explicitly out of v1 OSS scope.

The pitch does not rely on a hosted dashboard, a SaaS subscription, or a closed binary. The customer keeps full control of their data and verifies the chain end to end. That makes Reeve installable in environments where agent-based tools have struggled — air-gapped networks, classified environments, regulated finance.

---

## 8. Roadmap

The work past the current release splits into three categories.

**Approval-inventory expansion (in flight, partial coverage shipping now).** Saved-approval extraction on `main` covers Claude Code, Codex CLI, Codex App saved tool approvals, and Claude Desktop trusted folders. Risk-flagging policies for granted permissions landed in PR #86. Remaining adapter work is fixture-gated: Reeve will parse Cursor, Continue, broader Claude Desktop/Cowork approval state, VS Code MCP, Zed, and Factory only after captured config formats prove where saved approval state lives. The schema groundwork (the `granted` capability source and `granted-permission` evidence kind) was set in ADR-0008 and the v0.2.0 schema; what is shipping now is per-adapter parsing. Tracker: [#83](https://github.com/Reeve-Security/reeve/issues/83) (scanner work) under umbrella [#4](https://github.com/Reeve-Security/reeve/issues/4) (saved-permissions inventory).

**Polish** (no schema change required). Mostly customer-driven. Sharpens specific use cases without changing the public contract.

**v0.2.x and beyond — broader trust-domain expansion.** Cloud-hosted agent adapters (Bedrock, Vertex AI Agent Builder, SageMaker, Azure AI Studio), framework adapters (LangChain, LlamaIndex), and additional vendor-desktop adapters (ChatGPT Desktop, Gemini Desktop). Each new adapter ships with its own ADR for the trust-model expansion, especially for cloud-hosted agents where the discovery shape changes from "filesystem path" to "cloud API call."

**v1.0 and beyond.** Identity blast-radius analytics — the flagship commercial feature — joins here. The enterprise narrative moves from "what tools exist" to "if this AI agent's credentials are compromised, what is the actual reach across the customer's identity graph?" That story leverages the AIBOM (now including approval state) as an input to graph analytics rather than the end product itself. Native sigstore-rs replaces the cosign shell-out when sigstore-rs reaches maturity. Windows AppContainer support arrives in v1.1.

Items explicitly **out of scope for v1**: hosted dashboard, IDE plugins, runtime enforcement (real-time blocking of misbehaving agents), SPDX output, SBOM scanning of non-AI code. These are intentionally deferred. The v1 thesis is that the contract — schema + signed evidence — is the product, not a SaaS surface.

---

## 9. Repository pointers for technical reviewers

The repository at `github.com/Reeve-Security/reeve` is structured for review, not just for code:

- [`docs/positioning.md`](positioning.md) — long-form positioning and competitive context
- [`docs/architecture.md`](architecture.md) — the three-layer rule and why it is enforced
- [`docs/scope.md`](scope.md) — every path Reeve reads, by adapter, by OS
- [`docs/signing.md`](signing.md) — full signing protocol, threat model, day-to-day operations
- [`docs/v1-spec.md`](v1-spec.md) — the full v1 specification
- [`docs/gtm/inherited-authority.md`](gtm/inherited-authority.md) — buyer-facing positioning for the approval-inventory / inherited-authority story; technical and executive deck lines; the messaging "red lines" we will not cross
- [`docs/decisions/`](decisions/) — seventeen-plus ADRs covering every load-bearing decision; each ADR includes a plain-language summary so a non-engineer can follow the reasoning. ADR-0008 (granted source + `granted-permission` evidence) is the foundational decision behind the approval-inventory feature.
- [`docs/releases/`](releases/) — per-version capability appendices and install / verification recipes
- `schema/SPEC.md` — schema specification with the v0.1.0 ADR resolution summaries
- `schema/examples/fixtures/` — example AIBOMs with positive and negative cases, used by the validator's contract test
- `policies/` — the default Rego policies, each with its own `*_test.rego`. Includes the risk-flagging policies for granted permissions added in PR #86.
- `crates/` — the Rust workspace, organized by layer; six crates total

A technical reviewer who wants to spend an hour on the repository should read in this order: positioning → architecture → scope → SPEC → the inherited-authority gtm doc → the ADR index in `docs/decisions/` → the latest release appendix in `docs/releases/`. After that hour they will have a complete mental model of the project: what it is for, how it is structured, why every load-bearing choice was made, what shipped most recently, and what is known to be deferred.

---

## 10. Where this leaves us

Reeve has shipped the v0.1 release path as designed. The schema is locked, the scanner covers employee endpoints across macOS and Linux, the signing chain is verifiable end to end, the documentation is reviewable by a security team without a vendor call, and the contract is structured so customers can plug the output into their existing tooling without a migration.

What remains is **getting humans other than the founder and the AI agents to run this thing**. That is not a code problem. It is a customer-evidence and outreach problem. The product is ready before the pitch is — a good problem to have, but a real one, and it shapes the next phase of work.

For the specifics of which version is current, what changed in it, and how to install and verify it, jump to the latest release appendix in [`docs/releases/`](releases/).
