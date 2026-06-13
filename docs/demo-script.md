# One-Shot Demo Recording Script

> **Audience:** security engineers, AppSec leads, platform security,
> and founder-led buyer calls.
>
> **Goal:** record Reeve inventorying a realistic mixed-platform AI
> assistant fleet, producing signed evidence, and stopping short of
> governance or enforcement claims.
>
> **Source matrix:** [`infra/demo-fleet/variant-matrix.md`](../infra/demo-fleet/variant-matrix.md).
>
> **Status:** recording checklist for issue #195. Endpoint IDs are fixed
> enough for #191 planning. Exact CVE labels remain gated on #192.

## Hard Rules

- Say **inventories**, **surfaces**, **records**, **verifies**, or
  **correlates**.
- Do not say Reeve **secures**, **fixes**, **blocks**, **enforces**, or
  **approves**.
- Do not execute exploit payloads. Vulnerable evidence is version,
  package, config, or signature evidence only.
- Do not name CVEs, TrustFall, LayerX, Trend Micro, or any launch stat
  unless #192 has pinned the primary source and exact wording.
- Do not describe Windows profiling as sandbox enforcement. Windows
  profiling is observational per ADR-0017.
- Do not describe R2 as product architecture. R2 is only the recording
  artifact bucket.

## Consent Ladder

Use this ladder in the narration. It prevents the demo from implying
Reeve executes arbitrary MCP servers on a normal scan.

| Tier | Command mode | Evidence kind | Narration |
|---|---|---|---|
| 1 | default scan | `mcp-registration` | "Default Reeve reads documented config paths and inventories registered MCP servers." |
| 2 | `--introspect-execute --introspect-execute-yes` | `mcp-tools-list` | "Live MCP self-description is a separate opt-in because it launches local stdio servers." |
| 3 | `--profile --profile-yes` | `profile-observed` | "Profiling is another explicit opt-in. macOS and Linux use sandbox boundaries; Windows records observational evidence." |
| 4 | `--include-conversation-metadata --scan-conversation-secrets` | `sensitive-data-report` | "Conversation secret scanning requires two explicit opt-ins and emits a separate report with no raw secret values." |

## Recording Setup

- Use the signed evidence artifacts from the one-shot fleet run.
- Record against saved artifacts where possible. Do not depend on live
  cloud hosts during narration.
- Keep the terminal large enough for mobile playback.
- Keep a second pane available for the rendered fleet report.
- If #111 registry reference artifact is not signed before recording,
  remove the optional registry-reference scene.

## Scene List

### 0. Open: Invisible AI Supply Chain

**Endpoints:** none.

**On screen:** title card or terminal prompt.

**Voiceover:**

> "Your company knows what runs in production because it has SBOMs. But
> AI assistants on employee laptops now have tools, approvals, local
> configs, and conversation state. Most teams cannot inventory that
> supply chain."

### 1. Fleet At Rest

**Endpoints:** all IDs in `infra/demo-fleet/variant-matrix.md`.

**Artifacts:** signed fleet manifest, fleet report.

**On screen:** fleet summary table: OS, persona, assistants, MCP
registrations, approvals, sensitive-report counts, evidence age.

**Voiceover:**

> "This is a 50-endpoint recording dataset shaped like a small company:
> Linux developer machines, Windows finance and sales laptops, and macOS
> executive or creative endpoints. Reeve turns each endpoint into signed
> evidence, then summarizes the fleet."

### 2. Default Inventory: Registered MCP Servers

**Endpoints:** `eng-linux-01`, `mkt-win-01`, `fin-win-01`.

**Evidence:** `mcp-registration`.

**On screen:** endpoint drilldown showing MCP server registrations
across Claude Desktop, Claude Code, Codex CLI, Cursor, VS Code MCP, or
other covered surfaces.

**Voiceover:**

> "First tier: default inventory. Reeve reads documented MCP config
> paths and records what is registered. No local MCP server execution is
> required for this view."

### 3. Explicit Introspection And Profiling

**Endpoints:** `eng-linux-02`, `eng-macos-01`, `sales-win-02`.

**Evidence:** `mcp-tools-list`, `profile-observed`.

**On screen:** command pane showing explicit flags, then evidence rows.

```bash
reeve scan --target "$HOME" \
  --introspect-execute --introspect-execute-yes \
  --profile --profile-yes \
  --policy-check
```

**Voiceover:**

> "Second and third tiers are explicit. Introspection asks the MCP server
> what tools it exposes. Profiling records what it attempts to do under
> the platform boundary. Windows records observation, not sandbox
> enforcement."

### 4. Vulnerable-Version Evidence

**Endpoints:** `fin-win-03`, `eng-linux-04`, `sales-win-03`.

**Evidence:** `VV-01`, `VV-02`, `VV-03` from the variant matrix.

**On screen:** version/package evidence rows with advisory labels filled
only after #192 closes.

**Voiceover:**

> "This is not exploit execution. Reeve records package and version
> evidence. Once an advisory is verified, security teams can route the
> finding to the patching process they already use."

### 5. Approval State

**Endpoints:** `eng-linux-05`, `hr-win-03`, `sales-macos-01`.

**Evidence:** `granted-permission`.

**On screen:** approvals table showing no approvals, allow-once, and
always-allow variants.

**Voiceover:**

> "Approvals are part of the AI supply chain. A user may click always
> allow once and forget it. Reeve records those durable grants as
> evidence so the customer can review them."

### 6. Conversation Secret Report

**Endpoints:** `fin-win-04`, `hr-linux-04`, `eng-linux-06`.

**Evidence:** `sensitive-data-report`.

**On screen:** separate sensitive-data report summary. Show finding
types and redacted locations, not raw values.

**Voiceover:**

> "Conversation scanning is separate and requires two opt-ins. The
> report records matched secret classes and redacted locations. It does
> not embed raw conversation text or raw secret values in the AIBOM."

### 7. Config Drift

**Endpoints:** `mkt-win-04`, `eng-linux-03`.

**Evidence:** `config-drift`.

**On screen:** before/after diff: new MCP registration, changed command
args, changed approval state, or removed signed config.

**Voiceover:**

> "Reeve can compare evidence across scans. Here the endpoint changed:
> a new MCP registration appeared and an approval state widened. Reeve
> does not block it; it makes the change visible."

### 8. Signed Evidence Chain

**Endpoints:** `fleet-manifest`, plus `fin-win-03` as endpoint example.

**Evidence:** `sigstore-bundle`, `fleet-manifest`.

**On screen:** manifest file, one endpoint AIBOM, one sensitive-data
report, and cosign verification output.

```bash
cosign verify-blob \
  --bundle fleet-manifest.sigstore.json \
  --certificate-identity-regexp '<release-identity-regexp>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  fleet-manifest.json
```

**Voiceover:**

> "The output is not a screenshot. It is signed evidence. A reviewer can
> verify the manifest with cosign and inspect the endpoint artifacts
> without trusting the demo narration."

### 9. Optional Registry Reference Correlation

**Gate:** include only if #111 has produced a signed registry reference
artifact before recording.

**Endpoints:** `mkt-linux-02`, `fin-win-03`.

**Evidence:** `registry-reference-match`.

**On screen:** endpoint MCP server matched to public registry metadata.

**Voiceover:**

> "The local agent inventories what exists on the endpoint. The central
> registry reference enriches that inventory from public MCP server
> metadata. The customer does not push its endpoint inventory back to
> Reeve."

### 10. Close

**Endpoints:** fleet summary.

**On screen:** final report totals and repository URL.

**Voiceover:**

> "Reeve is inventory, not governance. It gives security teams signed
> evidence about AI assistant tooling. Their existing patching, MDM,
> SIEM, SOAR, and GRC workflows decide what to do next."

## Apply-Day Checklist

- [ ] #192 has verified any named advisory, CVE, or third-party stat
  used on screen.
- [ ] No scene triggers exploit payloads.
- [ ] Fleet matrix endpoint IDs match artifact filenames.
- [ ] Every command shown is reproducible from the artifact bundle or
  documented fleet runbook.
- [ ] Windows profile narration says observational.
- [ ] Conversation secret scene shows redacted report only.
- [ ] Registry reference scene removed unless #111 signed artifact
  exists.
- [ ] Final cut uses Reeve inventory language, not enforcement language.
