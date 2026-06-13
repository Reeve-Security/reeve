# Reeve deployment scenarios

Plain-language walkthrough of how Reeve actually gets deployed and what
the operational flow looks like at three scales. Written to answer the
question "how does this work in my environment?" without requiring the
reader to understand Sigstore internals.

Complements:
- `docs/signing.md` — the signing mechanics behind these scenarios.
- `docs/integrations.md` — composing Reeve output with existing
  SBOM / vulnerability tooling.
- `docs/v1-spec.md` — the full v1 feature surface.
- `tools/mdm/` — reference MDM deployment templates.
- `tools/deploy/` — reference no-MDM deployment templates.

This document is operational: *what you install, what you configure, what
it costs, who sees what.* The key mental anchor: **signing is a step
that happens once in the middle of the pipeline, in one place, by one
organizational identity — not on every laptop**.

---

## Binary placement and execution context

`aibom-cli` is a self-contained single binary. It does not depend on
its install directory, the current working directory, or any build
machine path. The schema and built-in assets needed for normal
validation are embedded in the release artifact, so placement does not
change scan behavior.

MDM can place the binary wherever the organization normally installs
tools: `C:\Program Files\Reeve\`, `/usr/local/bin`, `/opt/reeve`, a
managed tools directory, or a read-only network share. `--target`
selects the filesystem root to scan, and `--output-dir` selects where
artifacts are written. Neither value is inferred from the binary's own
location.

`cosign verify-blob` is for verifying a downloaded release artifact or
signed scan bundle. A normal local scan does not require cosign unless
the operator asks Reeve to perform real Sigstore signing or verification
work.

Fleet scans must run in a context that can see the user profile being
inventoried. Most AI agent surfaces are per-user stores such as
`%USERPROFILE%`, `%LOCALAPPDATA%`, or `~`. A per-machine SYSTEM/root
task can see system-managed configuration, but it may miss each user's
per-user agent stores unless it enumerates those profile roots directly
or launches one scan per user session. The default fleet pattern is:
MDM installs the binary once, then schedules a per-user scan or an
explicit `C:\Users\*` / `/Users/*` enumeration job.

## The three deployment scales

| Scale | Endpoints | Setup effort | Who touches OIDC |
|---|---|---|---|
| Solo user | 1 | 5 minutes | Nobody |
| Small team | 5–50 | ~2 hours one-time | One CI workflow identity |
| Enterprise | 50–5,000+ | 1–2 days one-time | One CI workflow identity for the whole organization |

No scenario requires per-employee OIDC logins. Signing authority is
always at the **organization** level, not the endpoint level.

---

## Scenario 1 — Solo user on their own laptop

**Who this is for**: a person who wants to know what AI agent tools
(MCP servers) are installed on their own machine. They may be a
developer checking Cursor and Codex, an HR specialist checking Claude
Desktop, an accountant checking an AI spreadsheet workflow, or an
auditor preparing evidence for a client.

**Setup required**: install Reeve. That's it.

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Reeve-Security/reeve/releases/latest/download/aibom-cli-installer.sh | sh
```

Homebrew is deferred per ADR-0024. GitHub Releases plus adjacent
Sigstore bundles are the canonical distribution path.

**What happens when you run it**:

```bash
$ aibom-cli scan
Scan complete: 9 components found
  cursor: 4
  claude-code: 5
Output:
  ./scan-<id>.cdx.json
  ./scan-<id>.aibom.json
```

Five seconds. No internet connection required during the scan. No
browser prompts. No accounts. No cloud. No signing — the output is
local-only, for the user's own eyes.

**What you get**: two JSON files listing every MCP server Reeve found
on the machine, the transport each one uses (stdio vs HTTP/SSE),
where each one was installed from, and the tool's declared
capabilities (read from its self-description).

**What you do with it**: read the JSON. Pipe it into `jq` to filter.
Compare it against the list of tools you *thought* were installed.
Uninstall anything unexpected.

**Cost**: zero. No signing, no cloud infra, no account.

---

## Scenario 2 — Small team (5–50 people)

**Who this is for**: a startup, law firm, finance team, or small
security-conscious organization that wants a weekly inventory of AI
tools across employee laptops without building custom infrastructure.

**Setup required** (one-time, 2 hours for a security-minded engineer):

1. One deployment template from `tools/deploy/curl-install/` or
   `tools/deploy/ansible/`, customized with the team's binary URL,
   signed `surfaces.yaml`, `surfaces.yaml.sigstore.json`, and signer
   identity regexp.
2. One GitHub Actions workflow file, committed to the company's
   GitHub org. This is the central signer.
3. One shared storage location — typically an S3 bucket, but GitHub
   release artifacts or even a shared Google Drive folder works for
   small teams.
4. On each laptop: a scheduled task (macOS launchd, Linux cron, or
   through whatever endpoint agent the team already uses) that runs
   `aibom-cli scan` once a week and drops the output into the shared
   storage.

**What the weekly flow looks like**:

- **Monday morning on each laptop**: the scheduled task runs
  `aibom-cli scan` while the employee is making coffee. Takes five
  seconds. Drops two JSON files into shared storage. No browser, no
  prompt, no OIDC, no signing — the laptop just wrote two files.

- **Monday night at 2 AM**: the GitHub Actions workflow wakes up on
  schedule. It fetches the week's new scan files from shared
  storage. For each one, it calls `cosign sign-blob` using GitHub
  Actions' own identity — the identity looks like
  `repo:yourcompany/reeve-signer:ref:refs/heads/main`, not any
  individual employee's account. All the week's scans get signed
  by that one identity. Signed files are written back to shared
  storage.

- **Tuesday morning**: the security lead reviews the signed output.
  They can view it in any JSON viewer, run `cosign verify-blob` on
  any file to confirm authenticity, diff this week's inventory
  against last week's to spot new or removed MCP servers, feed it
  into any SBOM tool the team already uses.

**Sample GitHub Actions workflow** (the whole central signer):

```yaml
name: Nightly Reeve signing pass
on:
  schedule: [{ cron: "0 2 * * *" }]
permissions:
  id-token: write        # required for Sigstore keyless OIDC
  contents: read
jobs:
  sign-batch:
    runs-on: ubuntu-latest
    steps:
      - run: aws s3 sync s3://yourco-reeve-unsigned/ ./in/
      - run: |
          for scan in ./in/*.aibom.json; do
            aibom-cli sign \
              --input-dir ./in \
              --scan-id $(basename "$scan" .aibom.json) \
              --output-dir ./out
          done
      - run: aws s3 sync ./out/ s3://yourco-reeve-signed/
```

**Total human effort after setup**: zero per week. Nothing to click,
no one logs in anywhere, no browser prompts.

**Cost**: roughly $1–5/month in GitHub Actions minutes. The shared
storage is either already paid for (S3) or free (GitHub artifacts).

---

## Scenario 3 — Enterprise (500 laptops)

**Who this is for**: a security team at a company with hundreds to
thousands of employee laptops, already running MDM, already paying
for an SBOM platform, already responding to CVE alerts across their
fleet.

**Setup required** (one-time, 1–2 days for a mid-level security
engineer):

1. **MDM push**: the Mac fleet tool (Jamf, Kandji) or cross-platform
   MDM (Intune, Workspace ONE, JumpCloud) pushes the Reeve binary and
   signed surface-config bundle to every employee laptop. Start from
   `tools/mdm/jamf/`, `tools/mdm/intune/`, or
   `tools/mdm/workspace-one/`. Zero user interaction.

2. **MDM-scheduled scan**: the MDM configures each laptop to run
   `aibom-cli scan` once a week and upload the output JSON files to
   a central ingestion point — typically an existing S3 bucket the
   security team already uses for endpoint telemetry.

3. **Central signing service**: one CI workflow (GitHub Actions or
   GitLab CI, whichever the company uses) runs on a schedule, pulls
   the unsigned scan files from the S3 bucket, signs each with the
   CI workflow's OIDC identity (one organizational identity like
   `repo:mycorp/reeve-inventory-signer`), writes signed bundles
   back to storage or pushes them directly to the SBOM platform.

4. **SBOM platform allowlist**: whichever SBOM platform the company
   uses — Snyk, Dependency-Track, Wiz, Orca, JFrog Xray, Sonatype
   Lifecycle — gets one configuration entry: "accept AIBOMs signed
   by `repo:mycorp/reeve-inventory-signer`, reject anything else."

**What the weekly flow looks like**:

- **Monday morning**: 500 laptops quietly produce scans via their
  MDM-scheduled task. None of those 500 employees sees anything —
  no browser, no prompt, no notification, no popup. The scan is
  invisible at the user level, the same way any other MDM-scheduled
  task is invisible.

- **Monday night**: the central signing job runs. Takes about 15
  minutes to sign all 500 bundles. Cost: roughly $2 of CI time.

- **Monday / Tuesday**: signed bundles feed into the SBOM platform
  automatically. The platform verifies each signature — about half
  a second per bundle — and ingests the CycloneDX data into its
  normal inventory alongside the company's other SBOM data.

- **Tuesday morning**: the security team looks at a single dashboard
  showing "MCP servers across the fleet this week." Full inventory,
  vulnerability status, deltas from last week. Any scan that failed
  verification (tampered, wrong signer, etc.) is flagged in red and
  investigated.

**Total employee impact**: zero. Nobody on any of the 500 laptops
ever sees anything related to Reeve or signing.

**Cost**:
- MDM: already paid for.
- SBOM platform: already paid for.
- CI: adds roughly $10/month at this scale.
- Reeve itself: open-source, free.

---

## Non-developer endpoint archetypes

Reeve's discovery is OS-path-driven, not role-driven. The scanner reads
approved AI-tool configuration paths and produces the same AIBOM shape
whether the endpoint belongs to engineering, HR, accounting, marketing,
sales, legal, finance, or operations.

Useful fleet archetypes for demos and deployment planning:

| Archetype | Example AI surface | Risk question |
|---|---|---|
| HR resume screening | Claude Desktop with document MCP server | Can this tool read only the approved recruiting folder? |
| Accounting spreadsheet automation | Codex CLI or Claude with spreadsheet MCP server | Did a tool with finance data attempt undeclared egress? |
| Marketing asset workflow | Claude plus image-generation MCP server | Which external services did the tool contact? |
| Sales CRM workflow | Cursor or VS Code MCP with CRM scripts | Which local scripts and network endpoints are registered? |
| Legal document review | Claude Desktop with broad document grants | Are broad filesystem grants declared, observed, and policy-approved? |
| Operations runbook helper | VS Code MCP or Claude Code | Can the tool execute commands or reach production systems? |

These are not special code paths. They are the same scan, evidence,
signature, and policy pipeline used for developer endpoints.

---

## SBOM platform ingestion — Snyk example

Snyk is the concrete example here; the flow for any other modern SBOM
platform (Dependency-Track, Wiz, Orca, JFrog Xray, Sonatype Lifecycle,
Aikido) is mechanically identical. Field names and UI labels differ.

**One-time setup in Snyk** (takes a few minutes):

An admin adds an entry in Snyk's SBOM-ingestion integration config:
"accept CycloneDX imports signed by Sigstore with identity pattern
`repo:mycorp/reeve-*`." This is the same integration surface Snyk
already exposes for ingesting signed npm provenance, PyPI PEP 740
attestations, and SLSA provenance from GitHub Actions.

**What happens on every weekly ingest** (fully automated):

1. The central signer workflow from Scenario 3 writes 500 signed
   bundles into a location Snyk is configured to ingest from —
   typically an S3 bucket Snyk polls, a direct API push to Snyk's
   CycloneDX import endpoint, or a GitHub Actions step that calls
   the Snyk CLI.

2. Snyk receives each bundle. Its ingestion pipeline runs:

   a. Reads the Sigstore bundle portion of the file.

   b. Calls its Sigstore verification routine. Snyk already has
      this — it uses the same library internally for npm
      `--provenance` signatures, PyPI PEP 740 attestations, and
      other supply-chain artifacts.

   c. Checks the signer identity against the allowlist.
      `repo:mycorp/reeve-inventory-signer` matches, so the bundle
      is accepted.

   d. If verification succeeds: Snyk extracts the CycloneDX
      document from the bundle, reads the package identities
      (`purl` fields like
      `pkg:npm/@modelcontextprotocol/server-filesystem@2.3.1`),
      and stores them in its SBOM database alongside every other
      SBOM the company has uploaded.

   e. If verification fails at any stage: Snyk rejects the ingest,
      logs it as "untrusted source" or "tampered artifact," and
      alerts via the company's standard security-alerts channel.

3. Snyk's existing vulnerability intelligence — which the company
   already pays for — automatically correlates the newly-ingested
   MCP server packages against its CVE database. No new alerting
   rules to configure.

**What this unlocks**:

When CVE-2026-12345 drops affecting `node-fetch@3.3.1` next Tuesday
morning, Snyk's normal "which of my SBOMs contain this vulnerable
package?" query **automatically** includes AI agent tools, not just
web applications. The security team gets one alert: "CVE-2026-12345
affects 14 MCP servers across 47 employee laptops." They respond
using the same CVE triage workflow they've always used. No new
dashboard. No new process.

**What changes in your day-to-day** compared to pre-Reeve:

- One extra SBOM "source" showing up in Snyk, labeled something like
  "Reeve AI Agent Inventory."
- One more dashboard panel showing MCP-server-specific findings.
- CVE triage flow extended to include AI agent tools automatically.

**What does not change**:

- Nothing about how Snyk itself works.
- Nothing about how the security team responds to alerts.
- Nothing about vulnerability-scanning cost. Snyk charges per
  package-hour scanned; the MCP packages add a small number but
  are negligible against the company's whole software surface.

---

## Setup checklist at each scale

| Scenario | What to install | What to configure | What to verify |
|---|---|---|---|
| Solo user | Reeve binary | Nothing | Output JSON files exist and are readable |
| Small team (5–50) | Reeve binary on each laptop | One GitHub Actions workflow YAML + one shared storage location + one scheduled task on each laptop | Weekly signed bundles appear in shared storage, signed by the CI workflow identity |
| Enterprise (500+) | Reeve binary via MDM push | One MDM-scheduled task + one central CI workflow + one SBOM-platform allowlist entry | Weekly dashboard in existing SBOM platform, no failed-verification alerts |
| SBOM ingestion (Snyk or similar) | Nothing new | One allowlist entry for the signer's OIDC identity | First ingested bundle passes verification, appears as a new source in the dashboard |

---

## When something goes wrong (quick troubleshooting)

- **Endpoint scans produce empty output**: the laptop has no MCP
  configs at the expected paths. Not a bug. (Reeve discovers eight
  built-in MCP config surfaces: Claude Desktop, Cursor, Continue,
  Claude Code, Codex CLI, Factory, Zed, and VS Code MCP extension.
  Explicit or signed custom surface configs can extend that set.
  Workspace-local discovery covers `.mcp.json` files under the scan
  target.)

- **Central signer fails with "cosign not found"**: install cosign
  on the signer environment (`brew install cosign` or equivalent).
  Endpoints do not need cosign. Only the signing environment does.
  This friction point remains until issue #11's native sigstore-rs
  maturity gate passes for a released crate and parity tests prove the
  backend can replace cosign safely.

- **SBOM platform rejects every bundle with "untrusted signer"**:
  the allowlist entry does not match the signer identity. Run
  `cosign verify-blob` locally against a sample bundle to see the
  actual signer identity string, then update the allowlist.

- **Scans work but no signatures appear**: verify the central signer
  workflow is running on schedule (check CI logs) and that it has
  `id-token: write` permission in its YAML. Without that permission,
  GitHub Actions cannot issue OIDC tokens to Sigstore.

- **Air-gapped environment**: Reeve v0.1 signing requires network
  access to Sigstore public-good infrastructure
  (`fulcio.sigstore.dev`, `rekor.sigstore.dev`, and the OIDC
  provider). Scanning itself is fully offline; signing is not.
  Full air-gapped signing requires a private Sigstore deployment —
  v1.x roadmap item.

---

## What this document does not cover

- **The cryptographic details of how signing works** — see
  `docs/signing.md` §2-3.
- **Why Sigstore and not PGP or something else** — see
  `docs/signing.md` §6, §10.
- **The public-Rekor-log privacy tradeoff** — see `docs/signing.md`
  §7.1 and the private-Sigstore roadmap (v1.x).
- **Composing Reeve output with Syft for transitive dependency
  resolution** — see `docs/integrations.md`.
- **The policy engine and capability-delta verdict flow** — part of
  the v1 feature surface beyond the scanner, tracked under tasks #10
  and #11. The deployment story stays identical; policy verdicts
  become one more thing the SBOM platform displays.

Ask questions directly. Deployment walkthroughs are easier to refine
with specific scenarios than with speculative coverage.
