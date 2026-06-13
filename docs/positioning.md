# Positioning

## Reeve produces evidence, not safety claims

Reeve is a **system of record for the AI supply chain**. It does not
claim "this tool is safe." It claims "this is what this tool is, who
signed it, what it says it does, what it actually did, and here is
the cryptographic trail behind each of those claims."

Your policies — or NIST's, or the EU's — decide what *safe* means.
Reeve produces the evidence those policies consume.
[ADR-0038](decisions/0038-evidence-not-safety-verdicts.md) formalizes
this as the says/can/has-done evidence boundary.

## The SBOM analogy

This is the same pattern that works for conventional software
supply-chain tooling. Syft does not tell you your application is
secure; it tells you what is in it. Trivy, Grype, and Dependency-
Track do the reasoning. An AppSec team or auditor makes the
decision.

Reeve plays the same role for AI agent tools. The reason this
pattern works is that evidence is auditable, portable, and
composable — claims of safety are not.

## Who Reeve is for

Reeve is endpoint inventory for AI agent tooling across the
organization, not just for software engineers. The same Claude Desktop
config path can appear on a backend engineer's laptop, an HR laptop
used for resume review, a finance laptop used for spreadsheet
automation, or a legal laptop used for document analysis. Reeve cares
about the registered AI tool and its MCP servers, not the employee's
job title.

That distinction matters for buyers. If an employee can install an AI
assistant that reads local files, runs commands, or reaches network
services, security and compliance need signed evidence of what was
registered and what it attempted to do. Developer endpoints are the
first obvious surface; knowledge-worker endpoints are the broader
fleet.

## Drop-in deployment

Reeve is designed to fit the endpoint channels security and IT teams
already run. A customer ships a signed CLI binary, schedules a scan, and
routes the signed output to existing storage, SIEM, SBOM, or GRC
systems. Jamf, Intune, Workspace ONE, Ansible, cron, launchd, and Task
Scheduler are enough for the initial deployment shape.

This is intentionally different from gateway or EDR-class products. A
gateway usually requires network rerouting and certificate management. An
EDR product usually adds a managed sensor. Reeve's launch surface is a
scheduled evidence-producing command, not a proxy, daemon, or enforcement
agent.

The deployment contrast, by category:

| Dimension | Reeve | Inline gateway / proxy | EDR-class sensor |
|---|---|---|---|
| What gets installed | A signed CLI binary | An inline proxy in the network path | A resident endpoint agent |
| Network changes | None | Traffic rerouting and TLS interception | None; host-resident |
| Runtime footprint | A one-shot scheduled command that exits | An always-on proxy | An always-on daemon |
| Live traffic | Not touched | Intercepted | Not the primary surface |
| Action on findings | Produces signed evidence; does not block | Can block inline | Can block or quarantine |
| Output destination | Your own storage, SIEM, or SBOM platform | The gateway control plane | The vendor management console |
| Removal | Delete the binary | Unwind routing and certificates | Uninstall the agent |

The table describes the typical deployment shape of each category, not
any one product; individual tools vary. The point is the install
surface: Reeve adds a scheduled command and signed output files, with
nothing to route through and nothing left resident.

## What Reeve claims

- **Complete inventory** across the scanned surface.
- **Cryptographically verified identity and provenance**, where
  signatures exist.
- **Capability truth**: what each tool declares versus what it does
  when run in a sandbox, with evidence for both.
- **Policy verdict** against the customer's Rego rules.
- **Audit-ready output.** The AIBOM is signed and reproducible.
  Hand it to an auditor unmodified.
- **Change detection** across scans.
- **Drop-in deployment** through existing endpoint-management and
  scheduling channels.

## What Reeve does not claim

- *"This tool is safe."* Policies define safety, not Reeve.
- *"This publisher will never be compromised."* Trust is point-in-
  time.
- *"Runtime enforcement."* Reeve reports; it does not block.
  Enforcement is out of scope for v1.
- *"Live traffic monitoring."* Reeve reads bounded config paths and
  performs explicit local profiling; it does not proxy or intercept MCP
  calls. See [ADR-0022](decisions/0022-config-reader-not-proxy.md).

## What Reeve does NOT do

Reeve is not EDR, DLP, an IDE plugin, a hosted dashboard, or a general
SBOM scanner. v1 does not perform runtime blocking, auto-remediation,
model-weight provenance, training-data lineage, Windows sandboxing,
SPDX output, or non-MCP adapter discovery.

Reeve's bounded filesystem scope is part of the product claim. A v0.1
scan reads the MCP config paths listed in [`docs/scope.md`](scope.md),
not the broader home directory, source tree, browser state, email,
documents, network shares, or secret stores. This is a differentiator
from broad endpoint tooling: Reeve produces narrowly scoped AIBOM
evidence for AI agent tool registrations, then hands that evidence to
policy engines and auditors.

This does not make Reeve a developer-only tool. It means the boundary
is role-neutral: Reeve reads the same AI-tool config paths on employee
endpoints used by engineering, HR, accounting, marketing, sales, legal,
finance, or operations.

## Why this framing matters

Legally defensible — we do not make safety claims we cannot back
with evidence. It matches the mental model security buyers and
auditors already operate in. And it positions Reeve as
**infrastructure** (the format others emit and consume) rather than
one more scanner in the bake-off.
