# ADR-0019: Conversation-log scanning uses a separate opt-in sensitive-data report

- **Status:** Proposed
- **Decides:** Issue #165 / #166 conversation-log inventory privacy architecture
- **Related:** ADR-0008, ADR-0004, `docs/scope.md`, `THREAT_MODEL.md`

## Context

Issue #165 proposes a new Reeve evidence surface: local AI assistant
conversation logs and session stores. These files can contain pasted API
keys, credentials, customer data, proprietary source code, internal
hostnames, and business-sensitive text. They also persist after an agent
is closed or uninstalled and may be copied into endpoint backups or
forensic images.

Reeve already has the endpoint context needed to find these files, but
reading conversation logs is qualitatively different from reading MCP
configuration. MCP config describes agent authority. Conversation logs
may contain user content.

The project needs a privacy architecture before any implementation work
starts. Otherwise a scanner whose security thesis is "evidence, not
claims" could accidentally become a tool for collecting sensitive user
content.

## Options considered

### A. Add conversation-log findings directly to the AIBOM schema

This keeps all Reeve output in one artifact and reuses the existing
AIBOM signing and policy pipeline.

Pros: one output file, familiar path for policy consumers, simple
distribution story.

Cons: expands AIBOM from agent authority evidence into sensitive-data
inventory, forces a schema bump, and makes every AIBOM consumer think
about whether private conversation findings may be present.

### B. Emit only policy findings and never serialize raw findings

Reeve would scan logs, run policies in memory, and only emit pass/warn
verdicts such as "secret pattern matched".

Pros: smallest serialized surface and low schema cost.

Cons: weak audit trail. A security team cannot later explain which
agent, which log file, or which pattern class caused the finding without
rerunning the scan. This also weakens drift comparison.

### C. Make conversation-log scanning commercial/private only

The OSS scanner would never touch conversation logs. A paid product or
service would implement the feature separately.

Pros: keeps the OSS privacy surface narrow and protects public launch
scope.

Cons: creates two scanners or two trust postures. It also undermines the
open evidence story if the most sensitive endpoint inventory is hidden
behind a closed format.

### D. Emit a separate signed sensitive-data report *(chosen)*

Reeve keeps AIBOM focused on agent authority and emits conversation-log
inventory into a separate artifact, for example
`scan-<id>.sensitive.json`, only when the operator explicitly opts in.
That report is signed separately and linked from higher-level reports,
not embedded in the AIBOM sidecar by default.

Pros: preserves AIBOM scope, gives auditors a durable artifact, keeps
privacy-sensitive findings isolated, allows separate retention rules,
and avoids forcing all AIBOM consumers to process sensitive-data
metadata.

Cons: adds another artifact, another signing path, and another report
consumer surface.

## Decision

Conversation-log inventory will not be added to the AIBOM schema in the
first implementation. It will be emitted as a separate signed
sensitive-data report.

Default scans do not read conversation logs. Operators must pass an
explicit opt-in flag to inventory conversation-log metadata. Content
pattern scanning requires a second explicit opt-in flag.

The sensitive-data report must never include conversation content, raw
secret values, or hashes of secret values. Findings may include:

- agent surface;
- redacted path relative to the scan target where possible;
- file size;
- last modified time;
- pattern class, such as `aws-access-key` or `jwt`;
- match count;
- confidence level;
- evidence id and source reference.

The report may include aggregate byte counts and file counts per agent
surface. It may not include surrounding text, prompt snippets, raw
matches, screenshots, embeddings, or searchable indexes.

The report must be signable and verifiable through the same public
Sigstore trust model used elsewhere in Reeve. It may be rendered into
human-readable reports and fleet summaries, but downstream tools must be
able to store it separately from the AIBOM.

Commercial products and professional services may consume this report,
map it to OSCAL/NIST/SOC 2 evidence, or aggregate it across a fleet.
They must not require a different private scanner to produce the core
finding format.

## Rationale

This decision keeps Reeve's core schema honest. The AIBOM answers "what
AI tools exist, what capabilities do they declare or exhibit, and what
authority has the user granted?" Conversation-log scanning answers a
different question: "what sensitive data appears to be sitting in local
AI assistant stores?"

Those questions are related, but they have different privacy and
retention requirements. Many customers will be comfortable storing an
AIBOM broadly in SBOM or GRC tooling. Fewer will want conversation-log
secret findings to flow into every AIBOM consumer by default.

A separate signed report gives customers a clean control boundary. They
can run the scanner with no conversation-log access, with metadata-only
conversation inventory, or with pattern scanning. They can retain or
delete the sensitive report on a different schedule from the AIBOM.

Avoiding raw secret values and secret hashes is deliberate. Hashes of
short or structured secrets can still become offline guessing targets.
The useful audit fact is the pattern class, count, source file, and
confidence, not the value itself.

## Plain-language summary

Reeve should not secretly read chat histories. Conversation logs can
contain the most private material on a laptop: customer data, pasted
tokens, internal source code, and strategy text.

So this decision says: normal Reeve scans do not touch those files. A
customer has to turn the feature on deliberately.

Even when turned on, Reeve does not copy conversations into the AIBOM.
It writes a separate sensitive-data report. That report can say things
like "Claude Desktop has three session files and one looks like it
contains an AWS access key." It must not include the actual key or the
surrounding conversation.

Keeping the sensitive-data report separate matters because different
teams handle different artifacts. An AIBOM can flow into normal SBOM and
GRC systems. A sensitive-data finding may need tighter access control,
shorter retention, or legal review.

This gives customers useful evidence without turning an endpoint scanner
into a content collection system.

## Consequences

- **This decision commits the project to:** keeping conversation-log
  inventory opt-in; requiring a second opt-in for content pattern
  scanning; emitting conversation-log findings in a separate signed
  sensitive-data report; excluding raw content, raw secret values, and
  secret hashes from serialized findings; and documenting the read set in
  `docs/scope.md` before code lands.
- **This decision unblocks:** filing implementation sub-issues under
  #165, defining the report schema, creating synthetic fixtures, adding
  policy checks over sensitive-data findings, and updating buyer-facing
  copy without implying that the AIBOM itself contains conversation
  content.
- **This decision forecloses:** embedding conversation-log findings
  directly in the AIBOM v0.2 schema; scanning conversation logs by
  default; storing raw secret values; and using secret hashes as a
  privacy escape hatch.
- **This decision defers:** exact CLI flag names, exact report schema
  version, which agent surfaces ship first, commercial packaging, and
  fleet aggregation UX.

## References

- [ADR-0004: Sign AIBOM + CycloneDX pair as a DSSE-wrapped in-toto Statement in a Sigstore bundle v0.3](0004-signature-envelope.md)
- [ADR-0008: Add `granted` capability source and `granted-permission` evidence kind](0008-granted-source-amendment.md)
- Issue #165
- Issue #166
- `docs/scope.md`
- `THREAT_MODEL.md`
