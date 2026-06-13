# ADR-0022: Reeve is a config reader and on-endpoint profiler, not an MCP proxy

- **Status:** Accepted 2026-05-14
- **Decides:** Issue #189 config-reader versus MCP proxy architecture boundary
- **Related:** ADR-0009, ADR-0017, ADR-0018, ADR-0019, ADR-0020, `docs/architecture.md`, `docs/positioning.md`, `docs/scope.md`

## Context

Strategy review raised a recurring architecture question: should Reeve
remain a bounded config reader, or become an MCP traffic proxy that
intercepts live assistant-to-tool calls?

Reeve's shipped behavior is already bounded inventory plus local
profiling:

- bounded filesystem config discovery from `docs/scope.md`;
- local MCP introspection for declared capabilities;
- local sandbox or observational profiling for declared-versus-observed
  capability evidence;
- signed snapshot and report artifacts;
- no live MCP traffic interception.

The question still needs an ADR because the difference shapes deployment,
public claims, central-corpus design, and enterprise trust review. A proxy
would be a different product posture: traffic routing, credential
exposure, runtime availability risk, and possible enforcement
expectations. Reeve's current thesis is evidence, not enforcement.

## Options considered

### A. Remain a bounded config reader and on-endpoint profiler *(chosen)*

Reeve reads documented config paths, introspects registered tools, and
may run bounded local profiling on the endpoint to compare declared and
observed behavior. It does not place itself between assistants and MCP
servers.

Pros: low deployment friction, clear filesystem scope, no traffic
rerouting, no customer traffic upload, preserves evidence-not-enforcement
positioning, and keeps the scanner attack surface auditable.

Cons: Reeve does not see every live runtime call. Drift detection is based
on scan-to-scan comparison, config state, and explicit profiling evidence,
not continuous traffic monitoring.

### B. Become an MCP traffic proxy

Reeve would sit in the path between assistants and MCP servers, routing or
observing live MCP calls.

Pros: live call visibility, direct runtime telemetry, and a possible
future gateway or centralized-call story.

Cons: creates MITM-style enterprise review friction, handles sensitive
payloads and credentials, increases availability and security risk,
implies runtime enforcement, and conflicts with the v1 non-goals in
`docs/v1-spec.md`.

### C. Support both modes

Reeve would keep the current scanner while also adding an optional proxy
mode later.

Pros: preserves optionality for buyers that want live visibility.

Cons: keeps the product boundary ambiguous, encourages public-copy drift,
increases support burden, and makes every architecture discussion carry
two mental models instead of one.

## Decision

Reeve remains a bounded config reader and on-endpoint profiler. It is not
an MCP proxy.

Concretely:

- Reeve does not install itself as a traffic proxy between assistants and
  MCP servers.
- Reeve does not route, broker, approve, deny, or intercept live MCP
  calls.
- Reeve does not upload customer inventory, conversation content, or live
  traffic to a central service.
- Reeve may read documented config paths and explicit opt-in
  conversation-store paths from `docs/scope.md`.
- Reeve may run bounded local profiling on the customer's endpoint to
  produce declared-versus-observed capability evidence.
- A future central MCP corpus may use public registries, package
  metadata, vendor advisories, third-party research, and Reeve-operated
  lab profiling. It must not depend on customer traffic interception.

## Rationale

The decision preserves Reeve's core positioning: inventory and signed
evidence, not governance workflow or runtime enforcement. Customers can
run Reeve, inspect the exact read set, receive signed artifacts, and feed
those artifacts into their own policy, SIEM, GRC, or review process.

A proxy would be more powerful in one narrow sense: it could see live
calls. But that power comes with the wrong deployment burden. Enterprise
security teams would need to review a new traffic path, decide whether
Reeve can see sensitive prompts or tool payloads, reason about credential
handling, and treat Reeve as part of runtime availability. That is a much
larger trust request than a bounded scanner.

Local profiling remains in scope because it is not the same thing as a
traffic proxy. Profiling is an explicit scan step that runs a discovered
local stdio MCP server under controlled conditions and records observed
behavior. It helps Reeve compare what a tool says it can do with what it
attempts to do, while keeping execution on customer hardware.

The pull-only central-corpus model also does not require proxy behavior.
Reeve clients can query public intelligence about MCP servers and package
versions without uploading customer inventory or traffic. Corpus
enrichment can come from public sources, third-party advisories, and
Reeve-run lab analysis.

## Plain-language summary

Reeve is the inventory clerk and evidence recorder. It reads the places
where AI assistants store their tool registrations, checks what is there,
and can briefly test local tools in a controlled room. Then it writes a
signed report.

Reeve is not the toll booth between the assistant and the tool. It does
not stand in the middle of every MCP call. It does not watch every live
conversation. It does not approve or deny tool calls while the user is
working.

That boundary matters because a toll booth sees traffic. If Reeve became
that, customers would have to trust it with prompts, tool payloads,
credentials, and runtime availability. That is a much harder product to
deploy and a different company to build.

The chosen model is narrower and stronger for launch: read documented
config, produce signed evidence, compare snapshots over time, and let the
customer decide what to do with the output.

## Consequences

- **This decision commits the project to:** bounded config discovery,
  explicit local profiling, scan-to-scan drift detection, pull-only
  central intelligence, and public copy that does not imply live traffic
  interception.
- **This decision unblocks:** Issue #189, central-corpus planning that
  does not depend on customer traffic upload, and site language that
  distinguishes "on-endpoint profiling" from "proxy."
- **This decision forecloses:** MCP proxy behavior in v1/v1.x, runtime
  traffic routing, gateway-style enforcement, and launch claims about
  continuous live-call monitoring.
- **This decision defers:** whether a separate future product ever offers
  gateway or proxy behavior. Reopening that path requires a new ADR that
  supersedes this one.

## References

- [ADR-0009: Linux profiling uses enforcement when available, with explicit observational fallback](0009-linux-profile-observational-fallback.md)
- [ADR-0017: Windows profiling starts as explicit observational evidence](0017-windows-observational-profiling.md)
- [ADR-0018: Empty discovery is valid inventory](0018-empty-discovery-is-valid-inventory.md)
- [ADR-0019: Conversation-log scanning uses a separate opt-in sensitive-data report](0019-conversation-log-sensitive-data-report.md)
- [ADR-0020: Demo fleet is a phased, department-flavored, populated dataset -- not the validation fleet](0020-demo-fleet-design.md)
- Issue #189
- `docs/architecture.md`
- `docs/positioning.md`
- `docs/scope.md`
- Strategic context: private founder strategy memo, 2026-05-14
