# Threat model

Audience: security engineers evaluating whether Reeve is safe to install
and trustworthy enough to be a load-bearing audit artifact. This is a
navigational summary, not a full security review. For the disclosure
process, see [`SECURITY.md`](SECURITY.md).

## Security thesis

Scanners are an attack surface. Reeve's own supply-chain integrity is
in scope for its security policy. Sandbox escape during capability
profiling, signature-verification bypass, and policy-engine verdict
misreporting are all in-scope vulnerabilities. This thesis is
load-bearing: it shapes the build order, the layer separation, and the
release-signing path. Reeve produces evidence, not safety claims (see
[`docs/positioning.md`](docs/positioning.md)) - but the integrity of
that evidence is a hard product requirement.

## Threat in three paragraphs

AI agents persist approval state. A user can click or configure
"always allow this tool," "always approve this command," or "trust this
server for this project." That approval is not a new OS privilege, but
it is durable agent authority. A later agent run can reuse it without
asking the user again.

If an endpoint, session, or agent process is compromised, the attacker
inherits the user's saved AI-agent approvals. The OS still sees
ordinary user-context activity, and EDR may still alert on behavior.
The missing inventory is the saved approval state itself: which agents
have durable permission to read, write, execute, call tools, or reach
network services.

Reeve models that surface as `granted-permission` evidence and
`capabilities.granted[]` where adapter formats are known. This fixture
record is from
[`schema/examples/fixtures-v0.2.0/positive/11-granted-permission/fixture-11.aibom.json`](schema/examples/fixtures-v0.2.0/positive/11-granted-permission/fixture-11.aibom.json):

```json
{
  "id": "ev-002",
  "kind": "granted-permission",
  "reference": "claude-code://settings/always-approve#fs:read"
}
```

## Conversation-log privacy boundary

ADR-0019 adds a separate sensitive-data report for opt-in
conversation-log inventory. This is intentionally not part of the AIBOM.
The AIBOM remains the broadly shareable artifact for agent authority and
capability evidence. Conversation-log findings are more private and may
need tighter access control, shorter retention, and a different review
path.

Default scans do not read conversation logs or session stores. Operators
must opt in with `--include-conversation-metadata` to inventory file
counts, total bytes, timestamps, and redacted paths for the supported
conversation-store roots. Reading file contents requires a second,
separate opt-in: `--scan-conversation-secrets`.

Even with the second flag, Reeve does not claim that a detected pattern
is a confirmed secret leak. It reports pattern classes, counts, source
references, and confidence for human review. That avoids turning a
heuristic match into an overstated policy verdict.

This boundary adds specific risks that the design has to manage:

- **Report retention risk.** The sensitive-data report can itself become
  a sensitive artifact. It may reveal where conversation stores exist,
  which agent surface wrote them, and whether secret-like material was
  detected. Operators should retain it separately from broadly shared
  AIBOMs.
- **Path metadata leakage.** File-system paths can expose usernames,
  repository names, project names, or host context. Reeve redacts
  user-controlled path segments by default and serializes only the
  redacted path.
- **False positives and analyst overreach.** Regex or heuristic matches
  can identify strings that resemble secrets but are benign test data or
  documentation. Findings therefore say "needs human review" rather than
  "confirmed leak".
- **Access-control boundary.** OSS output is local evidence, not a
  hosted evidence pipeline. Customer-side ACLs, retention controls, and
  downstream evidence routing are the operator's responsibility.

## Introspection execution boundary

Default scans inventory MCP registrations from documented config paths
without executing the registered stdio MCP servers. When Reeve needs the
server's live self-description (`tools/list`, `resources/list`, or
`prompts/list`), the operator must opt in with
`--introspect-execute` and confirm interactively, or pass
`--introspect-execute-yes` for non-interactive automation.

That opt-in is separate from `--profile`. Introspection execution asks a
server what it declares; sandbox profiling runs the server under the
platform-specific profiler to record observed behavior. The two surfaces
have different risk profiles and are not treated as the same consent.

## What Reeve catches that EDR, SBOMs, and gateways usually miss

- Persistent AI-agent approval state in local config files.
- Declared-vs-observed capability drift from profiling a tool under an
  OS sandbox.
- A signed inventory that ties AI-specific evidence to a CycloneDX BOM
  via the AIBOM sidecar.
- Policy verdicts over canonical evidence, including risky saved
  approvals where parser coverage exists.

EDR can observe process behavior after it happens. SBOM tools can
inventory packages. Network gateways can observe egress. Reeve's job is
the endpoint-side evidence layer those tools usually do not maintain:
which AI agent surfaces exist, what they claim, what they attempt, and
which durable approvals they already hold.

## What Reeve does not catch

- User intent. Reeve records evidence; policy and operators decide risk.
- Runtime blocking. v1 reports only; runtime enforcement is deferred.
- Every possible saved approval format. Approval parsing is
  adapter-specific and fixture-gated.
- Compromise of an MCP server after a clean scan.
- GUI click events or transient chat decisions that are not persisted
  as config state.
- General malware behavior unrelated to AI-agent surfaces.

## In scope

Vulnerability classes treated as in-scope (see [`SECURITY.md`](SECURITY.md)
for the canonical list):

- Sandbox escape during MCP capability profiling on macOS
  (`sandbox-exec`) or Linux (Landlock + seccomp).
- Signature-verification bypass against AIBOM output, surface-config
  bundles, or release artifacts (Sigstore, Rekor, hash checks).
- Policy-engine verdict misreporting: any path where Rego evaluation
  reports a different verdict than policy + evidence imply.
- Supply-chain compromise of Reeve's own release binaries, source
  tarball, policy bundle, or installer script.
- Filesystem read-scope expansion beyond the MCP config paths
  documented in [`docs/scope.md`](docs/scope.md).
- Privilege escalation triggered by the scan, profiler, or signing
  paths, including parser bugs against MCP configs or DSSE envelopes.

## Out of scope

- Vulnerabilities inside the MCP servers Reeve scans. Reeve reports
  what those servers declared and observed; fixing the upstream tool
  is the maintainer's problem.
- Issues requiring privileged local access beyond a normal developer
  workflow (root, kernel modules, debugger attach).
- Social engineering against the operator: clipboard hijack, shoulder
  surf, or AIBOM hand-edits after generation. Signing detects
  tampering; it does not stop a user from ignoring verification.
- Resource exhaustion from genuinely huge, legitimate inventories.
  Empty inventories are valid (ADR-0018).
- Runtime enforcement bypass. v1 reports only; runtime blocking is a
  v4 design goal.

## Schema, policy, and verification chain

The schema lives in [`schema/SPEC.md`](schema/SPEC.md), with JSON Schema
versions under [`schema/`](schema/). The policy library lives in
[`policies/`](policies/) and is evaluated as Rego compiled to Wasm.

The verification chain is Sigstore-first: release artifacts, surface
configuration bundles, and AIBOM outputs are verified through signed
bundles, hash checks, signer identities, and Rekor transparency where
available. The operational walkthrough is
[`docs/signing.md`](docs/signing.md).

## Trust boundaries

The three-layer architecture is enforced as a security property: no
layer reads another layer's internal state.

| Boundary         | Trusts                                  | Does not trust                                              |
|------------------|-----------------------------------------|-------------------------------------------------------------|
| Adapter -> Core  | Canonical AIBOM emitted by adapters.    | MCP server stderr, raw config bytes, parser internals.      |
| Core -> Policy   | Schema-validated, canonicalized AIBOM.  | Adapter internals, OS-specific evidence formats.            |
| Policy -> Output | Rego eval results, Wasm-compiled.       | Rego source intent - only syntax + Wasm compilation checked. |

The MCP adapter is the only layer that touches scanned servers or
third-party config files. The policy engine sees canonical facts only,
never OS-specific telemetry.

## Supply chain

Reeve's own provenance is part of the security claim:

- Built in GitHub Actions on Blacksmith CI runners (Ubuntu, macOS -
  ADR-0012).
- Release binaries, source tarball, installer script, and the
  pre-built policy Wasm bundle are signed as keyless cosign Sigstore
  bundles (`.bundle` sidecars), with signing identity bound to the
  GitHub Actions OIDC token. See ADR-0010.
- Transparency-log entries land in Rekor; the README documents the
  `cosign verify-blob` command users run before installing.
- AIBOM scan output uses the same primitive: DSSE in-toto Statement
  inside a Sigstore bundle (ADR-0004); cosign is a hard runtime
  dependency for real signing (ADR-0006).

No long-lived private keys exist anywhere in the release pipeline.

## Sandbox profile

**macOS.** MCP profiling runs the target server under a default-deny
`sandbox-exec` profile and parses unified-log denial records as
evidence. Both constraint and observation come from the OS sandbox.

**Linux.** Profiling uses Landlock filesystem enforcement plus seccomp
network denial when the kernel supports them; `strace` collects
syscall evidence inside the enforced run. If the kernel cannot create
a Landlock ruleset, Reeve falls back to an explicit observational
`strace` mode and emits a warning evidence record. The fallback is
not a sandbox and is not described as one. See ADR-0009.

**Windows.** Observational only. Future Windows profiling will use
ETW-backed event collection; AppContainer enforcement is a separate,
later track and is not implied by Windows output. The evidence stream
carries an explicit observational warning. See ADR-0017 (with
ADR-0014 through ADR-0016 for the binary-distribution and discovery
boundaries).

## Reporting a vulnerability

See [`SECURITY.md`](SECURITY.md) for the private disclosure channel,
acknowledgement window, and coordinated-disclosure policy. Do not
file public GitHub issues for security reports.

## Known limitations

- Windows enforcement is observational only in v1; no AppContainer
  sandbox yet (ADR-0017).
- Declared-vs-observed capability delta is informational by default.
  Whether a delta is a policy failure is decided by the operator's
  Rego, not by Reeve.
- Reeve validates Rego policies for syntax and Wasm compilation, not
  intent. A misauthored policy that under-reports findings will still
  compile and run.
- The Linux observational fallback records behavior without
  constraining it. Evidence is labeled accordingly.
- Empty discovery is a valid AIBOM (ADR-0018). Treat "zero MCP
  servers found" as a fact to verify against scope, not as a
  guaranteed clean state.
