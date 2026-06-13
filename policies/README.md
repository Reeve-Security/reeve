# Default Policies

Reeve ships with **fourteen** default Rego policies that catch
the most common AI supply-chain failure modes. Each policy is a
Rego file that evaluates an AIBOM document and produces allow /
deny / warn verdicts with a justification string.

**Policy numbering is stable:** once a policy is numbered, its
number never changes. New policies are appended with the next
available number. Policies #1–#10 are the original v1 design;
Policy #11 was added as a consequence of ADR-0005. Policy #12 was
added after ADR-0008 made granted permissions first-class evidence.
Policies #13 and #14 apply only to ADR-0019 sensitive-data reports,
which are separate from AIBOM sidecars and require explicit operator
opt-in before conversation/session-store metadata or contents are read.

Policies are compiled to a single WebAssembly bundle at build
time (`opa build -t wasm`) and signed with Sigstore before
distribution. Today's CLI embeds the default bundle at build time.
Runtime loading of externally fetched or customer-provided bundles is
post-launch.

## The v0.1 default policies

1. **Signature required for stdio servers in production targets.**
   Rejects unsigned stdio MCP servers when the scan target profile
   is `production` or `strict`.

2. **Publisher allowlist enforcement.** Rejects entries whose
   verified publisher identity is not in the configured allowlist.

3. **Declared versus observed capability match.** Flags entries
   where the observed capability set exceeds the declared set —
   the silent-capability-creep detector.

4. **Transport allowlist.** Rejects entries using a transport not
   permitted by the target profile. Example: block WebSocket in a
   federal profile.

5. **Maximum scan age.** Warns when an AIBOM has not been
   refreshed in more than the configured threshold. Default: seven
   days.

6. **No undeclared egress.** Rejects entries whose observed network
   egress targets are not in the declared capability set.

7. **No exec or subprocess without capability.** Rejects entries
   whose observed behavior includes `exec` or subprocess launches
   without the corresponding declared capability.

8. **Trusted package source.** Rejects entries installed from a
   registry or source not in the trusted list.

9. **No version downgrade across scans.** Flags entries whose
   installed version regressed since the previous scan — a common
   indicator of a dependency-confusion attack.

10. **No unsigned MCP server in strict profile.** Rejects any
    unsigned MCP entry when target profile is `strict`, regardless
    of transport.

11. **No unknown extension capability.** Flags entries that emit a
    capability id in an extension namespace not present in the
    consumer-configured extension-namespace allowlist. **Warn** by
    default; **deny** under `strict` profile. Introduced as a
    consequence of ADR-0005 (capability taxonomy). Extension
    namespaces are either registered adapter short forms (v0.1:
    `mcp`) or reverse-DNS namespaces with two or more DNS labels.
    Single-label namespaces outside the registry are reserved by
    the schema and cannot appear in conforming capability entries
    at all.

12. **Risky granted permission.** Flags high-risk saved approvals
    from `capabilities.granted[]`: destructive commands such as
    `rm`, elevation primitives such as `sudo` / `runas` /
    `osascript`, wildcard subprocess approvals such as Codex
    `approval_policy = "never"`, download commands that can become
    `curl | sh` install paths, broad filesystem write grants such as
    `/etc`, and secret-path read/write grants such as `/etc/shadow`
    or SSH credential paths. This policy evaluates persisted user or
    system approval state; it does not claim OS privilege bypass or
    runtime enforcement.

13. **Sensitive-data volume.** Warns when a separate opt-in
    sensitive-data report inventories more conversation/session files or
    bytes than the configured threshold. The warning is a retention and
    access-control review cue; it does not mark the endpoint unsafe.

14. **Sensitive secret pattern.** Warns on unsuppressed pattern findings
    in a separate opt-in sensitive-data report. The verdict says the
    finding needs human review, not that a leak is confirmed. It denies
    reports that claim content-pattern scanning but do not record which
    rule pack produced the findings.

## Sensitive-data report policy input

The first twelve policies evaluate AIBOM authority evidence through
`aibom policy check <scan-dir>`. Policies #13 and #14 evaluate the
separate ADR-0019 report through:

```console
aibom policy check-sensitive scan-123.sensitive-data.json
```

The policy input shape is:

```json
{
  "sensitiveDataReport": {
    "surfaces": [],
    "findings": [],
    "inputs": {}
  },
  "config": {
    "profile": "default",
    "sensitive_data_max_file_count": 1000,
    "sensitive_data_max_total_bytes": 104857600
  }
}
```

These policies never read raw conversation content. They only consume
the already-redacted sensitive-data report fields: surface counts,
total bytes, suppression state, rule-pack identity, and pattern class.
They remain separate from AIBOM authority policies so broad inventory
consumers do not accidentally ingest sensitive-report evidence.

## Authoring guidance

Each policy is a single `.rego` file named after its short
identifier (`no-undeclared-egress.rego`, `transport-allowlist.rego`,
etc.). Each file exports a `deny` rule, a `warn` rule, or both.
Verdicts must include a `justification` string explaining the
finding in human terms, and a `references` array linking to the
relevant AIBOM fields by JSON Pointer.

Compliance mapping tables (under `policies/mappings/`, to be added)
translate policy verdicts into NIST AI RMF, EU AI Act Article 52,
SOC 2, FedRAMP, and ISO 42001 controls.

## Status

Rego sources will be added here as step 3 of the v1 build order
(see `docs/build-order.md`). Policy work begins after the AIBOM
schema stabilizes, because each policy's rules must reference
stable schema paths.
