# ADR-0008: Add `granted` capability source and `granted-permission` evidence kind

- **Status:** Accepted 2026-04-25
- **Decides:** ADR-0005 amendment — third capability source value + new evidence kind
- **Related:** ADR-0002 (versioning), ADR-0005 (capability taxonomy), task #19

## Context

ADR-0005 defines two capability `source` values: `declared` (what the tool claims it can do) and `observed` (what the tool actually did when sandboxed). The founder identified a third category that is neither declared nor observed: **granted permissions** — the permissions a user has explicitly approved and saved in their AI assistant's configuration.

When a user clicks "always approve" in Claude Code, Cursor, Codex CLI, or similar tools, that approval persists in the tool's configuration files. These saved permissions represent **effective authority** that the AI agent has on the machine, categorically different from:
- `declared`: what the tool's publisher claims it needs
- `observed`: what the tool did during a specific sandbox run
- `granted`: what the user has permanently authorized, often at a scope broader than any single invocation

Compromised agents inherit every "always-approve" permission silently. Inventorying these permissions is prerequisite for task #19.

## Options considered

### A. Treat granted permissions as a subtype of declared

Add a boolean flag `userApproved: true` on existing `declared` capabilities.

- **Pros:** no schema version bump; minimal code change.
- **Cons:** conflates two semantically different concepts. A declared capability (`fs:read`) is a publisher claim; a granted permission is a user authorization. A tool might declare `fs:read` but the user might grant `fs:write` (or vice versa). The delta between declared and granted is itself a policy finding. Merging them loses that signal.
- **Rejected.** The distinction is load-bearing for safety analysis.

### B. Invent a new top-level field (parallel to capabilities)

Add `grantedPermissions[]` as a sibling to `capabilities` at the component level.

- **Pros:** completely separate namespace; no risk of confusing with capability evidence.
- **Cons:** duplicates the capability structure (id, qualifiers, evidence) in a new place. Policy engine would need to merge two arrays for every rule. Adds complexity without benefit.
- **Rejected.** The capability structure already handles id + qualifiers + evidence + source. A third source value uses the existing machinery.

### C. Add `granted` as a third `source` value + new evidence kind *(chosen)*

Extend the `source` enum from `["declared", "observed"]` to `["declared", "observed", "granted"]`. Add `granted-permission` as a new `evidenceRecord.kind`. Schema bumps from 0.1.0 to 0.2.0 per ADR-0002.

- **Pros:** uses the existing capability machinery; policies can evaluate `granted` alongside `declared` and `observed` with no structural change; the delta `granted - declared` is a first-class finding (over-permissioning); the delta `declared - granted` is also a finding (user blocked a declared capability).
- **Cons:** requires a schema version bump (0.1.0 → 0.2.0) because the enum change is a structural contract change per ADR-0002. All v0.1.0 consumers must be updated to accept 0.2.0.
- **Accepted.** The engineering cost of the version bump is lower than the semantic confusion of options A and B.

## Decision

Reeve extends ADR-0005 with a third capability source value `granted` and a new evidence kind `granted-permission`. The AIBOM schema version bumps from **0.1.0 → 0.2.0** per ADR-0002's pre-1.0 rule (minor bump = compatibility boundary).

When a saved grant uses a local filesystem path as its scope, Reeve serializes
the path only after redacting the operating-system home/user segment. The
redacted value must remain a schema-valid absolute path, so `/Users/alice/repo`
becomes `/Users/<redacted-home>/repo`, `/home/alice/repo` becomes
`/home/<redacted-home>/repo`, and `C:\Users\alice\repo` becomes
`C:\Users\<redacted-home>\repo`. Non-home absolute scopes such as `/`,
`/workspaces/acme`, or UNC shares remain unchanged. This preserves the grant
scope needed for policy while stripping the username from the shared AIBOM.

### Schema changes (aibom-v0.2.0.json)

1. **`capability.source` enum:** `["declared", "observed", "granted"]`
2. **New `capabilityGranted` schema:** identical shape to `capabilityDeclared` / `capabilityObserved` but with `source: {"const": "granted"}`.
3. **`evidenceRecord.kind` enum:** add `"granted-permission"`.
4. **`$schema` URL:** `https://aibom.example/schemas/aibom-v0.2.0.json`
5. **`aibom.schemaVersion`:** `"0.2.0"`

### `granted-permission` evidence kind structure

A `granted-permission` evidence record references a saved user approval in an AI assistant configuration. It carries:

| Field | Type | Description |
|---|---|---|
| `grantedBy` | string enum | `"user"` (interactive click) or `"system"` (enterprise policy / admin pre-approval) |
| `grantedAt` | ISO 8601 timestamp | When the approval was recorded |
| `grantScope` | string enum | `"global"` (applies to all projects), `"project"` (applies to one project/workspace), `"tool"` (applies to one specific tool instance) |
| `revocable` | boolean | Whether the user can revoke the approval without reinstalling the tool |

These fields are OPTIONAL on the evidence record's `qualifiers` object (the evidence record's `reference` field points to the config file; `qualifiers` carries the parsed metadata).

## Rationale

The three-source model matches how authorization actually works in AI assistant deployments:

- **Declared** = what the publisher thinks the tool needs. Trust but verify.
- **Observed** = what the tool did in one specific run. Ephemeral; may not cover all code paths.
- **Granted** = what the user has permanently authorized. Persistent; represents the attack surface a compromised agent actually inherits.

A security reviewer needs all three. A policy rule like "no global filesystem write grants without declared `fs:write`" requires `granted` and `declared` in the same document. A rule like "flag tools with `secret:read` granted but never declared" requires the `granted - declared` delta.

Using the existing capability structure (just adding a source value) keeps the policy engine, validator, and report generators unchanged except for the schema version negotiation.

## Plain-language summary

When you install an AI assistant tool, the tool tells you what it needs — that's the **declared** capability. When Reeve runs the tool in a sandbox to see what it actually does, that's the **observed** capability. But there's a third thing: the permissions you, the user, have clicked "always approve" on. Those saved approvals are **granted** capabilities.

Here's why granted is different. Declared is what the tool's publisher claims. Observed is what the tool did during one specific test run — it might not have exercised every code path. But granted is what the tool is **allowed** to do, permanently, on your machine. If someone compromises that tool, they get every granted permission instantly, without having to trick you into clicking approve again.

Reeve already tracked declared and observed. This decision adds granted as a third category. The schema version bumps from 0.1.0 to 0.2.0 because adding a new enum value is a structural contract change. But the shape of the data is the same — it's still a capability with an ID, some qualifiers, and a list of evidence references. The only difference is the label on the source field.

## Consequences

- **This decision commits the project to:**
  - Three capability sources forever (`declared`, `observed`, `granted`).
  - A new `granted-permission` evidence kind with optional metadata fields (`grantedBy`, `grantedAt`, `grantScope`, `revocable`).
  - Home/user identity redaction for saved-grant filesystem path qualifiers
    while preserving schema-valid absolute scope.
  - Validator must accept both `0.1.0` and `0.2.0` documents.
  - Task #19 (parse saved approvals from 6+ assistant config formats) is unblocked.
- **This decision unblocks:**
  - Task #19: inventory saved/approved agent permissions.
  - New policy rules: over-permissioning (granted > declared), missing declarations (declared > granted), unrevocable high-risk grants.
- **This decision forecloses:**
  - Treating granted permissions as a variant of declared or observed.
  - Adding granted permissions as a parallel top-level field instead of a source value.
- **This decision defers:**
  - The actual config-file parsers for each assistant surface (Claude Code, Cursor, Codex, Continue, Zed, Aider, Factory) — that's task #19.
  - Domain registration for `$schema` URLs — still `aibom.example` placeholder.

## References

- [ADR-0002: Schema versioning policy](0002-schema-versioning-policy.md)
- [ADR-0005: Capability taxonomy](0005-capability-taxonomy.md)
- `schema/aibom-v0.1.0.json` → `schema/aibom-v0.2.0.json`
- `schema/SPEC.md`
- Task #19 (granted permissions inventory)
