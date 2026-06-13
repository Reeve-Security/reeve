# ADR-0026: AIBOM v0.3 accepts absolute Windows filesystem path qualifiers

- **Status:** Accepted
- **Date:** 2026-05-25
- **Decides:** How AIBOM represents Windows filesystem paths in
  `fs:read` and `fs:write` capability qualifiers.
- **Related:** ADR-0002, ADR-0005, ADR-0016, ADR-0017

## Context

AIBOM v0.1 and v0.2 constrained filesystem `qualifiers.path` to
absolute POSIX paths matching `^/`. That was valid while Windows support
was limited to binary distribution and config-file discovery.

Windows scans now emit filesystem MCP roots such as
`C:\Users\alice` and observational filesystem paths from ETW. Those are
real endpoint evidence. If Reeve emits them into a v0.2 artifact, the
artifact fails its own schema validation before `verify` or
`policy check` can reach useful results.

Editing v0.2 in place would violate ADR-0002's immutable schema URL
rule. The contract needs a new schema version.

## Decision

Publish `schema/aibom-v0.3.0.json`. For `fs:read` and `fs:write`,
`qualifiers.path` accepts:

- POSIX absolute paths beginning with `/`;
- Windows drive-absolute paths beginning with a drive letter, colon, and
  slash or backslash, such as `C:\Users\alice` or `D:/work`;
- Windows UNC paths beginning with a server and share, such as
  `\\fileserver\share`.

The capability id remains `fs:read` / `fs:write`. We do not introduce a
Windows-specific qualifier key. Policy and downstream consumers continue
to key on the stable capability id and inspect path grammar as needed.

Reeve emits v0.3 when a scan contains any filesystem capability path in
Windows drive or UNC form. POSIX-only scans may continue to emit older
schema versions when no newer field shape is needed.

## Consequences

- v0.1 and v0.2 stay immutable and POSIX-only.
- v0.3 is a cross-OS schema contract, not a Windows-only edition.
- `verify`, `validate-artifacts`, and `policy check` must auto-select
  the schema from the artifact's `$schema` / `aibom.schemaVersion`
  instead of assuming v0.1.
- Validator diagnostics map invalid filesystem paths to
  `capability.qualifiers.path_invalid` rather than opaque
  `schema.generic_violation` where possible.
- Policy rules can reason over Windows user-profile roots, drive roots,
  and secret-like paths without losing source path fidelity.

## Plain-Language Summary

Reeve's schema versions are not operating-system editions. v0.3 is the
same AIBOM contract with one necessary expansion: filesystem paths can
now be written in the path forms that Windows actually uses. macOS and
Linux paths still work the same way.
