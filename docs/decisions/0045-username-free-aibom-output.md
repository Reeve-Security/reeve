# ADR-0045: Every serialized host path in AIBOM/CDX output is username-free

- **Status:** Accepted 2026-06-09
- **Decides:** Redaction coverage for host paths in scanner output (issue #463)
- **Related:** ADR-0008, ADR-0026, ADR-0032

## Context

ADR-0008 introduced `redact_home_identity()`: grant path qualifiers replace
the home-directory segment with `<redacted-home>` while keeping the absolute
path shape, so policy can still reason about scope without the AIBOM leaking
an OS username.

Issue #463 found that this redaction was applied at only one of the sites
that serialize host paths. Registration evidence references, `file://`
granted-permission evidence references, cowork `storePath` / `manifestPath` /
`settingsPath` qualifiers, extension `installRoot` qualifiers, npm dependency
manifest properties, declared filesystem-root qualifiers, exec `cmd`
qualifiers carrying absolute commands, sandbox-profile event references, and
the scan target description all emitted the raw home path. An AIBOM shared
with an auditor or uploaded to a ticket therefore leaked the endpoint's OS
username.

## Options considered

### A. Redact only grant qualifiers (status quo)

Pros: no change. Cons: the username still leaks through every other
serialized path, so the privacy property ADR-0008 claimed does not hold for
the document as a whole.

### B. Redact every serialized host path *(chosen)*

Every host path that is serialized into the AIBOM or CDX output passes
through `redact_home_identity()` at the serialization site. Paths used
internally — file reads, discovery joins, dedupe keys, error contexts — stay
raw.

Pros: one rule, easy to audit, testable with a whole-document guard. Cons:
evidence references no longer match the literal on-disk path; a human
correlating evidence to a file must substitute their own username.

### C. Strip paths entirely from output

Pros: maximal privacy. Cons: destroys the evidence value (scope, surface
location) that ADR-0008 deliberately preserved.

## Decision

Every host path serialized into AIBOM or CycloneDX output — grant and
declared `path` qualifiers, `storePath`, `manifestPath`, `settingsPath`,
`installRoot`, `cmd` qualifiers, `aibom:dependencyManifest` properties,
registration and `file://` evidence references, sandbox-profile event
references, and `scan.target.description` — passes through
`redact_home_identity()`. The absolute path form is retained per ADR-0008.

Matching is component-based: the segment following a `Users` or `home` path
component is replaced with `<redacted-home>`, wherever that component occurs
in the path. This covers `/Users/x`, `/home/x`, `C:\Users\x`, and prefixed
home roots such as WSL `/mnt/c/Users/x` or test-harness homes like
`<tmp>/Users/x`. Over-redaction of rare non-home `…/home/<segment>` paths is
accepted; under-redaction is the bug.

Paths that are only used internally (reading config files, locating
packages, deduplication keys, error messages) are not redacted.

## Rationale

Reeve's output is designed to be shared — with auditors, in tickets, in a
central corpus. A document-wide privacy property is only useful if it holds
for the whole document, so the redaction rule must be "everywhere at the
serialization boundary," not "at the sites someone remembered." A whole-
document end-to-end test (`serialized_scan_output_never_contains_home_username`)
now asserts the property over the full serialized AIBOM and CDX bytes, which
keeps future path-emitting sites honest.

## Plain-language summary

A Reeve scan report lists files and folders so a reviewer can see what an AI
tool was allowed to touch. Those paths usually start with the computer
owner's username (`/Users/denis/...`). Before this decision, some parts of
the report hid the username and other parts did not, so sharing a report
quietly revealed who owned the machine. Now every path that ends up in the
report has the username replaced with `<redacted-home>`, while the rest of
the path is kept so the report stays useful. Paths Reeve uses privately on
the machine, to do its work, are untouched.

## Consequences

- **This decision commits the project to:** routing every new serialized
  path site through `redact_home_identity()` and extending the end-to-end
  guard test when new output fields carry paths.
- **This decision unblocks:** sharing AIBOM/CDX artifacts (demos, corpus,
  support tickets) without leaking endpoint usernames.
- **This decision forecloses:** byte-exact correlation between an evidence
  reference and the on-disk source path; consumers must treat
  `<redacted-home>` as the home segment.
- **This decision defers:** redaction of non-home identifying path segments
  (hostnames in UNC shares, project names) — out of scope for #463.

## Residual patterns (second pass)

Live re-verification on a real host after the first pass found two encoded
path forms that bypass component-based matching; both are now covered:

- **Reference fragments embedding raw paths.** Codex CLI granted-evidence
  fragments carry absolute project paths as TOML table keys
  (`…config.toml#projects["/Users/x/projects/y"].approval_policy`). The full
  formatted reference string is now redacted, not just its source-path part.
- **Cursor dash-encoded project directories.** Cursor flattens an absolute
  project path into one dash-joined directory name under `.cursor/projects`
  (`Users-x-projects-y`). The segment directly under `.cursor/projects` is
  rewritten to `Users-<redacted-home>-projects-y`; dash-joined names anywhere
  else are untouched.

## References

- Issue #463
- `crates/aibom-scanner/src/mcp/mod.rs` (`redact_home_identity`)
- `crates/aibom-scanner/src/mcp/output.rs`
- `crates/aibom-scanner/tests/redaction_guard.rs`
- ADR-0008 (`granted` source and redacted grant scopes)
