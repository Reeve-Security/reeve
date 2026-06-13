# ADR-0017: Windows profiling starts as explicit observational evidence

- **Status:** Accepted 2026-04-29
- **Decides:** Issue #57 Track 3 Windows profiling boundary
- **Related:** ADR-0009, ADR-0015, ADR-0016, `docs/scope.md`, `crates/aibom-scanner/src/mcp/profile/mod.rs`

## Context

Issue #57 has already established the first two Windows truths: Reeve can
publish a signed Windows binary (ADR-0015), and it can read Windows MCP
config-file locations (ADR-0016). The next product question is whether
Reeve can produce Windows behavior evidence without waiting for a full
Windows sandbox-enforcement backend.

Today the MCP profiler runs only on macOS and Linux. On other operating
systems, `crates/aibom-scanner/src/mcp/profile/mod.rs` returns
`sandbox profiling is unsupported on this OS`. That is accurate for the
current implementation, but it leaves the Windows roadmap ambiguous.

Windows has observation mechanisms such as ETW, process-launch events,
and network telemetry that can capture behavior facts before
AppContainer enforcement exists in Reeve. Those sources can be useful
evidence. They are not the same thing as a sandbox. The project needs a
public design boundary before implementation work starts so later PRs do
not overstate what Windows profiling means.

## Options considered

### A. Wait for AppContainer before adding any Windows profiling

This preserves the strongest security story because every Windows
profile would be both observed and constrained. It is rejected for this
track because it blocks useful behavior evidence and keeps Windows
behind a larger enforcement project.

### B. Treat ETW-backed observation as equivalent to sandbox enforcement

This would let the product say that Windows profiling exists quickly. It
is rejected because it is false. Observation records what happened; it
does not constrain what the profiled MCP server was allowed to do.

### C. Start with explicit observational profiling; keep enforcement separate *(chosen)*

This lets future Windows profiling produce behavior evidence through
ETW-backed or equivalent operating-system observation while keeping
AppContainer as a separate enforcement track. The output, CLI wording,
and docs must say "observational" and must not imply sandbox
enforcement.

## Decision

When Reeve adds Windows MCP behavior profiling, the first shippable form
will be explicit observational profiling rather than sandbox
enforcement.

That observational implementation may use ETW-backed event collection or
equivalent Windows-native observation sources to produce canonical
observed capabilities and evidence records through the existing MCP
adapter interface. It must label the run as observational, must not
claim that the server was contained, and must keep AppContainer
enforcement as a later track.

If Windows telemetry is unavailable, requires permissions Reeve does not
have, or loses events because buffers overflow, Reeve must emit an
explicit warning evidence record and must not turn that run into a clean
profile. The warning must be recoverable from the AIBOM evidence stream,
not only from terminal output.

This ADR does not add Windows profiling code. It does not change the
schema, policy engine, or three-layer architecture. It fixes the public
contract for future implementation work.

## Rationale

This choice preserves Reeve's evidence-not-claims posture. A Windows
scan can truthfully say "we observed these process, file, and network
events" before it can truthfully say "we constrained the server inside a
Windows sandbox".

The decision also matches the existing architectural boundary. The MCP
adapter can emit the same canonical observed-capability and evidence
structures regardless of whether the event source is macOS unified logs,
Linux `strace` plus kernel enforcement, or future Windows observation.
The policy engine still consumes canonical facts rather than OS-specific
internals.

Finally, separating observation from enforcement keeps the next Windows
slice small. AppContainer, token restrictions, filesystem/network deny
rules, and enforcement-verdict semantics remain hardening work. They do
not need to block the first truthful Windows behavior-evidence slice.

## Plain-language summary

Reeve already knows how to look at Windows MCP config files. The next
question is whether it can also say what those tools actually did on a
Windows machine.

The answer for the next slice is: yes, but only as observation. Reeve
can eventually watch a Windows MCP server and record its behavior
without pretending that watching is the same thing as locking it in a
box.

That distinction matters because customers and auditors will read the
docs literally. If the product says "sandbox profiling" when it only
means "we watched some events", the product is making a stronger safety
claim than the implementation earned.

This ADR keeps the story honest. Windows behavior evidence can land
before Windows containment does. Later AppContainer work can strengthen
the guarantees without changing the core schema or pretending the first
slice was more protective than it was.

If Windows cannot provide enough telemetry on a given machine, Reeve
must say that plainly in the evidence. A partial or unavailable trace is
still useful operational information, but it is not a clean behavior
profile.

## Consequences

- **This decision commits the project to:** labeling future Windows
  profiling as observational until AppContainer enforcement exists;
  keeping Windows event collection inside the MCP adapter boundary;
  warning in AIBOM evidence when telemetry is unavailable, insufficient,
  or lossy; and documenting the distinction anywhere Windows profiling
  is mentioned.
- **This decision unblocks:** the next implementation PR for Windows
  behavior evidence, ETW-backed fixture capture, and customer-visible
  documentation about the Windows profiling roadmap.
- **This decision forecloses:** calling ETW-backed observation a
  sandbox, an enforcement boundary, or proof that Windows containment is
  implemented.
- **This decision defers:** Windows AppContainer enforcement, deny-rule
  semantics, and exact implementation details for the eventual
  enforcement-backed profiler.

## References

- [ADR-0009: Linux profiling uses enforcement when available, with explicit observational fallback](0009-linux-profile-observational-fallback.md)
- [ADR-0015: Windows binary distribution starts without Windows discovery or profiling](0015-windows-binary-distribution.md)
- [ADR-0016: Windows MCP discovery is config-file only](0016-windows-mcp-discovery-paths.md)
- `docs/scope.md`
- `crates/aibom-scanner/src/mcp/profile/mod.rs`
- Issue #57
