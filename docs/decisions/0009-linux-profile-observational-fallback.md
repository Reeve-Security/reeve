# ADR-0009: Linux profiling uses enforcement when available, with explicit observational fallback

- **Status:** Accepted 2026-04-26; amended 2026-04-28 by issue #49
- **Decides:** Linux v0.1 behavior-profiling semantics
- **Related:** `docs/v1-spec.md`, `docs/architecture.md`, `crates/aibom-scanner/src/mcp/profile/mod.rs`

## Context

Reeve's v1 specification names Landlock plus seccomp as the Linux
sandbox mechanism for MCP behavior profiling. The first Linux
implementation captured syscall evidence with `strace`. `strace` is
useful evidence, but it is not isolation: without kernel enforcement,
the profiled MCP server runs with the invoking user's privileges.

That difference affects Reeve's security properties. The project
thesis says scanners are an attack surface, and the decision-recording
protocol requires public-contract and security-property deviations to
be recorded as ADRs.

## Options considered

### A. Ship Linux profiling only after Landlock and seccomp enforcement

This preserves the original spec exactly. It avoids any ambiguity about
whether Linux profiling is isolated. The downside is that it blocks
Linux evidence collection entirely until a larger backend can be
implemented and tested.

### B. Treat `strace` as equivalent to sandbox enforcement

This keeps the implementation simple and produces useful filesystem,
network, and exec observations. It is rejected because it is inaccurate:
`strace` observes behavior but does not restrict it.

### C. Keep `strace` as an explicit observational fallback *(chosen for 2026-04-26)*

This keeps Linux behavior evidence available while making the lack of
enforcement visible in code, documentation, and emitted profile
evidence. The profiler must keep `strace` output separate from server
stderr, must not parse arbitrary stderr as syscall evidence, and must
emit a warning that Linux profiling is observational without
Landlock/seccomp enforcement.

### D. Use Landlock/seccomp when available; keep `strace` as event collection *(chosen by 2026-04-28 amendment)*

This preserves the existing parser and evidence flow while adding
kernel enforcement before the profiled server starts. `strace` remains
the event collector, not the isolation boundary. Landlock restricts
filesystem reads and writes to the executable/runtime/package allowlist
and profiler tempdir. seccomp denies network socket operations. If the
kernel cannot create a Landlock ruleset, the profiler falls back to the
explicit observational mode from option C and records the warning.

## Decision

Reeve's Linux MCP profiler uses Landlock filesystem enforcement and
seccomp network denial when the kernel supports those primitives.
`strace` is still used to collect syscall evidence from the enforced
run, so policy evidence stays in the same format.

When Landlock/seccomp setup is unavailable, Reeve may run the explicit
`strace` observation fallback. This fallback is not a sandbox and must
not be described as enforcement. Each fallback Linux profile run records
a warning evidence item stating that Linux profiling used observation
without Landlock/seccomp enforcement.

The fallback is limited to the MCP adapter profiling path. It does not
change the v1 adapter scope, schema contract, policy engine, or layer
boundaries.

## Rationale

The amended choice preserves useful v0.1 evidence collection while
making the normal Linux path match the security claim more closely. The
scanner can report observed file reads, network attempts, and subprocess
launches on Linux while the profiled server is restricted by kernel
policy. If the host cannot enforce that policy, the output tells
consumers that those observations came from tracing rather than enforced
isolation.

The implementation must keep the two OS parser paths mutually
exclusive. macOS unified-log and `sandbox-exec` stderr lines are parsed
as sandbox denial evidence. Linux `strace` files are parsed as syscall
trace evidence. MCP server stderr is not syscall input.

## Plain-language summary

On macOS, Reeve currently runs MCP servers inside an operating-system
sandbox and reads the sandbox denial logs. That means macOS profiling
both limits what the server can do and records what it tried to do.

On Linux, Reeve now tries to lock down the profiled server with kernel
controls before it invokes MCP tools. Landlock limits filesystem access.
seccomp denies network socket operations. Reeve still watches the run
with `strace` so it can turn denied attempts into AIBOM evidence.

If the host kernel does not support the enforcement path, Reeve says so
in the evidence instead of pretending tracing is a sandbox.

## Consequences

- **This decision commits the project to:** Landlock/seccomp on Linux
  when available; warning on fallback observational profile runs;
  separate macOS and Linux parsers; no parsing of MCP server stderr as
  Linux syscall trace evidence.
- **This decision unblocks:** Linux evidence collection with filesystem
  and network enforcement on supported kernels.
- **This decision forecloses:** describing the fallback Linux path as a
  sandbox or enforcement mechanism.
- **This decision defers:** fuller subprocess prevention on Linux beyond
  network denial and filesystem containment. The initial executable is
  allowed to start; later subprocess execution is still captured as
  evidence.

## References

- `docs/v1-spec.md`
- `docs/architecture.md`
- `crates/aibom-scanner/src/mcp/profile/mod.rs`
