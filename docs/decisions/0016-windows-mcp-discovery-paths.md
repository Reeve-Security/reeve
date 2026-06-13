# ADR-0016: Windows MCP discovery is config-file only

- **Status:** Accepted 2026-04-29
- **Decides:** Issue #57 Track 2 Windows discovery paths
- **Related:** ADR-0011, ADR-0014, ADR-0015, issue #57

## Context

ADR-0014 proved the Windows release-build lane. ADR-0015 promoted that
lane into a signed Windows release artifact, but deliberately avoided
claiming Windows endpoint behavior.

Issue #57 Track 2 asks for the next slice: Windows MCP config-file
discovery. This is not Windows sandbox support. It only teaches the MCP
adapter to read the Windows locations where already-supported agent
products store MCP configuration.

The scope guard still matters. `docs/v1-spec.md` defers Windows sandbox
support to v1.1. It does not forbid reading static MCP config files from
a Windows user profile. The public contract must therefore say exactly
what exists: Windows config-file discovery exists; Windows profiling,
ETW collection, AppContainer, and sandbox enforcement do not.

## Options considered

### A. Keep Windows binary distribution only

Ship the signed Windows zip but leave Windows discovery for later.

Pros: smallest change. Cons: the demo fleet can install Reeve on
Windows but cannot show useful Windows inventory evidence.

### B. Add Windows discovery and observational profiling together

Add config-file discovery and ETW-backed observational profiling in one
large PR.

Pros: stronger endpoint story. Cons: mixes a low-risk path-discovery
change with a higher-risk Windows tracing design. It also forces the
ADR for Windows observational-vs-enforced behavior before the path
contract is useful.

### C. Add Windows config-file discovery only *(chosen)*

Add the Windows MCP config paths for supported surfaces, document them
in `docs/scope.md`, test discovery from a Windows-shaped fixture tree,
and keep profiling/sandbox work deferred.

Pros: useful customer-visible progress, low blast radius, and aligned
with the existing MCP adapter. Cons: Windows capability evidence remains
limited to declared/configured facts until observational profiling lands.

## Decision

Reeve supports Windows MCP config-file discovery for the documented
paths in `docs/scope.md`.

The Windows-specific paths added in this slice are:

```text
AppData/Roaming/Claude/claude_desktop_config.json
AppData/Roaming/Code/User/mcp.json
AppData/Roaming/Code/User/settings.json
```

The existing home-rooted dot paths also apply when the scan target is a
Windows user profile:

```text
.cursor/mcp.json
.continue/config.yaml
.continue/config.yml
.continue/config.json
.claude.json
.claude/settings.json
.codex/config.toml
.factory/mcp.json
```

Zed has no Windows build, so Reeve does not add a Windows Zed path.

This decision does not add Windows profiling. It does not add Windows
sandbox enforcement. AppContainer remains deferred to the Windows
sandbox-support work.

## Rationale

Windows config files are static discovery inputs. They fit inside the
existing MCP protocol-adapter layer and communicate through the same
canonical AIBOM entries as macOS and Linux discovery. No schema change,
policy-engine change, or runtime enforcement change is needed.

Keeping this slice separate preserves product truth. A Windows scan can
now say "these MCP servers are registered in Windows config files." It
cannot yet say "these behaviors were observed under Windows profiling"
or "these attempted operations were denied by Windows enforcement."

That distinction is the same evidence-not-claims posture Reeve already
uses for Linux fallback behavior in ADR-0009 and Windows release
distribution in ADR-0015.

## Plain-language summary

This change lets Reeve find MCP servers on Windows by looking in the
normal Windows config-file locations.

It is like reading a list of installed tools from the user's settings
folder. Reeve can now report what those Windows config files say is
registered. It does not yet run those tools in a Windows sandbox or
watch what they do.

That split is important. Customers can use Windows discovery evidence
without confusing it with Windows enforcement evidence. The release can
truthfully say Windows config discovery works, while still saying
Windows profiling and sandboxing are not done.

## Consequences

- **This decision commits the project to:**
  - listing every Windows MCP config path in `docs/scope.md`,
  - testing Windows-shaped user-profile discovery fixtures,
  - treating Zed as excluded on Windows until Zed ships Windows support,
  - keeping Windows discovery claims separate from Windows profiling and
    sandbox claims.
- **This decision unblocks:**
  - Windows demo-fleet inventory scans,
  - Windows path-resolution tests in CI,
  - later Windows observational profiling work against known discovered
    servers.
- **This decision forecloses:**
  - treating the signed Windows zip as binary-only once this track lands,
  - implying that Windows discovery includes profiling or enforcement.
- **This decision defers:**
  - Windows observational profiling,
  - ETW collection,
  - Windows AppContainer enforcement,
  - Windows sandbox support.

## References

- [ADR-0011: User-defined custom MCP surfaces](0011-custom-surfaces.md)
- [ADR-0014: Track 0 adds a Windows release-build target without Windows discovery or profiling](0014-windows-release-track0.md)
- [ADR-0015: Windows binary distribution starts without Windows discovery or profiling](0015-windows-binary-distribution.md)
- `docs/scope.md`
- Issue #57
