# ADR-0015: Windows binary distribution starts without Windows discovery or profiling

- **Status:** Accepted 2026-04-29
- **Decides:** Issue #57 Track 1 Windows release binary distribution
- **Related:** ADR-0010, ADR-0014, issue #57

## Context

ADR-0014 proved the Windows release-build lane: Blacksmith Windows
runners, Rust MSVC toolchain, cargo-dist local artifact generation, and
cosign installer availability all work for `x86_64-pc-windows-msvc`.

Issue #57 Track 1 asks for the next step: make the Windows binary a real
release artifact. The key boundary is product truth. A Windows binary is
not the same thing as Windows discovery, Windows profiling, or Windows
sandbox enforcement.

## Options considered

### A. Keep Windows as probe-only

Continue running only the Track 0 workflow and do not document Windows
release artifacts.

Pros: lowest risk. Cons: does not satisfy enterprise distribution
pressure; demo fleet cannot install a first-party Windows binary.

### B. Ship Windows binary with full Windows support claims

Publish `aibom-cli-x86_64-pc-windows-msvc.zip` and describe Windows as a
supported endpoint platform.

Pros: strongest marketing line. Cons: false. Discovery paths,
observational profiling, and AppContainer enforcement are not present
yet. This would violate Reeve's evidence-not-claims posture.

### C. Ship signed Windows binary, explicitly scoped to binary distribution *(chosen)*

Keep `x86_64-pc-windows-msvc` in cargo-dist targets so the next tagged
release publishes `aibom-cli-x86_64-pc-windows-msvc.zip` with a
verifiable cosign `.bundle`. Document install and verification for that
archive, while stating that Windows discovery, Windows profiling, and
Windows sandbox enforcement remain follow-up tracks.

Pros: unblocks Windows packaging and demo-fleet install mechanics
without overstating support. Cons: users can run the binary before
Windows-specific discovery is complete, so docs must make the limitation
plain.

## Decision

Reeve will publish a signed Windows archive starting with the next tagged
release after `v0.1.2`.

The artifact name is:

```text
aibom-cli-x86_64-pc-windows-msvc.zip
```

It is signed by the existing release host job, which signs every
`.zip` artifact with `cosign sign-blob --yes --bundle`. Verification
uses the same GitHub Actions OIDC identity regex as the macOS/Linux
archives.

This decision does not add Windows discovery. It does not add Windows
profiling. It does not add Windows sandbox enforcement. AppContainer
work remains deferred.

In short: it does not add Windows discovery, does not add Windows profiling,
and does not add Windows sandbox enforcement.

## Rationale

Track 0 answered the runner/toolchain question. Track 1 turns that into
a release contract customers can verify. It keeps scope narrow: a
Windows executable exists and is signed; Windows endpoint behavior is
still governed by later issue #57 tracks.

The existing release-signing workflow already signs `*.zip`, so no
separate Windows signing path is needed. The release trust chain remains
the same: GitHub Actions OIDC, Fulcio, Rekor, cosign bundle, and the
workflow identity bound to `Reeve-Security/reeve`.

## Plain-language summary

We can now build the Windows executable in CI. That means the next
release can include a Windows zip next to the macOS and Linux archives.

That zip will be signed the same way the other release files are signed.
A customer can download `aibom-cli-x86_64-pc-windows-msvc.zip`, download
its `.bundle`, and verify it with `cosign verify-blob`.

This does not mean the Windows product story is done. It means Windows
machines can receive a first-party Reeve binary. The Windows-specific
scanner paths and Windows profiling evidence still have to land before
Reeve can claim real Windows endpoint coverage.

## Consequences

- **This decision commits the project to:**
  - publishing `aibom-cli-x86_64-pc-windows-msvc.zip` on future tagged
    releases,
  - signing that zip with a verifiable cosign `.bundle`,
  - documenting PowerShell install and verification commands.
- **This decision unblocks:**
  - Windows packaging validation,
  - Windows discovery implementation against a first-party binary,
  - demo-fleet Windows endpoint install mechanics.
- **This decision forecloses:**
  - treating Windows release artifacts as proof of Windows discovery,
    profiling, or sandbox support.
- **This decision defers:**
  - Windows path discovery,
  - Windows observational profiling,
  - Windows AppContainer enforcement.

## References

- [ADR-0010: Release artifacts are signed as keyless cosign bundles](0010-release-artifact-signing.md)
- [ADR-0014: Track 0 adds a Windows release-build target without Windows discovery or profiling](0014-windows-release-track0.md)
- Issue #57
