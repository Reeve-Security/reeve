# ADR-0024: GitHub Releases plus Sigstore are the canonical distribution path

- **Status:** Accepted 2026-05-18
- **Decides:** Reeve's v0.1 release distribution strategy after Apple Developer ID approval removed the need for a Homebrew-first no-Apple workaround.
- **Related:** ADR-0004, ADR-0006, ADR-0010, ADR-0015, Issue #147, Issue #196

## Context

Reeve's release path had drifted toward Homebrew because Apple Developer
ID approval was still pending. That made Homebrew look strategic: it
seemed like the cleanest way to give macOS users an install path that
did not depend on Apple notarization.

That premise changed. The Apple Developer account has been approved.
The project still has not wired Developer ID certificates or
notarization into the release workflow, but Apple approval is no longer
an external blocker.

The security root for Reeve distribution was never Homebrew. It is the
GitHub Release artifact plus the adjacent Sigstore bundle. ADR-0004
defines the signature envelope for evidence artifacts, ADR-0006 explains
why Reeve shells out to the official `cosign` CLI where needed, and
ADR-0010 applies keyless cosign signing to release artifacts.

The repository state contradicted that model: the README described
Homebrew as the primary no-Apple macOS path, `dist-workspace.toml`
configured Homebrew formula generation and publishing, and the generated
release workflow contained a Homebrew formula publish job. This created
a maintenance obligation for a tap repository and token before the
project needed one.

## Options considered

### A. Keep Homebrew as the primary macOS path

Continue treating a Reese Skye tap install command as the preferred
macOS install flow and require a tap repository plus tap token before
launch.

Pros: familiar for macOS developers; short install command once the tap
exists.

Cons: makes a convenience channel look like the trust root; adds tap and
token maintenance; keeps a no-Apple workaround framing after Apple
approval; distracts from the signed GitHub Release path that auditors can
verify directly.

### B. Remove Homebrew entirely forever

Delete all Homebrew references and decide the project will never publish
a formula.

Pros: simplest release surface; no tap maintenance.

Cons: overcorrects. A Homebrew tap may still be useful later as a
convenience wrapper around signed GitHub Release artifacts.

### C. Make GitHub Releases plus Sigstore canonical; defer Homebrew and notarization *(chosen)*

Use `cargo-dist` to build GitHub Release archives and the shell
installer. Sign release artifacts with keyless Sigstore bundles in the
release workflow. Keep Homebrew out of the active release config until
the project explicitly chooses to maintain a tap. Keep Apple Developer
ID notarization in issue #147 until certificates and notarization are
ready to wire into CI.

Pros: matches the actual security model; keeps the active release path
small; avoids tap/token churn; preserves Homebrew as a future
convenience; leaves notarization tracked without blocking current
launch work.

Cons: macOS users do not get a `brew install` path yet; first-run
Gatekeeper quarantine handling may still require a documented manual
step until notarization lands.

## Decision

Adopt Option C.

The canonical v0.1 distribution path is:

1. GitHub Actions builds release archives and the shell installer with
   `cargo-dist`.
2. The release workflow signs release artifacts with keyless Sigstore
   bundles.
3. Users download from GitHub Releases and verify with
   `cosign verify-blob` before running or unpacking artifacts.

The shell installer is a convenience artifact produced by the same
release workflow. It is not a separate trust root.

Homebrew is deferred. Reeve will not publish a Homebrew formula or
require a tap token in the active release workflow until a later
decision makes that maintenance cost worthwhile.

Apple Developer ID signing and notarization remain tracked in issue
#147. Apple account approval removes the external account blocker, but
certificate export, secret storage, CI wiring, and notarization smoke
tests are separate implementation work.

## Rationale

This keeps Reeve's distribution story aligned with its security thesis.
Reeve asks users and auditors to trust signed evidence, not a channel by
itself. GitHub Releases provide the artifact host; Sigstore provides the
verifiable proof. Homebrew can make installation easier, but it does not
replace artifact verification.

It also keeps v0.1 focused. A tap repository, GitHub token, formula
publish job, and Homebrew smoke test are extra moving parts. They are
reasonable later, but they should not block source verification, demo
fleet work, or launch proof work now.

Apple approval changes the priority order. We no longer need to optimize
around a missing Apple account. Notarization can proceed when the
project chooses to wire Developer ID material into CI. Until then, the
README documents the quarantine fallback for verified macOS binaries.

## Plain-language summary

Reeve's release should be easy to explain:

Download the file from GitHub Releases. Download its `.bundle` file.
Verify the bundle with `cosign`. If verification passes, install the
binary or run the shell installer.

That is the core trust story.

Homebrew is only a shortcut. It may become useful later, but it is not
the thing that makes the release trustworthy. The signature does that.

Apple approval is now available, which is good. But wiring Apple
certificates and notarization into CI is still separate work. We will do
that when it is time, under issue #147. Until then, macOS users verify
the release artifact and, if Gatekeeper quarantine blocks first run,
remove quarantine from the verified binary.

## Consequences

- **This decision commits the project to:** GitHub Releases plus
  adjacent Sigstore bundles as the canonical release distribution path;
  `cargo-dist` shell installer generation; no active Homebrew formula
  publish job; #147 as the notarization track.
- **This decision unblocks:** release docs cleanup, removal of Homebrew
  tap/token requirements from the active workflow, and continuation of
  #192/#191 work without Homebrew setup.
- **This decision forecloses:** describing Homebrew as the primary macOS
  install path for v0.1; requiring a Homebrew tap token for launch.
- **This decision defers:** whether to maintain a Homebrew tap later;
  Developer ID certificate handling and notarization wiring.

## References

- [ADR-0004: Sign AIBOM + CycloneDX pair as a DSSE-wrapped in-toto Statement in a Sigstore bundle v0.3](0004-signature-envelope.md)
- [ADR-0006: Real signing requires cosign; distribution is documented prerequisite, not bundled](0006-cosign-dependency-strategy.md)
- [ADR-0010: Release artifacts are signed as keyless cosign bundles](0010-release-artifact-signing.md)
- [ADR-0015: Windows binary distribution starts without Windows discovery or profiling](0015-windows-binary-distribution.md)
- Issue #147
- Issue #196
