# ADR-0006: Real signing requires cosign; fixture signing stays explicit

- **Status:** Accepted 2026-04-24
- **Decides:** v0.1 release-time cosign dependency strategy
- **Related:** ADR-0004, `docs/signing.md`, `docs/release-readiness.md`, `docs/research/sigstore-rs-maturity.md`, GitHub issue #6, GitHub issue #11

## Context

ADR-0004 commits Reeve v0.1 to signing the CycloneDX document and
AIBOM sidecar together as a DSSE-wrapped in-toto Statement in a
Sigstore bundle. The implementation currently uses the official
`cosign` CLI as the bridge to Sigstore keyless signing.

That leaves one operational question for v0.1: what should happen
when a user requests signing and `cosign` is not installed? Silent
downgrade to a fixture bundle is convenient for tests and demos, but
it is unacceptable for release artifacts because it can make an
unsigned placeholder look like a completed signing step.

## Options Considered

### A. Require cosign for every scan

Every invocation that emits an AIBOM would require `cosign`, even
when the user only wants local inspection or deterministic fixture
output.

Pros: simplest rule to explain. No accidental fixture output.

Cons: pushes a signing dependency onto endpoints and local demo
environments that do not perform real signing. This conflicts with
the deployment model in `docs/signing.md`, where endpoint scans can
produce unsigned artifacts and a central service signs later.

### B. Keep automatic downgrade for all signing requests

If `cosign` is present, use it. If it is missing, warn and emit a
fixture bundle.

Pros: preserves the most ergonomic local behavior. Tests and demos
work on machines without Sigstore tooling.

Cons: too weak for release and production signing. A missing `cosign`
installation in CI could quietly produce a fixture bundle unless a
human notices the warning.

### C. Make real signing explicit and fail closed; keep fixture mode explicit *(chosen)*

Add an explicit real-signing mode that requires `cosign` and fails
with an actionable error if it is unavailable. Keep a fixture mode
for deterministic tests, demos, and offline scans. Keep auto mode
for legacy local convenience, but prohibit release pipelines from
depending on it.

Pros: release paths fail closed while tests and demos stay usable
without networked signing infrastructure. The dependency is scoped to
the environment that actually signs.

Cons: adds one CLI option and one release-process rule that users
must learn.

## Decision

Reeve v0.1 treats `cosign` as a dependency only for environments that
perform real Sigstore signing. `aibom scan --sign-mode real` and
`REEVE_SIGN_MODE=real` require a working `cosign` binary and fail
before writing scan artifacts when it is unavailable. Fixture output
is available through `--sign-mode fixture` and `--skip-sign`. Auto
mode remains the default for local compatibility: it signs with
`cosign` when available, otherwise warns and emits a fixture bundle.

Release workflows must use real mode, not auto mode.

### Distribution strategy: cosign is a documented prerequisite

For v0.1, Reeve does **not** bundle `cosign` into its release archives
and does **not** block the release on a native `sigstore-rs` backend.
Instead, `cosign` is documented as a runtime prerequisite for users
who need real signing, with install one-liners in the README.

This is option **A** from the expanded evaluation below:

- **Option A — Document as prerequisite** *(chosen for v0.1)*
  - Add `cosign` install instructions to README (Homebrew, GitHub releases, Aqua, npm).
  - Honest; minimal work; matches how Sigstore ecosystem users already get cosign.
  - Defer bundling or native replacement until adoption signals justify the effort.

- **Option B — Bundle cosign alongside Reeve via cargo-dist**
  - Ship a platform-specific `cosign` binary in the same archive.
  - Pros: one-installation experience; pinned cosign version reduces supply-chain risk.
  - Cons: doubles archive size (~50MB per platform); cosign release cadence outpaces Reeve; maintenance burden of tracking cosign CVEs and re-releasing.
  - **Deferred.** Revisit if early-adopter feedback converges on "install friction is the #1 blocker."

- **Option C — Complete native `sigstore-rs` backend before release**
  - Replace `std::process::Command::new("cosign")` with `sigstore-rs` API calls.
  - Pros: removes runtime dependency entirely;纯 Rust supply chain; embeds directly in the binary.
  - Cons: `sigstore-rs` API surface for paired-DSSE-Statement signing + Rekor v2 bundle v0.3 emission is not yet proven sufficient (GitHub issue #11 tracks the maturity gate).
  - **Deferred until maturity gate passes.** A released `sigstore-rs` crate must prove ADR-0004 parity with cosign output before Reeve switches, or we risk breaking Rekor inclusion proofs.

- **Option D — Hybrid** *(recommended long-term path, starting with A)*
  - Document prerequisite for v0.1.x (option A).
  - Run the `sigstore-rs` maturity gate in parallel (GitHub issue #11).
  - Switch to native only when a released crate proves parity with cosign output.
  - Evaluate bundling (option B) only if install friction proves to be a top-3 adoption blocker in user interviews.

**Rationale for choosing A now:** The target user for v0.1 is a security-conscious developer or platform engineer who is already in the Sigstore ecosystem (they know what Rekor and Fulcio are). Asking them to `brew install cosign` or download a GitHub release is not a meaningful barrier. The engineering time saved by not bundling or rewriting is better spent on scanner coverage, policy depth, and the Linux sandbox backend — features that differentiate Reeve from competitors.

## Rationale

This preserves ADR-0004's security posture without making every scan
environment a Sigstore signing environment. The important boundary is
intent. When a user or CI workflow explicitly asks for real signing,
the system must not produce a fixture bundle as a substitute. When a
test, demo, or endpoint-side inventory run explicitly asks for
fixture output, it should remain deterministic and offline.

The result matches the deployment patterns in `docs/signing.md`:
endpoints can produce evidence without `cosign`, while central
signers and release workflows install `cosign` and fail closed if it
is missing.

## Plain-Language Summary

Reeve has two different jobs that look similar but mean very
different things.

For a real release or production attestation, Reeve must sign with
Sigstore. In v0.1, that means calling the official `cosign` tool. If
that tool is missing, the right behavior is to stop immediately and
say exactly what is wrong. A placeholder signature is not good enough
for a release.

For tests, demos, and offline inventory, Reeve still needs a stable
bundle-shaped file so the rest of the pipeline can run. That file is
a fixture. It is useful, but it is not a real Sigstore signature.

The CLI now makes the choice explicit. `--sign-mode real` means "do
the real signing or fail." `--sign-mode fixture` means "produce the
deterministic placeholder." The default `auto` mode remains friendly
for local use, but release automation must pin real mode so a missing
dependency cannot slip through as a fake success.

## Consequences

- **This decision commits the project to:** explicit signing modes,
  fail-closed behavior for real signing, a supported fixture path
  for deterministic tests and demos, and documenting (not bundling)
  the `cosign` prerequisite for v0.1.
- **This decision unblocks:** issue #6, the release-readiness work
  in issue #2, and the README install-path documentation.
- **This decision forecloses:** treating a fixture bundle as an
  acceptable substitute for an explicitly requested real signature;
  bundling `cosign` in v0.1 release archives.
- **This decision defers:** replacing the `cosign` shell-out with a
  native `sigstore-rs` backend until the maturity gate in
  `docs/research/sigstore-rs-maturity.md` passes for a crates.io
  release (tracked by GitHub issue #11) and bundling `cosign`
  alongside release artifacts (evaluated but deferred).

## References

- [ADR-0004: Signature envelope](0004-signature-envelope.md)
- [`docs/signing.md`](../signing.md)
- [`docs/release-readiness.md`](../release-readiness.md)
- [`docs/research/sigstore-rs-maturity.md`](../research/sigstore-rs-maturity.md)
- GitHub issue #6
- GitHub issue #11
