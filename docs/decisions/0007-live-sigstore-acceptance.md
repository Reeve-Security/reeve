# ADR-0007: Live Sigstore acceptance runs as a dedicated GitHub Actions workflow, not on every main push

- **Status:** Accepted 2026-04-24
- **Decides:** How Reeve v0.1 proves that `--sign-mode real` actually produces a live Fulcio cert + Rekor v2 tlog entry, and that the validator accepts the resulting bundle under `--verify-crypto` (GitHub issue #13)
- **Related:** ADR-0004, ADR-0006, `docs/signing.md`, `docs/release-readiness.md`

## Context

ADR-0004 commits Reeve to signing the CycloneDX + AIBOM pair as a
DSSE-wrapped in-toto Statement inside a Sigstore bundle v0.3.
ADR-0006 commits Reeve to fail-closed real signing via `cosign`. Both
decisions needed an operational proof: that the signer wiring can
obtain a real Fulcio certificate via keyless OIDC, get a Rekor v2
inclusion receipt, and that the validator's `--verify-crypto` path
accepts the resulting bundle.

`scripts/release-readiness.sh` and `ci.yml` deliberately use
`--sign-mode fixture` so every CI run is deterministic, offline, and
free of Sigstore dependencies (see `docs/release-readiness.md`
§5). That guarantees nothing about the real signing path.

This ADR records the decision of where and how often the live
acceptance check runs.

## Options considered

### A. Inline live signing in `ci.yml` on every push to `main`

Extend the existing `check` job (or add a second job in the same
workflow) so every merge to `main` signs against live Sigstore and
verifies the result.

Pros: live path is exercised continuously; regressions are caught at
merge time.

Cons: every `main` push publishes a Rekor entry under the repo's
GitHub Actions OIDC identity — Rekor log noise, meaningful cost to
the public-good instance on high-commit days, and an implicit
dependency that main cannot merge when Fulcio or Rekor are degraded.
Tightly couples the deterministic release-readiness runner to live
services it was explicitly designed to avoid.

### B. Rely on the ignored `online_smoke` integration test only

Keep the live path as a developer-initiated manual test
(`REEVE_ONLINE_SIGSTORE=1 cargo test -- --ignored`) and document the
expectation that maintainers run it before release.

Pros: zero infra cost and zero log noise.

Cons: there is no record that the live path was ever exercised on a
production-shaped runner. Issue #13's acceptance criterion requires
"CI or release workflow with `id-token: write`" — a manual dev-box
run is explicitly insufficient.

### C. Dedicated workflow triggered deliberately by release tags, manual dispatch, and labeled PRs *(chosen)*

Add `.github/workflows/live-sigstore-acceptance.yml` with
`id-token: write`. Trigger it on `workflow_dispatch` (manual
release-time sign-off) and on `push: tags: ['v*']` (every release
tag exercises the live path before the tag is consumed by
downstream tooling). Also trigger it for pull requests only when the
PR carries an explicit `online-sigstore` label, so the live gate can
prove signer changes before merge without publishing Rekor entries
for every PR. Leave `ci.yml` untouched and fixture-only.

Pros: live path runs on a cadence tied to release moments rather
than per-commit; satisfies issue #13's "CI or release workflow"
acceptance; each run is auditable in the Actions history and its
Rekor receipts are discoverable; does not couple `main` merge
health to Sigstore service health. Maintainers can still fire it on
demand, and release-critical PRs can opt into the same proof before
merge.

Cons: a regression introduced between releases is not caught until
the next tag or dispatch. Mitigated by the ignored
`online_smoke` test being available for local pre-merge use and by
the dispatch trigger being usable for ad-hoc gating.

## Decision

Reeve v0.1 proves live Sigstore acceptance via a dedicated
`live-sigstore-acceptance` workflow triggered by `workflow_dispatch`,
by push of `v*` tags, and by pull requests explicitly labeled
`online-sigstore`. The workflow requests `id-token: write`, installs
`cosign` v3.0.6, runs the `online_smoke` integration test, then runs
`aibom-cli scan --sign-mode real` against the committed CLI
scan-target fixture and asserts the produced `.sigstore.json` carries
a real Fulcio certificate, a Rekor tlog entry, the expected two
in-toto Statement subjects, and passes both `cosign
verify-blob-attestation` against the GitHub Actions OIDC identity and
`aibom-cli verify --verify-crypto`.

`ci.yml` stays fixture-only. The release-readiness runner stays
fixture-only. Neither path may be treated as evidence of live
Sigstore behavior.

## Rationale

The key property ADR-0006 protects is that a real signing request
never silently downgrades to a fixture. That property is checked
statically in `cli_e2e.rs` and dynamically by the new workflow. We
do not gain meaningfully more protection by running the live path on
every commit than by running it on release tags plus on demand, and
we do pay real costs on the public-good Rekor instance if we spam it.

Triggering on `v*` tags ties the live proof to the moment it
matters — a release — and `workflow_dispatch` gives maintainers a
zero-friction way to re-prove the path at will. The PR label trigger
adds a pre-merge proof path for changes to `crates/aibom-signer/` or
to `.github/workflows/`, while still avoiding Rekor noise on routine
documentation or fixture-only changes.

## Plain-language summary

There are two things the project needs to prove about signing. The
first is that the boring, everyday path — produce a fixture bundle,
validate it, run a policy, print PASS — works on every commit. That
is the job of the existing CI workflow, and it deliberately has
nothing to do with real Sigstore. It must not talk to Fulcio or
Rekor.

The second is that the real path — call cosign, get a real
certificate from Fulcio, have Rekor record the signature in its
public log — actually works end-to-end on a realistic runner with a
realistic identity. That is a heavier operation: it publishes an
entry to a shared public log, it depends on services Reeve does not
control, and it costs something (small, but not zero) every time we
run it.

We chose to put the live proof into its own workflow that runs on
release tags, on demand, and on PRs that deliberately opt in with an
`online-sigstore` label. That matches how release-time gates work on
other supply-chain projects (Kubernetes, sigstore/cosign itself,
Rekor): continuous integration stays cheap and deterministic, and
the live acceptance gate runs only when the project needs a real
public Sigstore proof. Developers who want to run the live path
locally can still do so with `REEVE_ONLINE_SIGSTORE=1 cargo test -p
aibom-signer --test online_smoke -- --ignored`.

## Consequences

- **This decision commits the project to:** keeping `ci.yml` and
  `scripts/release-readiness.sh` free of live Sigstore/Rekor
  dependencies; running the live acceptance workflow at minimum on
  every release tag and on PRs that change the real-signing path;
  documenting any release that ships without a green live-acceptance
  run as an explicit exception.
- **This decision unblocks:** issue #13 acceptance; release tagging
  under the ADR-0006 rule that real mode is mandatory for release
  artifacts.
- **This decision forecloses:** treating a green `ci.yml` run as
  evidence that real signing is working.
- **This decision defers:** replacing cosign-side verification with
  native sigstore-rs verification (issue #11). The current workflow
  uses pinned cosign to prove the public-good Sigstore path and
  Reeve's validator wiring; deeper native verification arrives with
  the sigstore-rs backend.

## References

- [ADR-0004: Signature envelope](0004-signature-envelope.md)
- [ADR-0006: Real signing requires cosign](0006-cosign-dependency-strategy.md)
- [`docs/release-readiness.md`](../release-readiness.md)
- [`docs/signing.md`](../signing.md)
- [`.github/workflows/live-sigstore-acceptance.yml`](../../.github/workflows/live-sigstore-acceptance.yml)
- GitHub issue #13
