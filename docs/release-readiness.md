# v0.1 Release Readiness

This document defines the minimal path required to declare Reeve v0.1 ready for release. It is intentionally narrow and does not expand product scope.

## Goal

A reproducible, demoable, cryptographically verifiable path from source → scan → AIBOM → signature → verification → policy evaluation.

## Required components

### 1. CLI path works end-to-end

The following commands must execute successfully on a known test environment:

- `aibom scan`
- `aibom verify`
- `aibom policy check`

Output must be schema-valid and consistent across runs.

### 2. Fixture-backed demo path

A deterministic demo must exist using either:

- a controlled local MCP configuration, or
- a fixture-based simulation

The demo must show:

- discovery of at least one MCP tool
- declared vs observed capability difference (if applicable)
- successful schema validation

### 3. Signing and provenance

Reeve v0.1 ships two signing paths that must both keep working, and
an explicit rule about when each one is used:

- **Real signing** (`aibom scan --sign-mode real`, or
  `REEVE_SIGN_MODE=real`): shells out to `cosign` for Sigstore
  keyless attestation. Required for release artifacts. Hard-fails
  with an actionable error when cosign is unavailable; never
  silently downgrades to a fixture bundle. Cosign install path is
  `sigstore/cosign-installer` in CI or `brew install cosign` /
  distro package on developer boxes; `REEVE_COSIGN_BIN` lets the
  operator point at a specific binary.
- **Fixture / no-sign** (`--sign-mode fixture` or `--skip-sign`):
  emits the deterministic placeholder Sigstore bundle used by unit
  tests, fixture-regenerator idempotency checks, and the
  reproducible demo. Does not require cosign.
- **Auto** (default when no flag is passed, or
  `--sign-mode auto`): legacy behavior — use cosign if present, warn
  and fall back to fixture otherwise. Permitted for local runs only;
  release pipelines must not rely on it.

Per ADR-0006, acceptance for a v0.1 release build requires:

- The release workflow installs cosign before running Reeve's
  signing step.
- The release signing step runs with `--sign-mode real` (or
  `REEVE_SIGN_MODE=real`) so a missing-cosign regression fails the
  release job instead of producing a fixture-bundled artifact.
- The CLI rejects an explicit real-signing request when cosign is
  missing (covered by
  `scan_sign_mode_real_fails_when_cosign_missing` in
  `crates/aibom-cli/tests/cli_e2e.rs`).
- The fixture/no-sign path continues to pass on machines without
  cosign (covered by
  `scan_sign_mode_fixture_emits_deterministic_fixture_bundle` in the
  same file).

The live Sigstore/Rekor acceptance gate for `--sign-mode real` runs
as a dedicated workflow,
`.github/workflows/live-sigstore-acceptance.yml`, triggered by
`workflow_dispatch`, by push of `v*` release tags, and by pull
requests explicitly labeled `online-sigstore`. It uses `id-token:
write`, installs pinned `cosign` v3.0.6, exercises the
`online_smoke` integration test, signs the committed CLI scan-target
fixture with `--sign-mode real`, asserts the produced
`.sigstore.json` carries a real Fulcio certificate and Rekor v2
tlog entry, verifies the bundle with `cosign
verify-blob-attestation` against the GitHub Actions OIDC issuer and
repository identity, and runs `aibom-cli verify --verify-crypto`
through to PASS. See ADR-0007 for why that proof lives in a
dedicated workflow rather than in `ci.yml`.

Windows endpoint launch testing follows the same split. A Windows VM
used as an endpoint test target does not need an interactive Sigstore
browser login. The endpoint run may use `--skip-sign` or
`--sign-mode fixture`; real Sigstore proof belongs in the central
signing environment or CI workflow that owns the organization OIDC
identity. Track Windows VM signing-runbook coverage in issue #241.

### 4. Policy evaluation

At least one policy must:

- consume AIBOM input
- produce a deterministic verdict
- be test-covered

At least one example must show a failing policy condition.

### 5. CI or reproducible script

A CI job or documented script must:

- run tests
- validate schema
- execute CLI demo path

Full release automation is not required, but the path must be reproducible.

The concrete runner is `scripts/release-readiness.sh`. It:

- builds `aibom-cli` (release profile),
- runs `aibom-cli scan --sign-mode fixture` against the committed
  `crates/aibom-cli/tests/data/cli-scan-target` fixture,
- runs `aibom-cli verify` on the generated scan directory,
- runs `aibom-cli validate-artifacts` on the resulting triplet,
- runs `aibom-cli validate` across the 37-fixture contract-test
  corpus,
- runs `aibom-cli policy check` against the
  `03-undeclared-egress-delta` positive fixture and asserts the
  expected `DENY declared-observed-capability-match` verdict,
- re-validates the policy-rewritten triplet, and
- diffs a deterministic invariants summary (component bom-refs,
  CDX names, policy verdicts) against
  `scripts/release-readiness.expected.txt`.

The runner is wired into `.github/workflows/ci.yml` so every CI
run exercises the demo path end-to-end. It deliberately uses
`--sign-mode fixture` so it has no cosign/Sigstore/Rekor
dependency. The separate live-signing acceptance gate for
`--sign-mode real` lives in
`.github/workflows/live-sigstore-acceptance.yml` (see ADR-0007)
and must not reuse this fixture-only runner as proof of a real
Sigstore/Rekor bundle.

Local prerequisites are Rust, Python 3, and OPA (`opa` on `PATH` or
`OPA_BIN` pointing at an executable) when the runner builds the CLI. If
`REEVE_AIBOM_BIN` points at an existing `aibom-cli` binary, the runner
skips the build and does not require OPA at runtime.

### 6. Positioning alignment

Docs must clearly state:

- Reeve produces evidence, not safety claims
- AIBOM is the system-of-record output
- v0.1 scope is limited to MCP adapter and CLI

## Explicit non-goals for v0.1 release

- multi-adapter support
- runtime enforcement
- hosted UI/dashboard
- full policy catalog maturity
- enterprise analytics

## Acceptance definition

v0.1 is ready when:

- a developer can clone the repo
- run the CLI against a known input
- produce a valid AIBOM
- verify it cryptographically
- run at least one policy
- reproduce the result in CI or via script

Concretely: `bash scripts/release-readiness.sh` passes on a clean
checkout and in CI. That single command is the canonical
reproducibility check for v0.1.

Nothing more is required for v0.1.
