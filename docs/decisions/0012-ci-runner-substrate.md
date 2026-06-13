# ADR-0012: CI runner substrate is Blacksmith; orchestration stays GitHub Actions

- **Status:** Accepted 2026-04-28
- **Decides:** Where Reeve's continuous integration jobs physically execute, and what trade-offs that choice commits the project to
- **Related:** ADR-0006 (cosign dependency), ADR-0007 (live Sigstore acceptance), ADR-0010 (release artifact signing)

## Context

Reeve's continuous integration was running on GitHub-hosted runners under a personal-account Free plan. The CI matrix exercises Linux and macOS, with macOS billed at a 10× minute multiplier. Two operational problems followed:

1. **Cost and quota fragility.** A single billing failure or quota exhaustion blocked all runs; this materialized as the GitHub-Actions billing block on 2026-04-26 that halted PR #26 and main-branch CI for hours.
2. **Compute speed.** Cold starts and shared GitHub-hosted hardware made Rust + WASM + sandbox-profiling jobs slower than necessary. Iteration cadence dropped accordingly.

Self-hosting runners on existing hardware (Mac mini, Intel NUC) was considered. It is cheap on a per-month basis but expensive in operational complexity and meaningful in attack surface — Reeve's product thesis is that scanners are an attack surface, and an always-on self-hosted CI runner with cached secrets contradicts that posture without significant isolation work (ephemeral VM-per-job, network egress allowlists, branch-restricted dispatch). That investment was deferred.

## Options considered

### A. GitHub-hosted runners only

Description: keep the status quo. Pay GitHub for runner minutes. No new vendor dependency.
Pros: zero migration work; signed release builds run in a clean room operated by the same vendor that hosts the OIDC issuer; no new third party in the supply chain.
Cons: Linux + macOS minute pricing for private repos is the highest of any compared option (especially macOS at 10× multiplier); single point of cost-failure (a billing event blocks all CI); GitHub-hosted runner hardware is not particularly fast for cargo + wasmtime + sandbox profiling.

### B. Self-hosted GitHub runners on existing hardware

Description: install GitHub Actions Runner agents on the Mac mini and the Intel NUC. Run all CI on owned hardware. Optionally introduce ephemeral VM-per-job isolation, network egress allowlists, branch-allowlist dispatch.
Pros: monthly compute cost approaches zero; full control of the build environment; aligns with on-prem strategy if Reeve ever needs a physical air-gapped build path.
Cons: substantial operational cost (runner agent updates, hardware maintenance, OS patching, Tart/libvirt for ephemerality); meaningful attack surface for a security tool unless ephemeral-per-job + isolation guardrails are built; hardware availability is not 24/7 reliable for a one-person operation.

### C. Blacksmith managed runners *(chosen)*

Description: install the Blacksmith GitHub App on the organization, switch `runs-on:` labels from GitHub-hosted equivalents to Blacksmith equivalents (`blacksmith-4vcpu-ubuntu-2404`, `blacksmith-4vcpu-ubuntu-2204`, `blacksmith-6vcpu-macos-latest`), keep all GitHub Actions workflow YAML unchanged in structure. Compute moves to Blacksmith hardware; orchestration, secrets, OIDC issuance, GitHub App ecosystem, and PR check integration remain on GitHub Actions.
Pros: drop-in label change; significantly cheaper minute pricing on Linux and Linux ARM, comparable-or-better effective price on macOS due to faster hardware; 3000 free minutes per SKU per month covers Reeve's current footprint; faster builds reduce iteration latency; no operational burden of self-hosted runner agents; revertible in one PR if vendor risk materializes.
Cons: introduces a new vendor with access to Reeve's CI compute path; macOS raw rate is higher than GitHub-hosted (offset by faster hardware); requires a GitHub Organization, so this decision is coupled to the personal-account → organization migration that closed contemporaneously; the cosign-keyless release path still depends on GitHub-hosted OIDC, so signing trust does not move to Blacksmith.

## Decision

Reeve runs all routine CI compute on Blacksmith managed runners under the `Reeve-Security` GitHub organization. GitHub Actions remains the orchestration platform; the workflow YAML, secrets, OIDC issuance for cosign, and PR check integration are unchanged. The mapping in effect:

| GitHub-hosted label | Blacksmith label |
|---|---|
| `ubuntu-latest` | `blacksmith-4vcpu-ubuntu-2404` |
| `ubuntu-22.04` | `blacksmith-4vcpu-ubuntu-2204` |
| `macos-latest` | `blacksmith-6vcpu-macos-latest` |

GitHub-hosted runners are retained as a quiet fallback only. The organization keeps a $50 monthly Actions spending cap as a safety net against a misrouted job slipping back onto GitHub-hosted compute. No workflow currently targets GitHub-hosted runners; any reintroduction must be deliberate and ADR-recorded.

## Rationale

Three constraints drove the choice:

1. **Cost predictability.** Blacksmith's free-tier quota of 3000 minutes per SKU per month covers Reeve's current iteration rate with comfortable headroom. The same workload was costing a steady ~$12/month on GitHub-hosted with macOS dominating 87% of the bill. The expected steady-state cost on Blacksmith is zero.
2. **Iteration speed.** Faster compute closes the loop between a developer commit (or a Hermes / Codex agent commit) and a verdict. Slow CI is friction that compounds over hundreds of iterations.
3. **Operational simplicity given Reeve's threat model.** Self-hosted runners, done correctly for a tool that markets itself on supply-chain integrity, would require the same isolation work Reeve does on customer machines (ephemeral execution, network confinement, branch allowlists). That work is on the long-term roadmap (issue #29, deferred). Blacksmith's managed posture is acceptable in the interim because they expose the same trust boundary as any managed CI vendor: the customer ships code to vendor compute, the vendor returns a verdict. GitHub Actions itself is in this trust class today.

The release pipeline (cargo-dist + cosign keyless via Fulcio) was deliberately kept on Blacksmith Linux runners rather than reverted to GitHub-hosted for "clean-room" reproducibility. The Sigstore certificate identity binds to the GitHub Actions workflow file path on the organization repository, not to the physical runner; the trust signal that survives is "this binary was signed by a workflow at `repo:Reeve-Security/reeve:.github/workflows/release.yml@refs/tags/v*`," which is the same regardless of where the workflow physically executed. If clean-room separation later proves to be a customer requirement, the release jobs can be moved back to GitHub-hosted in a small follow-up PR; the rest of CI stays on Blacksmith.

## Plain-language summary

Reeve's tests need to run somewhere. Until this decision, every test ran on GitHub's own rented computers, paid by the minute, with macOS costing ten times as much per minute as Linux. That worked, but it was slow and a single billing hiccup once stopped all work for half a day.

GitHub gave us two real alternatives: rent computers from a different vendor, or run our own. Running our own would be the cheapest in dollars but the most expensive in time and trust — Reeve's whole pitch is that running tools that read sensitive configurations is risky, and a build server we operate ourselves is exactly that kind of risk unless we put a lot of work into isolating it. We chose to defer that work for now and instead rent computers from Blacksmith, a vendor that specializes in being a faster and cheaper drop-in for GitHub's runners.

The change was small in code: we updated the labels in our workflow files from `ubuntu-latest` to `blacksmith-4vcpu-ubuntu-2404` (and similar for macOS). Everything else stayed the same — our pipelines, our secrets, our pull-request checks, our release-signing workflow. If Blacksmith goes away or changes their pricing badly, we revert the labels in one pull request and we are back to GitHub-hosted runners.

The release-signing path still uses GitHub's official identity, so the cryptographic chain a customer verifies is unchanged. That chain says "a workflow at this path in this repository signed this binary" — it does not say which physical computer ran the workflow. That is the trust property that matters, and it survives the move.

## Consequences

- **This decision commits the project to:**
  - using Blacksmith as the routine CI compute provider for the foreseeable future,
  - keeping the GitHub Actions workflow YAML structure and secrets stable so a revert remains a label-only change,
  - retaining the GitHub Actions spending cap as a safety net against accidental fallback to GitHub-hosted runners,
  - updating this ADR or writing a successor if the runner mapping changes (instance sizes, OS pinning, new architectures).
- **This decision unblocks:**
  - cheaper and faster CI iteration cadence,
  - capacity for AI agent–driven development (Hermes, Codex) that pushes many PRs per day without exhausting GitHub's billing budget,
  - moving forward on v0.1.1 and beyond without a recurring monthly cost surprise.
- **This decision forecloses:**
  - reliance on the GitHub Actions free-minute quota for routine private-repo CI; that quota is now reserved for fallback,
  - the simpler narrative that "everything Reeve produces is built on GitHub-operated infrastructure end to end"; Blacksmith is now part of the build path even though it is not part of the cryptographic identity chain.
- **This decision defers:**
  - the self-hosted runner work captured in issue #29 (ephemeral-VM-per-job, network isolation, branch allowlists). That work returns to consideration if Blacksmith pricing changes materially, the security posture of managed third-party CI becomes unacceptable, or a customer requirement explicitly rules out third-party CI compute.

## References

- [ADR-0006: Real signing requires cosign; distribution is documented prerequisite, not bundled](0006-cosign-dependency-strategy.md)
- [ADR-0007: Live Sigstore acceptance runs as a dedicated GitHub Actions workflow, not on every main push](0007-live-sigstore-acceptance.md)
- [ADR-0010: Release artifacts are signed as keyless cosign bundles](0010-release-artifact-signing.md)
- [Blacksmith documentation — runners](https://docs.blacksmith.sh/runners/)
- [Blacksmith pricing page](https://www.blacksmith.sh/pricing)
- Issue #29 (deferred self-hosted CI + demo fleet roadmap)
