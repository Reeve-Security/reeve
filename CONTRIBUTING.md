# Contributing

## Contributor License Agreement (CLA)

Before your contribution can be merged, you must agree to the
[Contributor License Agreement](CLA.md). You keep the copyright to your work.
The CLA only grants the project the rights it needs to ship your contribution
under the [Apache-2.0 license](LICENSE).

Signing is automatic: when you open a pull request, a CLA bot checks whether
you've signed and links you to sign if not. Your PR cannot merge until the
check passes; you sign once and it covers all future contributions.

## Repository boundary

- `tools/` is reusable open-source machinery: deploy helpers, MDM templates,
  and product-adjacent automation that is intended to ship with the public
  repository.
- `private/` is internal-only forever: run evidence, customer notes, GTM
  material, secrets, and other founder-private operating data.
- Do not commit generated `*.aibom.json`, local state, or ad-hoc
  `inventory.yml` files outside the tracked fixture set.

## Gates

The repository owns its quality gates as scripts, so the list of checks lives in
one place and cannot drift. Run the gate, require it green; do not maintain a
separate checklist.

- Before opening or merging a PR: `scripts/merge-gate.sh` (the CI `check` job runs
  the same gate via `scripts/merge-gate.sh --ci-local`; pass `--pr <N>` locally to
  also require the GitHub required checks to be green on the same commit).
- Before tagging a release: `scripts/release-gate.sh <X.Y.Z>`.
- Before publishing a security advisory: `scripts/advisory-publish-gate.sh <X.Y.Z> <GHSA-...>`.

All three are verify-only. They never merge, tag, or publish; a human does those
after the gate exits zero.

`gitleaks` is a remote required CI check, not a local prerequisite: the merge gate
does not run it, so you do not need gitleaks installed to contribute. Its version is
pinned in `.gitleaks-version` (read by the CI job; `scripts/check-gitleaks-pinning.py`
keeps CI from drifting off it). If you want to reproduce the secret scan locally,
install that exact version (a newer or older gitleaks can change allowlist semantics
and fingerprints, so matching the pinned version is what makes a local run trustworthy).

### Security advisory forks

GitHub's temporary private advisory forks do not run Actions, so a fix worked in a
fork has no CI signal of its own. Before merging an advisory fix: rebase it onto the
latest `main`, run `scripts/merge-gate.sh --ci-local` on that rebased state, and after
the advisory merges, wait for `main` CI to go green before continuing.

## Code of Conduct

Participation in this project is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).
