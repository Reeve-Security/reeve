# sigstore-rs maturity gate for native signing

Issue #11 tracks the future migration from the `cosign` shell-out to a native Rust signing backend. This is a release-hardening roadmap item, not permission to weaken ADR-0004.

## Current decision

Keep `cosign` as the production signing backend until a released `sigstore-rs` crate can satisfy the full Reeve signing contract.

A native backend must be a strict replacement for the current `cosign` path. It must not change the emitted signature envelope, weaken Rekor transparency guarantees, or mix claimed facts with verified facts in policy input. It must fail closed for real signing requests when native signing cannot complete.

## Required parity gates

All gates must pass before Reeve can switch from `cosign` to `sigstore-rs`:

| Gate | Required capability | Why it matters |
| --- | --- | --- |
| DSSE envelope | Build/sign a DSSE envelope over Reeve's in-toto Statement. | ADR-0004 requires DSSE-wrapped statements, not raw blob signatures. |
| in-toto Statement | Represent two subjects: CycloneDX document and AIBOM sidecar. | Verifiers must know exactly which pair of artifacts the signature covers. |
| Bundle v0.3 | Emit or verify Sigstore bundle v0.3 shape used by Reeve fixtures and release assets. | Reeve's schema/fixtures and release docs are keyed to v0.3. |
| Rekor v2 dsse | Upload DSSE entries and verify inclusion proof/UUID against Rekor v2. | Transparency must be first-class evidence, not an optional signature side effect. |
| GitHub Actions OIDC | Use ambient Actions OIDC without browser prompts or long-lived secrets. | Reeve release signing and CI paths must stay non-interactive/keyless. |
| Fixture parity | Produce output that Reeve can validate with the same policy/verification split as current cosign bundles. | Policy input must keep verified-vs-claimed facts separate. |
| Failure behavior | Fail closed when real signing is requested and native signing cannot complete. | No fixture or unsigned downgrade for production signing. |

## Non-goals for the migration

The migration must not introduce:

- long-lived signing keys,
- browser-prompt signing in CI,
- a hosted signing service,
- custom transparency log semantics,
- a new signature envelope format,
- fallback from real signing to fixture signing.

## Recheck procedure

Run this when a new `sigstore` crate is released or a relevant upstream milestone lands:

1. Read `cargo info sigstore` and upstream release notes.
2. Check each parity gate above against the released crate, not unreleased main-branch code.
3. If all gates are present, open a new implementation issue that includes:
   - minimum `sigstore` crate version,
   - exact APIs used for DSSE, in-toto, Fulcio, Rekor v2, and bundle v0.3,
   - golden fixture expectations,
   - rollback plan to `cosign`.
4. Keep `cosign` shell-out as the default until tests prove native/cosign parity.

## Last checked

- Crate: `sigstore`
- Released version observed by `cargo search sigstore --limit 5`: `0.13.0`
- Result: defer native backend. Required parity gates are not all available in the released crate.

## Plain-language summary

Do not replace `cosign` just because a Rust Sigstore crate exists. Reeve needs a very specific signature: DSSE-wrapped in-toto over two files, logged in Rekor v2, packaged as bundle v0.3, signed with CI OIDC, and fail-closed when real signing fails. Native Rust signing is good only after it can do all of that.
