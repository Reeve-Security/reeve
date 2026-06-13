# Reeve Releases

Per-version capability appendices. The evergreen product overview is
[`docs/reeve-product-brief.md`](../reeve-product-brief.md).

## Latest

| Tag | Published | Highlight |
|---|---|---|
| **[v0.3.8](v0.3.8.md)** | 2026-06-13 UTC | First public release line; human-readable reports, redaction hardening, CycloneDX 1.5 validation, and launch-candidate promotion |

## Public Release Line

| Tag | Published | Signed release? | Org | Notes |
|---|---|---|---|---|
| [v0.3.8](v0.3.8.md) | 2026-06-13 UTC | yes | Reeve-Security | Promotes the launch candidate with human-readable reports, redaction hardening, CycloneDX 1.5 validation, and precise registry lookup statuses |

## Pre-Public History

Reeve had pre-public releases in private history. The public release line starts at
v0.3.8.

## Adding a New Release Appendix

1. Tag the release.
2. Wait for the release workflow to publish artifacts and Sigstore bundles.
3. Add `docs/releases/v<X.Y.Z>.md`.
4. Update the latest/current rows here.
