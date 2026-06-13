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

## Code of Conduct

Participation in this project is governed by the
[Code of Conduct](CODE_OF_CONDUCT.md).
