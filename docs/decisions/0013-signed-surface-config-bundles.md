# ADR-0013: System-wide surface configs verify adjacent Sigstore bundles

- **Status:** Accepted 2026-04-28
- **Decides:** Trust model for centralized custom-surface configuration
- **Related:** ADR-0004, ADR-0006, ADR-0011, issue #61

## Context

ADR-0011 lets Reeve read custom MCP surface definitions. Its first form
was explicit-only. The 2026-04-28 amendment added system-wide lookup so
MDM and endpoint-management tooling can drop one file per machine.

That creates a new trust question. `/etc/reeve/surfaces.yaml` and the
macOS / Windows equivalents are deployer-owned paths, but they are still
files on disk. If an attacker can write one, they can change what Reeve
tries to scan. Reeve already keeps custom paths relative and below the
scan target, but the deployer still needs proof that the config came from
an authorized signer.

## Options considered

### A. Trust the system path

Load `/etc/reeve/surfaces.yaml` whenever it exists and rely on operating
system permissions.

Pros: simplest. No signing UX. Cons: weak for the product's own security
thesis. Reeve would treat local disk state as deployer intent.

### B. Require signatures immediately

Refuse every unsigned surface config by default.

Pros: strongest production posture. Cons: breaks the phase-1 migration
path and makes pilots harder. A customer cannot try centralized config
without first building a signing flow.

### C. Verify adjacent bundle; warn by default, fail closed on request *(chosen)*

Look for `surfaces.yaml.sigstore.json` next to the config. If present,
verify it. If missing, warn and apply by default. If
`--require-signed-config` is set, refuse unsigned config. Signed configs
require `--signer-identity-regexp` or build-time
`REEVE_SURFACE_CONFIG_SIGNER_IDENTITY_REGEXP`.

Pros: preserves migration path, gives production a fail-closed switch,
matches Reeve's release and AIBOM signing model. Cons: default mode still
allows unsigned config until operators opt into the stricter flag.

## Decision

Reeve verifies adjacent Sigstore bundles for custom surface configs.
The bundle covers exactly the config bytes through a DSSE-wrapped
in-toto Statement with predicate type
`https://aibom.example/attestation/surface-config/v0.1`.

The signature file is named by appending `.sigstore.json` to the config
filename, for example `surfaces.yaml.sigstore.json`. Provenance metadata
uses `surfaces.provenance.json`.

Verification behavior:

1. Explicit `--surface-config <path>` still has precedence over system
   config.
2. If an adjacent signature exists, Reeve verifies the bundle before
   parsing the config.
3. If verification fails, Reeve refuses to apply the config.
4. If no signature exists, Reeve warns and applies by default.
5. If `--require-signed-config` is set and no signature exists, Reeve
   fails closed.
6. Fixture bundles are accepted only when
   `REEVE_ACCEPT_FIXTURE_SURFACE_CONFIG_SIGNATURE=1` is set. That escape
   hatch is for tests and offline demos, not production.

## Rationale

The chosen path keeps centralized config deployable without making local
disk writes equivalent to deployer authorization. It follows the same
shape as release artifact signing: sign bytes, publish a Sigstore bundle,
verify signer identity, and fail closed when the caller asks for a
production posture.

This also avoids creating a Reeve-specific key store. The deployer owns
the signing identity, expressed as an OIDC identity regexp. Reeve only
needs to know which identity is allowed.

## Plain-language summary

Custom surface config tells Reeve where to look for private company AI
tool configs. That is powerful. If the wrong person can change that file,
they can influence what Reeve reads.

So Reeve treats the config like a signed instruction. The deployer signs
the file. Reeve checks the signature before using it. If the file was
changed after signing, the hash no longer matches and Reeve refuses it.

For early pilots, Reeve still allows unsigned config but prints a warning.
For production, operators pass `--require-signed-config`; then unsigned
config is rejected.

The signer identity is explicit. A customer can say "only configs signed
by this CI workflow count." That matches how Reeve release binaries and
AIBOM outputs already work.

## Consequences

- **This decision commits the project to:**
  - `surfaces.yaml.sigstore.json` as the adjacent signature filename,
  - `surfaces.provenance.json` as the provenance metadata filename,
  - `--require-signed-config`,
  - `--signer-identity-regexp`,
  - fail-closed behavior when signature verification fails.
- **This decision unblocks:**
  - deployer-owned centralized config with a production trust posture,
  - MDM packaging templates that embed signed config bundles.
- **This decision forecloses:**
  - silently trusting system config purely because it lives under
    `/etc`, `/Library/Application Support`, or `%PROGRAMDATA%`.
- **This decision defers:**
  - native Rust Sigstore verification parity,
  - private OIDC issuer selection beyond the default GitHub Actions
    issuer,
  - signed workspace/user-home auto-discovery.

## References

- [ADR-0004: Signature envelope](0004-signature-envelope.md)
- [ADR-0006: Real signing requires cosign](0006-cosign-dependency-strategy.md)
- [ADR-0011: User-defined custom MCP surfaces](0011-custom-surfaces.md)
- [`docs/signing.md`](../signing.md)
