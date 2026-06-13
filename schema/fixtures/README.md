# Schema Fixtures

Fixtures are canonical contract cases, not casual examples. They tell you
whether an AIBOM implementation follows the schemas, validator behavior,
canonicalization rules, signing shape, and policy expectations.

Each fixture directory contains a CycloneDX document, an AIBOM sidecar,
and the minimum signing fixture data needed for the test. A `manifest.json`
file states what the fixture tests and what result is expected.

## Fixture Types

- `aibom-v0.1.0/positive/`: valid triplets. Validators must accept these.
- `aibom-v0.1.0/negative/`: intentionally broken triplets. Validators must reject these
  at the expected stage.
- `aibom-v0.1.0/policy/`: fixtures used by the default Rego policy tests.
- `aibom-v0.2.0/`: fixtures for v0.2 schema additions.
- `aibom-v0.3.0/`: fixtures for v0.3 schema additions.
- `sensitive-data-report/`: fixtures for the separate opt-in
  sensitive-data report.
- `secret-rule-pack/`: fixtures for customer-supplied sensitive-data rules.

## Validation Stages

Positive AIBOM fixtures must pass:

1. schema validation;
2. semantic validation across the sidecar and CycloneDX file;
3. canonical byte validation;
4. CycloneDX-to-sidecar hash matching;
5. Sigstore fixture-bundle shape validation.

Negative fixtures must fail at the `rejectStage` named in their manifest
and pass all earlier stages. This keeps failures precise.

## Fixture Bundles

Files named `*.sigstore.fixture.json` are structural placeholders, not
real Sigstore bundles. They exist so offline CI can test the signed-output
shape without contacting external services.

Never rename `*.sigstore.fixture.json` to `*.sigstore.json`.

## Canonical Bytes

`<scan-id>.aibom.json` files are stored in deterministic canonical JSON
form. `canonical-bytes.sha256` records the hash of those bytes.

Regenerate fixtures with:

```bash
python3 scripts/regenerate-schema-fixtures.py
```

CI reruns the generator and fails if fixture bytes drift unexpectedly.

## Sensitive-Data Fixtures

Sensitive-data reports are separate from AIBOM sidecars. These fixtures
ensure reports stay redacted and never serialize raw conversation content,
raw secret values, snippets, screenshots, embeddings, searchable indexes,
or hashes of secret values.
