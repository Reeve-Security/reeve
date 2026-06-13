# MCP registry seed

Issue #213 is the first official-registry reference-data slice. It uses
only the official MCP Registry API and emits a deterministic signed seed
artifact. It does not scrape community directories, run cron, or write
to a hosted database.

## Source

Official source:

```text
https://registry.modelcontextprotocol.io/v0.1/servers
```

The API is read-only for this slice. Capture a bounded page, then
normalize it locally:

```bash
mkdir -p out/mcp-registry
curl -fsSL \
  "https://registry.modelcontextprotocol.io/v0.1/servers?limit=25" \
  > out/mcp-registry/official-page.json

cargo run -p aibom-cli -- mcp-registry-seed \
  --input out/mcp-registry/official-page.json \
  --output out/mcp-registry/mcp-registry-seed.json \
  --bundle out/mcp-registry/mcp-registry-seed.sigstore.fixture.json \
  --source-url "https://registry.modelcontextprotocol.io/v0.1/servers?limit=25" \
  --sign-mode fixture
```

Use fixture signing for local tests only. Use real signing when the seed
artifact is used in public/demo material:

```bash
cargo run -p aibom-cli -- mcp-registry-seed \
  --input out/mcp-registry/official-page.json \
  --output out/mcp-registry/mcp-registry-seed.json \
  --bundle out/mcp-registry/mcp-registry-seed.sigstore.json \
  --source-url "https://registry.modelcontextprotocol.io/v0.1/servers?limit=25" \
  --sign-mode real
```

## Output contract

The seed artifact includes:

- `kind: reeve-mcp-registry-seed`
- source URL and input SHA-256
- canonical identity per record: publisher, name, package name, version
- dedupe key: `official-mcp-registry|<name>|<version>`
- declared server metadata from the registry record
- official registry metadata from `_meta`
- deterministic canonical JSON bytes

The Sigstore bundle signs the seed artifact as an in-toto statement with
predicate type:

```text
https://aibom.example/attestation/mcp-registry-seed/v0.1
```

## Consumer verification

Local fixture bundles prove deterministic behavior only:

```bash
python3 scripts/verify-mcp-registry-seed.py \
  --seed out/mcp-registry/mcp-registry-seed.json \
  --bundle out/mcp-registry/mcp-registry-seed.sigstore.fixture.json \
  --expected-source-url "https://registry.modelcontextprotocol.io/v0.1/servers?limit=25" \
  --allow-fixture
```

Public/demo seed artifacts must use real Sigstore signing. Verify Fulcio
and Rekor proof with cosign, then parse the seed:

```bash
python3 scripts/verify-mcp-registry-seed.py \
  --seed out/mcp-registry/mcp-registry-seed.json \
  --bundle out/mcp-registry/mcp-registry-seed.sigstore.json \
  --expected-source-url "https://registry.modelcontextprotocol.io/v0.1/servers?limit=25" \
  --certificate-identity-regexp '^https://github.com/Reeve-Security/<signing-repo>/.github/workflows/<signing-workflow>@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+.*)$'
```

The script refuses fixture bundles unless `--allow-fixture` is explicit.
For real bundles, it shells out to `cosign verify-blob` before checking
the DSSE statement digest, predicate type, source URL, dedupe keys, and
record summary.

## Operational boundary

Scheduled registry capture, hosted storage, enrichment, and data
publication are not part of the public `reeve` repository.

This repository keeps the reusable primitive:

- fetch registry pages;
- normalize a captured registry page set into a deterministic seed;
- verify a signed seed artifact.

External operators may shell out to a pinned `aibom-cli` release to run
those primitives. Public verification docs must pin the actual signing
workflow identity used for any signed artifact.

## Demo gate

Scene 9 in `docs/demo-script.md` stays gated until a real signed seed
exists. Fixture bundles prove local behavior, not public provenance.
