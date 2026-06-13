# MCP registry API contract slice

Issue #115 asks for a public read-only registry API, but this repository
does not ship a runtime server or static-data publisher. This document
defines the bounded artifact contract that `aibom-cli scan
--registry-source` can consume. Scheduled artifact publication is outside
this public repository.

## Supported routes in this slice

- `GET /servers/{publisher}/{name}`
- `GET /servers/by-hosted-url/{transport}/{sha256}`
- `GET /search?q=...`

These routes are intentionally limited to data that can be served
deterministically from a published `datasets/mcp-servers/` tree.
Today that stable queryable surface is limited to publisher/package
identity, title/description text, and declared hosted remotes from the
official registry seed path.

### `GET /servers/{publisher}/{name}`

Reads the latest published seed snapshot at
`datasets/mcp-servers/latest.json`, filters matching records by
`canonicalIdentity.publisher` and `canonicalIdentity.packageName`, and
returns all matched versions newest-first.

The response is grouped because the current route shape does not carry a
version segment. The latest record is identified explicitly via
`latestVersion`.

### `GET /servers/by-hosted-url/{transport}/{sha256}`

Reads the latest published seed snapshot at
`datasets/mcp-servers/latest.json`, keeps the latest published record for
each `{publisher}/{name}` pair, extracts declared hosted remotes from
`declaredMetadata.remotes`, normalizes transport names to the current
static contract (`streamable-http`, `websocket`), and publishes one JSON
artifact per normalized hosted endpoint.

The fixture path key is the SHA-256 of the canonical string
`"{transport}\n{normalized-url}"`, where URL normalization trims
surrounding whitespace and removes trailing slashes. The response
contains the normalized URL plus every latest server fixture path that
currently claims that hosted endpoint.

### `GET /search?q=...`

Reads the latest published seed snapshot at
`datasets/mcp-servers/latest.json`, groups records by
`canonicalIdentity.publisher` + `canonicalIdentity.packageName`, keeps
the latest published version for each server, and materializes
case-insensitive normalized single-token search fixtures over:

- publisher
- package name
- title
- description

The current static slice intentionally keeps the query surface bounded:
it extracts alphanumeric word tokens from those fields, lowercases them,
and publishes one JSON artifact per supported token. Tokens shorter than
two characters are dropped, and separator-joined full-field queries
remain out of scope for this static slice. Multi-token, fuzzy, and
ranked search semantics remain deferred until a runtime-backed API
exists.

## Deferred routes

The following issue #115 routes are still intentionally deferred because
the published dataset does not yet provide a stable backing contract for
them:

- `GET /servers/by-hash/{sha256}`
- `GET /servers/by-capability/{capability}`
- `GET /vulnerabilities/{server}`

Those routes require additional indexing, query semantics, or new data
sources beyond the current seed publication path. In
particular, the current official-registry seed shape does not preserve
stable capability-bearing fields such as `tools` or `capabilities`, so
`/servers/by-capability/{capability}` would be synthetic if we emitted
it today.

For the same reason, the live upstream official-registry payload still
lacks stable package hash/digest fields: the seed records carry declared
`remotes`, publisher/package identity, and description text, but no
content or package digest. So `/servers/by-hash/{sha256}` would be
synthetic if emitted today. The payload likewise carries no
vulnerability-bearing fields (no advisory, CVE, or vulnerability
records), so `/vulnerabilities/{server}` would be synthetic too.

Concretely, the static API builder and the published `api-fixtures/`
tree must not synthesize a `servers/by-hash/{sha256}` index or a
`vulnerabilities/{server}` index for the current seed shape. These
routes land only once the upstream payload provides stable package
hash/digest and vulnerability fields, as a new contract update.

## Contract artifacts

The producer of a registry artifact tree is outside this repository.
Reeve's public responsibility is the consumer behavior: the CLI reads a
tree matching this contract and treats lookup failures as soft failures.
The OpenAPI document for the current contract slice lives at
`docs/openapi/mcp-registry-api-v0.1.yaml`.

## Published static artifact paths

An external publisher can publish this bounded contract slice under
`api-fixtures/`:

- `api-fixtures/openapi/mcp-registry-api-v0.1.yaml`
- `api-fixtures/servers/<publisher>/<name>.json`
- `api-fixtures/servers/by-hosted-url/<transport>/<sha256>.json`
- `api-fixtures/search/q/<normalized-token>.json`
- `api-fixtures/<response>.json.sigstore.json`

These are static, machine-readable contract artifacts for the current
dataset-backed routes. The `search` slice is limited to normalized
single-token queries from the latest snapshot. Each published JSON
response body is accompanied by an adjacent detached Sigstore bundle at
`<response>.json.sigstore.json`. Local fixture publication keeps the same
path shape with fixture-marked bundle contents. These artifacts do not
yet add runtime query routing or rate limiting.

Because this is a static artifact tree rather than a runtime service,
the attestation bundle is published as a sibling file rather than an
HTTP header or trailer. Verify one response body with
`cosign verify-blob-attestation`, for example:

```bash
cosign verify-blob-attestation \
  --bundle api-fixtures/servers/ac.inference.sh/mcp.json.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Reeve-Security/<signing-repo>/.github/workflows/<signing-workflow>@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --type https://aibom.example/attestation/mcp-registry-api-response/v0.1 \
  api-fixtures/servers/ac.inference.sh/mcp.json
```

## Rate-limit policy for this static slice

The current public hostname for issue #115 is a static artifact tree,
not a runtime router. That means there is no application-enforced quota
or authenticated tiering contract today.

Current client policy:

- treat `api-fixtures/` as a best-effort public snapshot surface;
- cache responses locally instead of re-fetching the same fixture paths
  during a scan;
- prefer the bounded lookup routes (`servers/by-hosted-url/...` first,
  then `search/q/...`) instead of crawling every published server
  fixture;
- treat transport failures, 404s on optional index routes, and future
  host-side throttling as soft failures with graceful fallback.

If issue #115 later grows a runtime-backed API, explicit per-client
limits and any authenticated higher-tier policy should land as a new
contract update rather than being implied retroactively for this static
slice.

## Current CLI consumer slice

`aibom-cli scan` now accepts `--registry-source <url-or-path>` for a
bounded, best-effort lookup pass against this static contract. Point the
flag at the published `api-fixtures/` root, for example:

```bash
aibom-cli scan \
  --target "$HOME" \
  --registry-source https://example.invalid/api-fixtures \
  --skip-sign
```

Current bounded behavior (lookup order per component, ADR-0046):

1. **Synthetic skip.** Scanner-synthetic components (saved approval/grant
   state, presence-only stores such as connector or session-metadata
   stores) are never looked up; they report status `not-applicable` with
   the note "scanner-synthetic component; not a registry artifact".
2. **Purl-exact.** When `--registry-source` points at a local path or
   `file://` tree, the CLI builds an index from each published
   `servers/<publisher>/<name>.json` fixture's declared package
   coordinates (`declaredMetadata.packages[]`, npm and PyPI registry
   types only — purls are never invented for other registry types) and
   matches the discovered component purl after normalization
   (`pkg:npm/%40scope/name` equals `pkg:npm/@scope/name`; qualifiers and
   subpath stripped; version kept). An exact hit reports status
   `matched-purl` with `matchStrategy: "purl-exact"`; coordinates
   published without a version match on the version-less purl form.
3. **Hosted URL.** Exact hosted transport-URL matches (file-tree scan or
   the HTTP `servers/by-hosted-url/<transport>/<sha256>.json` route)
   report status `matched-hosted-url` with `matchStrategy:
   "exact-hosted-url"` (or `"exact-hosted-url+token-search"` when token
   search disambiguated a hosted-URL tie).
4. **Token search last.** `search/q/<normalized-token>.json` lookups from
   component name/purl tokens never report a match. A single top hit
   reports status `candidate` with `matchStrategy: "token-search"`;
   multiple top hits report `ambiguous`.

Report status values in `*.registry-lookup.json`
(`contract: "mcp-registry-static-search-v1"`):

- `not-applicable` — scanner-synthetic component; no lookup attempted.
- `matched-purl` — component purl exactly matched a declared package
  coordinate (strongest public identity signal).
- `matched-hosted-url` — exact hosted transport-URL match (previously
  reported as `matched`).
- `candidate` — single token-search hit; advisory only, never a claimed
  match (previously over-reported as `matched`).
- `ambiguous` — multiple purl, hosted-URL, or token-search candidates.
- `search-match-only` — a search index pointed at a server fixture that
  could not be fetched.
- `no-match` — no stage produced a result.
- `source-unavailable` — the registry source failed mid-lookup.

Other notes:

- the scan still succeeds if the registry source is unavailable or a
  lookup misses; the CLI emits a warning and writes the
  `*.registry-lookup.json` report beside the normal scan artifacts;
- the static HTTP contract has no purl route yet, so HTTP(S) sources run
  stages 1, 3, and 4 only.
