# ADR-0025: Seed the central corpus from the official MCP Registry first

- **Status:** Accepted 2026-05-22
- **Decides:** First implementation slice for issues #111 and #213
- **Related:** ADR-0022, ADR-0023, Issue #111, Issue #213

## Context

The central MCP corpus is Reeve's public reference book: metadata about
public MCP servers that can enrich endpoint inventory without uploading
customer endpoint data. The full corpus plan in #111 includes multiple
sources, scraping, search APIs, storage, and cron. That is too wide for
the first launch-ready slice.

The official MCP Registry now exposes an unauthenticated read-only REST
API for aggregators. The registry is still preview, but its aggregator
documentation explicitly describes `GET /v0.1/servers`, cursor
pagination, and regular but infrequent pulls.

## Options considered

### A. Build the full #111 corpus now

This would include the official registry, community directories, GitHub
search, package registries, Postgres, and cron.

Pros: closer to the long-term moat. Cons: too many legal, storage, and
operational choices in one change; would widen launch scope.

### B. Start with package-registry mining

This would search npm/PyPI for MCP-related packages and normalize those
records first.

Pros: package manifests are useful for provenance. Cons: keyword mining
is noisy, source-specific, and less authoritative than a registry record.

### C. Start with the official MCP Registry seed *(chosen)*

This ingests a captured `GET /v0.1/servers` response, normalizes a small
seed artifact, deduplicates by canonical identity, and signs the seed.

Pros: one public source, no scraping, no hosted service, no customer
data, no Postgres, deterministic tests. Cons: preview API may change and
the seed is not the full corpus.

## Decision

Reeve starts the central corpus with a deterministic official-registry
seed artifact. The first implementation reads a captured official MCP
Registry API page from disk, normalizes records into a Reeve seed JSON
artifact, and emits a Sigstore bundle using the same fixture/real
signing split as other Reeve artifacts.

No live network fetch runs in CI. No scraping, database, cron, or
community-directory ingestion is part of this slice.

## Rationale

This keeps the first corpus slice inside the existing Reeve model:
pull-only public metadata, signed local artifacts, and deterministic
tests. It also honors ADR-0022: Reeve enriches endpoint inventory from a
public reference book, but customer endpoint evidence never flows back
into that reference book.

The official registry is the lowest-risk first source because it provides
a documented read API and terms for registry data. Later sources can
reuse the same normalized identity and dedupe vocabulary after their
storage and ToS questions are separately recorded.

## Plain-language summary

Think of the corpus as Reeve's public phone book for MCP servers. The
endpoint scanner says, "this laptop has server X." The corpus can say,
"server X appears in the public registry with this publisher, version,
description, and transport metadata."

We are not building the whole phone company yet. We are printing the
first small phone book page from the official source and signing it.

This first page is deliberately boring. It comes from one official API
response. It is normalized into a stable shape. It has a dedupe key so
future sources can match the same server without double-counting it. It
gets signed so demo and launch material can say the seed artifact itself
has evidence integrity.

This does not mean Reeve has a hosted corpus service, scraper farm, or
customer telemetry loop. It means Reeve has the first signed public
metadata artifact that future corpus work can extend.

## Consequences

- **This decision commits the project to:** official-registry seed
  artifacts with canonical identity, source URL, registry metadata,
  declared server metadata, dedupe key, deterministic bytes, and
  Sigstore bundle.
- **This decision unblocks:** issue #213 and optional demo Scene 9 once a
  signed seed artifact exists.
- **This decision forecloses:** calling scraped community directories,
  Postgres storage, or cron mandatory for the first seed.
- **This decision defers:** mcp.so, PulseMCP, GitHub GraphQL, npm/PyPI,
  storage ADR, and scheduled refresh.

## References

- Official registry aggregator docs:
  https://modelcontextprotocol.io/registry/registry-aggregators
- Official registry terms:
  https://modelcontextprotocol.io/registry/terms-of-service
- ADR-0022: `docs/decisions/0022-config-reader-not-proxy.md`
- ADR-0023: `docs/decisions/0023-demo-fleet-recording-scope.md`
