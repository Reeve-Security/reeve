# ADR-0046: Registry lookup is purl-first and token search never claims a match

- **Status:** Accepted 2026-06-11
- **Decides:** Lookup order and status honesty for `aibom-cli scan
  --registry-source` (issue #431, Reeve-side scope only)
- **Related:** ADR-0038, ADR-0044

## Context

`--registry-source` consults a static registry artifact tree
(`docs/mcp-registry-api.md`) to tell the operator which discovered
component corresponds to which published MCP registry server. Before
this decision the only exact signal was the hosted transport URL; every
other component fell through to single-token search, and a single
token hit was reported as status `matched`. That over-claimed: a
scanner-synthetic component such as `claude-code-approval-state`
"matched" the unrelated registry server `vim-mcp` through one shared
token. For a tool whose thesis is evidence, not claims (ADR-0038), a
guessed match labeled `matched` is the worst kind of output.

Meanwhile the registry server fixtures already carry the strongest
public identity signal we have: `declaredMetadata.packages[]` with
`registryType`/`identifier`/`version`, and the scanner already derives
npm purls for stdio components. Nothing connected the two.

Issue #431 also covers corpus rows in the private pipeline repository;
per ADR-0044 that stays out of this repository. This ADR decides only
the public matching primitive — no database, no scheduled capture, no
dataset publication.

## Options considered

### A. Keep hosted-URL-exact plus token-search "matched" (status quo)

Pros: no change. Cons: false matches presented as facts; demos and
reports are dishonest for any component without a hosted URL.

### B. Purl-first exact matching with honest statuses *(chosen)*

Per component, in order: (1) skip scanner-synthetic components
entirely (`not-applicable`); (2) exact normalized-purl match against
declared package coordinates (`matched-purl`); (3) exact hosted
transport-URL match (`matched-hosted-url`, previously `matched`);
(4) token search last, reporting `candidate` for a single hit and
`ambiguous` for ties — never `matched`.

Pros: every `matched-*` status is backed by an exact identity fact;
token search keeps its recall value but is labeled as the guess it is.
Cons: report consumers keyed on the old `matched` status must adapt
(the report `contract` field bumps to `mcp-registry-static-search-v1`).

### C. Drop token search entirely

Pros: simplest honesty. Cons: throws away useful advisory leads for
components with no purl and no hosted URL; `candidate` labeling
preserves the value without the false claim.

## Decision

- A new `registry_match` module owns purl normalization and package
  coordinate extraction. `normalize_purl` lowercases scheme/type,
  percent-decodes then minimally re-encodes path segments (so
  `pkg:npm/%40scope/name` equals `pkg:npm/@scope/name`), strips
  qualifiers and subpath, and keeps the version. It never invents
  fields.
- `package_coordinates_from_server` reads a server fixture's
  `declaredMetadata.packages[]` and derives purls for npm and PyPI
  registry types only. Other registry types carry
  `purl_status: "unsupported-registry"`; coordinates without a version
  carry `purl_status: "no-version"` and match on the version-less purl
  form. Purls are never fabricated for registry types without a defined
  derivation.
- For file-tree sources the existing fixture walk also builds a
  normalized-purl → server-path index. Lookup order per component:
  purl-exact (`matched-purl`), hosted URL (`matched-hosted-url`), token
  search last (`candidate` / `ambiguous`, never `matched`).
- Scanner-synthetic components — grant/approval state providers and
  presence-only stores — are flagged through the existing component
  hints (`synthetic: bool`) and report `not-applicable` with the note
  "scanner-synthetic component; not a registry artifact". A
  conservative name-pattern fallback covers lookups run without hints,
  only for components with no purl and no hosted endpoints.

## Rationale

Reeve records what a tool *says*, *can do*, and *has done* — and a
registry match is a claim about identity, so it must be held to the
same standard as any other fact Reeve emits. Exact purl equality and
exact hosted-URL equality are verifiable identity facts; shared word
tokens are not. Splitting the statuses (`matched-purl`,
`matched-hosted-url`, `candidate`) makes the evidence grade visible in
the report itself instead of flattening everything into `matched`.
Skipping synthetic components closes the embarrassing class of "your
approval cache matched vim-mcp" results at the source: those
components describe the host's saved state, not a publishable
artifact, so a registry lookup is not applicable by construction.

## Plain-language summary

When Reeve scans a machine it can cross-reference the AI tools it finds
against a public registry of MCP servers. Previously, if Reeve could
not match a tool exactly by its server address, it would search the
registry by individual words from the tool's name and present the best
guess as a "match" — so an internal bookkeeping entry like a saved
approvals list could be labeled as some unrelated public server that
shared one word with it. Now Reeve matches first by the tool's package
identity (the same identifier used to install it from npm or PyPI),
then by exact server address, and word-search results are clearly
labeled as unverified candidates instead of matches. Internal
bookkeeping entries are excluded from the lookup entirely.

## Consequences

- **This decision commits the project to:** keeping every `matched-*`
  registry status backed by an exact identity comparison, and labeling
  anything weaker as `candidate`/`ambiguous`.
- **This decision unblocks:** demo-safe registry lookup output and the
  #431 follow-on work that consumes purl-exact matches.
- **This decision forecloses:** reporting token-search hits as matches;
  deriving purls for registry types without a defined mapping.
- **This decision defers:** a purl lookup route in the static HTTP
  contract (today only file-tree sources build the purl index), purl
  derivations beyond npm/PyPI (oci, nuget, mcpb), and all corpus/DB
  rows of #431, which live in the private pipeline repository per
  ADR-0044.

## References

- Issue #431
- `crates/aibom-cli/src/registry_match.rs`
- `crates/aibom-cli/src/main.rs` (`consult_registry_source`,
  `RegistryExactMatchIndex`)
- `docs/mcp-registry-api.md` (Current CLI consumer slice)
- ADR-0038 (evidence, not safety verdicts)
- ADR-0044 (public repository boundary)
