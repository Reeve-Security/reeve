# ADR-0005: Capability taxonomy — closed core vocabulary plus namespaced extensions, expressed as structured capability objects

- **Status:** Accepted 2026-04-21
- **Decides:** Q5 from `schema/SPEC.md` — capability taxonomy
- **Related:** ADR-0001 (sidecar carries capability evidence); ADR-0002 (core vocab grows per schema version); ADR-0003 (capability objects participate in JCS + deterministic array order); ADR-0004 (capability content is signed-over, not trust-bearing)

## Context

Every AIBOM entry must express two capability sets per component:
**declared** (from the tool's self-description; for MCP, derived
from `tools/list`, `resources/list`, `prompts/list` and the input
schemas attached to each) and **observed** (from sandbox
instrumentation). The difference between the two — the capability
delta — is a first-class finding in `docs/architecture.md`
§"Evidence layers in an AIBOM entry."

Two pressures point in opposite directions:

1. **Policy enforceability and cross-tool aggregation** favor a
   closed, canonical vocabulary. Rego policies reference stable
   ids; delta computation is set difference over known strings;
   v2+ reputation counters aggregate capability incidence across
   the install base.
2. **v2+ adapter extensibility** favors openness. Non-MCP adapters
   (OpenAI function-calling, LangChain tools, Google A2A, whatever
   ships in a 2028 ecosystem) must be able to contribute
   capabilities without waiting on a v1 schema rewrite.

Q5 resolves that tension.

## Options considered

### A. Closed vocabulary (versioned, SPDX-license-list style)

- ✅ Machine-enforceable, fully canonical, clean delta and
  aggregation.
- ❌ Every new capability requires a schema version bump. v2+
  adapters blocked on schema releases. Adapter-specific internals
  (MCP protocol operations) bloat the core vocab or get lost.

### B. Freeform strings with recommended conventions

- ❌ No enforcement. Two adapters emit `fs:read` and
  `filesystem:read` for equivalent behavior; delta breaks;
  policies break. Reputation aggregation loses power — cannot
  count tools that "do `fs:read`" if the string varies.
- Rejected.

### C. Hybrid — closed **core** vocabulary plus namespaced **extension** vocabulary, both expressed as structured capability objects *(chosen)*

- Core capabilities (cross-adapter-relevant, policy-addressable):
  closed, schema-registered, versioned.
- Extension capabilities (adapter-specific or vendor-specific):
  open, under a registered namespace or a reverse-DNS namespace.
- Both carry full structure (id + qualifiers + source + evidence
  refs), not raw strings.
- ✅ Policies continue to work against core ids without caring
  about extension vocabulary.
- ✅ v2+ adapters ship capabilities under their namespace without
  a schema bump.
- ✅ Structured qualifiers expose policy-relevant detail (host,
  port, path, env var) in fields a validator can check, rather
  than stringly-typed suffixes.
- ❌ Two validation rules (core = closed enum of ids and
  qualifier keys; extension = namespace grammar with freeform
  qualifiers). Small added complexity; matches reality.

## Decision

**Capability taxonomy is a hybrid: a closed core vocabulary plus
namespaced extensions, with every capability expressed as a
structured object.** Declared and observed capabilities live in
separate arrays per component; the delta is derivable and is never
stored.

### Capability object

```json
{
  "id": "net:egress",
  "qualifiers": {"host": "api.example.com", "port": 443},
  "source": "declared",
  "evidence": ["ev-001", "ev-002"]
}
```

- `id` (required, string) — a core id or an extension id. See
  below.
- `qualifiers` (required, object; may be empty) — key/value
  narrowing. Core ids use schema-defined qualifier keys (see
  registry). Extension ids use adapter-/vendor-defined qualifier
  keys under their namespace.
- `source` (required, enum) — `"declared"` or `"observed"`.
  Redundant with the array the entry lives in, but present for
  Rego ergonomics when policies flatten capabilities. **Schema
  MUST enforce:** every entry in `capabilities.declared[]` has
  `source == "declared"`; every entry in `capabilities.observed[]`
  has `source == "observed"`. Mismatch rejects at validation.
- `evidence` (required, array of evidence-record ids;
  **minItems: 1**) — references into the sidecar's evidence
  ledger. Every capability MUST cite at least one evidence record.
  For declared capabilities, the evidence reference is to the
  source declaration fragment (e.g., the MCP `tools/list`
  response entry). For observed capabilities, the reference is to
  the sandbox trace entry.

**v0.1 does not include a per-capability `confidence` field.** See
*Rationale* for the deferral reasoning; see *Consequences → defers*
for re-entry path.

### Core vocabulary (v0.1, closed)

Eight ids. Schema validation rejects any core id not in this list
and any qualifier key not in the allowed set for its id.

| Core id | Allowed qualifier keys |
| --- | --- |
| `fs:read` | `path` |
| `fs:write` | `path` |
| `net:egress` | `host`, `port`, `scheme` |
| `net:listen` | `port`, `scheme` |
| `exec:subprocess` | `cmd`, `argCount` |
| `env:read` | `name` |
| `secret:read` | `ref` |
| `ipc:connect` | `peer` |

**Deliberate omissions from the v0.1 core (deferred to v1.x):**

- `fs:delete` folds into `fs:write` for v0.1. Distinct delete
  semantics return in v1.x if policy demand materializes.
- `fs:execute` folds into `exec:subprocess` for v0.1.
- `net:resolve`, `env:write`, `ipc:signal` are not referenced by
  any v1 default policy; emitters with observations that
  conceptually fit those ids should either suppress them or emit
  under an adapter-namespaced extension id until the core vocab
  expands.
- `process:fork`, `process:thread` are too low-level for v0.1 —
  sandbox emitters routinely produce many such events; including
  them as core ids floods the capability set without policy
  leverage.
- Database capabilities (`db:read`, `db:write`) — MCP tools
  rarely touch raw DB connections. Add in v1.x if demand
  materializes.

**Inclusion criterion for v0.1 core:** the id is referenced
(directly or as a base-id prefix) by at least one of the ten v1
default policies in `policies/README.md`, OR is central to the MCP
adapter's declared-capability derivation path. Every id in the
v0.1 registry meets this criterion. Expansion of the core
vocabulary in later schema versions follows ADR-0002 (0.x minor =
compatibility boundary; 1.x minor = additive-only).

### Core qualifier semantics (v0.1)

- `path`: absolute POSIX path; or a path prefix ending in `/` to
  denote "any descendant." **Prefix `/tmp/` matches descendants
  of `/tmp/`, not `/tmp` itself.** For the directory itself,
  emit the exact path (`/tmp`). Paths are POSIX-only for v0.1/v0.2.
  Windows drive-absolute and UNC grammar is added by ADR-0026 in
  v0.3. Glob grammar deferred to v1.x.
- `host`: DNS name or IP literal; `*` permitted in leftmost label
  for wildcard subdomain match (e.g., `*.openai.com`).
- `port`: integer 1–65535.
- `scheme`: enum `"http"` | `"https"` | `"tcp"` | `"udp"` |
  `"tls"`.
- `cmd`: basename only; never full argv (evidence captures argv
  separately).
- `argCount`: integer.
- `name` (env var): the environment variable name, not value.
- `ref` (secret): an opaque secret identifier — a name, a path,
  a store-specific URI. **Never the secret value.**
- `peer` (IPC): adapter-defined.

Qualifiers are emitted as narrowly as the evidence supports. An
observer with no host information for `net:egress` emits an empty
qualifier object; a policy can still match the base id.

### Extension vocabulary

Extension ids use the form `<namespace>:<subpath>` where the
namespace is either **registered** or a **reverse-DNS** string.
v0.1 registers only the `mcp` adapter namespace. **Single-label
namespaces outside the registry (`openai:`, `foo:`, `docker:`,
`langchain:`, etc.) are reserved and invalid until formally
registered in a future schema version.** Vendors needing a
namespace today use reverse-DNS.

**Schema grammar for `id`** (enforced at validation):

```
core id               = one of the enum values in the core registry above
registered adapter id = ^(mcp):[a-z0-9][a-z0-9:-]*$
reverse-DNS id        = ^[a-z0-9]+(\.[a-z0-9-]+)+:[a-z0-9][a-z0-9:-]*$
```

Any id not matching one of these three patterns is rejected at
schema validation.

Examples:

- Valid core: `fs:read`, `net:egress`.
- Valid registered adapter: `mcp:resource:expose`, `mcp:prompt:list`.
- Valid reverse-DNS: `com.example.product:custom-op`,
  `io.anthropic.mcp:resource:batch-expose`.
- **Invalid:** `openai:tool-call` (single-label, not registered),
  `foo:bar` (single-label, not registered), `com.example:op`
  (reverse-DNS requires at least two DNS labels), `FS:READ` (core
  ids are lowercase), `fs:chmod` (core-looking but not in the
  registry).

Extension `qualifiers` are freeform — the namespace owner defines
the shape. Schema does not validate qualifier keys under extension
ids. Policies that reference extension ids do so at their own risk
of vocab drift.

### Validation rules

Schema-level:

- `id` MUST match one of the three grammars above.
- **Core-looking but unregistered** ids (single-label namespace
  matching `^[a-z]+:` that is neither a registered adapter
  namespace nor a reverse-DNS form) are rejected.
- Qualifier keys for core ids MUST be in the allowed set for that
  id. Extension qualifier keys are unchecked.
- `evidence` array MUST contain at least one element
  (`minItems: 1`).
- `source` field MUST match the array the capability lives in
  (`declared` array → `source: "declared"`; `observed` array →
  `source: "observed"`).

Policy-level (enforced at `aibom policy check`):

- **Policy #11 — `no-unknown-extension-capability`** (new default
  policy — see *Consequences*): warn by default when a
  capability's id is in an extension namespace not present in the
  consumer-configured extension-namespace allowlist. Deny under
  `strict` profile. **Policy #11 is appended to
  `policies/README.md`; the existing ten default policies keep
  their numbers unchanged** (stable policy numbers matter once
  cited by external references).

### Separate declared / observed arrays; derived delta

Capabilities live on each component under two separate arrays:

```json
{
  "bom-ref": "mcp:filesystem@2.3.1",
  "capabilities": {
    "declared": [ /* capability objects */ ],
    "observed": [ /* capability objects */ ]
  }
}
```

- Arrays are tagged `set` per ADR-0003; ordering rule:
  **lexicographic by `id`, then by JCS canonicalization of the
  `qualifiers` object as tiebreaker.** `source` is not part of
  the tiebreaker because it is constant within a single array
  (enforced at schema validation).
- The delta (`observed − declared` and `declared − observed`) is
  computed by consumers at policy-evaluation time. It is not
  stored in the sidecar. Delta matching is by `(id, qualifiers)`
  — evidence references are not part of identity.
- Delta computation only considers **core ids**. Extension ids
  are descriptive, not behavioral — they do not contribute to
  delta findings.

### Merging rule

Within a single array (`declared` or `observed`) of a single
component, two capability entries with the same `(id, qualifiers)`
pair MUST be merged into one entry by the emitter. The merged
entry's `evidence` array is the union (deduplicated, lexicographic
sort) of the contributing evidence references. `source` is
preserved (it is already fixed by the array).

Qualifier equality is structural: same keys, same values. An entry
with qualifiers `{host: "a.com"}` does not merge with an entry with
qualifiers `{host: "a.com", port: 443}` — the latter is more
specific and remains distinct.

## Rationale

**Why closed core + open extension, not one or the other.** Every
default policy in `policies/README.md` addresses a cross-cutting
behavior: signatures, transports, egress, subprocess, version
drift. None of them look inside a specific adapter's protocol
semantics. Closing the policy-addressable vocabulary protects every
policy in the catalog from emitter drift. Leaving the adapter
namespace open protects the project from the common failure mode
where a taxonomy ossifies and the ecosystem routes around it. The
core is where enforcement lives; the extension is where
description lives.

**Why structured capability objects, not raw strings.** The
qualifier space is where policies express most of their precision
("block egress except to `api.openai.com`"). Encoding qualifiers as
string suffixes (`net:egress:api.openai.com`) conflates id with
value and makes JCS serialization fragile. A structured
`qualifiers` object makes policy input typed, lets the schema
enforce which qualifier keys are valid per id, and keeps JCS
canonicalization clean (object keys sort; string parsing does not
enter the signing path).

**Why reject core-looking unregistered ids.** Without this rule,
any emitter can invent `fs:chmod` and every consumer has to decide
whether to treat it as a core capability or not. Rejecting the id
at schema validation forces the question back to the vocab
registry, where it belongs. Extension namespaces exist precisely
so that an emitter that needs a new capability doesn't have to
fight the core — it can ship its capability under
`com.emitter.project:*` today and propose core registration on a
longer timeline.

**Why reserve single-label namespaces for registration only.**
Single-label namespaces like `openai:`, `langchain:`, `docker:`
carry strong implicit meaning and are the natural fit for future
adapters. Leaving them open would let an emitter squat `openai:*`
today before the real OpenAI adapter is specified, causing a
collision when the adapter arrives. Reserving them means the
schema — not whichever emitter shipped first — decides what
`openai:*` means. Vendors can still describe their product-
specific capabilities today using reverse-DNS (`com.openai.*`);
the short form waits for registration.

**Why declared and observed live in separate arrays rather than a
flat list with a `source` field.** Both shapes produce the same
delta, but the separate-arrays shape makes the common operation
(read declared; read observed; compute delta) a field access
rather than a filter. It also keeps JCS ordering rules per-array
rather than per-entry. The `source` field in the capability object
is kept anyway for ergonomics when a policy iterates flattened
capabilities; the schema enforces consistency so the two
representations cannot drift.

**Why evidence is required (minItems: 1).** A capability with no
evidence reference is a claim without provenance — exactly the
thing Reeve is built to eliminate. Declared capabilities cite the
source schema fragment (MCP `tools/list` response entry, etc.).
Observed capabilities cite the sandbox trace entry. A capability
in the sidecar with an empty evidence array is a data-quality bug;
surfacing it at schema-validation time prevents the bug from
propagating.

**Why confidence is deferred from v0.1.** The initial proposal
included a `confidence` field (`high` / `medium` / `low`) on the
capability object. Reviewing it, the semantics are load-bearing
and ambiguous: a declared capability's confidence is "high by
construction" — but that would mean "the tool said it clearly,"
not "the tool is telling the truth." Policies that read
`confidence` for trust decisions would misread the field. The
safer v0.1 position is no such field. If a future version adds a
confidence concept, it belongs on **evidence records** (where it
describes confidence in the evidence-to-capability mapping, not
trust in the claim), and should be renamed
(`evidenceConfidence`) to prevent the misreading. Policies should
not read such a field for allow decisions in v0.1 even if an
emitter adds one under an extension namespace.

## Plain-language summary

Every tool that runs on a computer has a set of things it can do —
read files, send network traffic, launch other programs, read
environment variables. Our AIBOM records two versions of that set
per tool: what the tool *says* it can do (`declared`) and what the
sandbox *caught* it doing (`observed`). The difference between the
two is where most supply-chain surprises hide.

To make those sets useful — to policies, to dashboards, to
auditors — every tool needs to describe its capabilities using the
*same words*. If one scanner writes `fs:read` and another writes
`filesystem:read` for the same behavior, nothing can compare
them. So we need a shared vocabulary.

But we also don't want the shared vocabulary to be a prison.
Tomorrow someone will want to describe an AI-specific capability
we didn't anticipate, or a vendor-specific operation that only
matters for their product. If the vocab is locked, they have to
wait for us to release a new version. If we make them wait, they
route around us and the vocabulary fragments anyway.

Our answer is **two vocabularies in one schema**.

**The core vocabulary is closed.** It has a small fixed list for
v0.1 — eight names — covering file reads and writes, outbound and
inbound network traffic, subprocess execution, environment-
variable reads, secret reads, and inter-process connections. Our
default policies enforce rules on these names. If a tool emits a
name that looks like a core name but isn't in the list (say,
`fs:chmod`), validation fails — you cannot silently invent core
capabilities. You can propose adding `fs:chmod` to the core in a
future schema version. Until then, it doesn't exist at the core
level. We deliberately started with a small list; additions happen
when a real policy needs them, not speculatively.

**The extension vocabulary is open**, under a namespace. Anything
an adapter or vendor needs to describe that isn't in the core goes
under a namespace. Registered short-form namespaces (`mcp:` for
now; future adapters like OpenAI or LangChain get their short
forms later) are reserved — nobody can squat them. Anyone may use
a reverse-DNS namespace (`com.example.product:`) immediately. The
schema doesn't check what's inside those names. You can ship a new
extension capability the same day you discover you need it. The
tradeoff: policies don't enforce extension names tightly. A
default policy warns whenever a capability comes from a namespace
you haven't told the verifier to trust.

**Each capability is a small structured object**, not a string. It
carries an id, a set of qualifiers (narrowing details like host
names and paths), a source flag (declared vs observed), and
pointers to the evidence records that support it. Every capability
must cite at least one evidence record — no evidence, no
capability. Two-host egresses from the same tool (`api.openai.com`
and `logs.example.com`) produce two capability objects with two
different qualifier sets, not one blob of concatenated strings.

Declared capabilities and observed capabilities live in separate
arrays on each component. The delta between them is computed on
demand — "this tool said it would only read files, but it opened a
socket to somewhere the publisher didn't declare" — and it is
never stored, because storing derived data invites staleness. The
delta is always the current set difference of the two arrays.

## Consequences

**This decision commits the project to:**

- A closed core capability vocabulary of **eight ids** (the v0.1
  registry above) with schema-defined qualifier keys per id.
- An extension vocabulary under **registered adapter namespaces**
  (v0.1 registers only `mcp`) and **reverse-DNS namespaces** (two
  or more DNS labels). Single-label namespaces outside the
  registry are reserved.
- Every capability is a structured object — `id`, `qualifiers`,
  `source`, `evidence[]` (minItems: 1). No raw-string capability
  encodings. **No per-capability confidence field in v0.1.**
- Declared and observed capabilities live in separate arrays per
  component; schema enforces `source` matches the array; delta is
  derived, not stored.
- Rejection at schema validation of: core-looking unregistered
  ids; qualifier keys outside the per-id allowed set; empty
  evidence arrays; source/array mismatches; single-label
  unregistered namespaces.
- Merging rule within a single component-array: entries with the
  same `(id, qualifiers)` are collapsed into one with evidence
  union.
- ADR-0003 ordering for capability arrays: lexicographic by `id`,
  then by JCS canonicalization of `qualifiers` as tiebreaker.
  `source` is not a tiebreaker (constant within array).
- **Policy #11 — `no-unknown-extension-capability`**, appended to
  `policies/README.md`. **The existing ten default policies keep
  their numbers unchanged.**
- POSIX-only `path` qualifier grammar for v0.1 (absolute path or
  prefix ending in `/`; descendants-of semantics).

**This decision unblocks:**

- Fixture drafting (task #6): fixtures carry real structured
  capability objects with MCP-namespace extensions and core-vocab
  entries.
- Sandbox-adapter implementation: the MCP adapter's `profile`
  step has a concrete target vocabulary to translate syscall /
  network evidence into.
- Rego policy authoring: policies reference stable core ids with
  typed qualifiers.
- v2+ adapter onboarding: a new adapter registers its namespace
  (in a new schema version) and ships extension capabilities
  without reopening Q5.

**This decision forecloses:**

- Raw-string capability encodings (`"net:egress:api.openai.com"`
  as a single string).
- Silent expansion of the core vocabulary. New core ids are
  schema-version concerns.
- Qualifier keys outside the schema-defined set for core ids.
- Storing the capability delta in the sidecar. Always derived.
- Squatting of single-label namespaces (`openai:`, `langchain:`,
  `docker:`, etc.) by emitters ahead of formal registration.
- Renumbering of existing default policies when new policies are
  added.

**This decision defers:**

- **Per-capability confidence field.** If re-added, it must be
  renamed (`evidenceConfidence`) and restricted to describing
  evidence-to-capability mapping quality, not trust in the claim.
  Policies must not read it for allow decisions until semantics
  are fully specified.
- Glob grammar for `path` qualifiers (v1.x).
- Core-vocab additions: `fs:delete` (distinct from `fs:write`),
  `fs:execute` (distinct from `exec:subprocess`), `net:resolve`,
  `env:write`, `ipc:signal`, `process:fork`, `process:thread`,
  DB capabilities. Add in v1.x when policy demand materializes.
- Registration mechanism for new adapter namespaces beyond `mcp`
  (v2+ adapter onboarding process).
- Upstream proposals of core ids to a broader standardization
  body (build-order step 5).

## References

- `schema/SPEC.md` §"Resolved decisions"
- `docs/architecture.md` §"Evidence layers in an AIBOM entry"
- `docs/v1-spec.md` §"MCP adapter (v1 scope)"
- `policies/README.md` (ten initial default policies; Policy #11
  added as a consequence of this ADR)
- ADR-0001 (sidecar carries component capability arrays)
- ADR-0002 (core vocab grows per schema version; 0.x minor =
  compatibility boundary)
- ADR-0003 (capability arrays are set-ordered; qualifier objects
  participate in JCS)
- ADR-0004 (capability content is signed-over; verified-vs-claimed
  separation means capability content is claimed data)
- SPDX License List (model for a closed, versioned, canonical
  vocabulary with an extension mechanism)
- Linux capabilities (`man capabilities(7)`) — closed vocabulary
  precedent
- macOS entitlements — reverse-DNS closed vocabulary precedent
- Android permissions — reverse-DNS closed vocabulary precedent
- OCI seccomp profiles — freeform vocabulary (rejected pattern
  for policy-bearing ids)
