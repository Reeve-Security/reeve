# ADR-0020: Demo fleet is a phased, department-flavored, populated dataset — not the validation fleet

- **Status:** Accepted 2026-05-14
- **Decides:** How Reeve produces a demonstrable end-to-end story that a founder, a prospect, or a reviewer can verify by running the tool against a varied, realistic dataset. Separate question from the existing release-validation fleet.
- **Related:** ADR-0007 (live Sigstore acceptance), ADR-0009 (Linux profiling fallback), ADR-0012 (Blacksmith runner substrate), ADR-0018 (empty discovery is valid inventory), ADR-0019 (conversation-log sensitive-data report). Memory note: `reference_reeve_infra.md`.

## Context

Two pressures arrived together:

1. **The marketing site claims a story the validation fleet does not exercise.** The
   existing `run-fleet.sh` harness validates 13 Linux + 5 macOS release profiles per
   release. Those profiles confirm the binary installs, signs, runs the scheduled
   scan, and produces an AIBOM matching expected-output assertions. They do **not**
   produce a populated, varied, department-flavored dataset that demonstrates the
   pain Reeve is built to surface: vulnerable MCP servers, planted secrets in chat
   logs, mixed always-allow / allow-once approvals, multi-vendor AI assistants
   across multiple non-developer personas.
2. **The founder will not endorse marketing claims until the tool has been shown
   producing the inventory those claims describe, end to end, against a varied
   fleet.** This is a non-negotiable confidence gate, and a correct one: every
   public claim is a contract, and claim audit (see Track A elsewhere in this
   work cycle) cannot rule on PARTIAL items without a running example to point at.

The release-validation fleet (13 + 5 profiles) is an acceptance gate. It is the
right artifact for that job and it stays. What it is not is a demonstration
artifact. We need a second, distinct fleet whose purpose is to make Reeve's
output legible to a non-technical reviewer.

The new fleet must be:

- **Varied along five dimensions** so the demo shows breadth, not one canonical
  case: department persona, AI assistants installed, MCP servers (vulnerable / clean /
  over-privileged / unsigned / typo-squatted), chat-log content (planted secrets vs
  clean), and approval state.
- **Provisioned reproducibly** so the demo dataset is itself reviewable evidence,
  not a hand-curated snapshot a skeptic cannot reproduce.
- **Affordable enough to keep running** for as long as we need to iterate on
  Reeve's output and the public copy that describes it.
- **Aligned with the existing infrastructure** (Hetzner Cloud for Linux, Tart on
  the Mac mini fleet for macOS) so we do not maintain two parallel provisioning
  stacks.

## Options considered

### A. Build the full 50-endpoint fleet immediately, all five departments × 10 endpoints each, Linux + macOS, populated end to end before any demo iteration

Pros:
- One-time investment; demo dataset is rich from day one.
- Pressure-tests scale earlier (50 endpoints is closer to a small-org reality
  than 20 is).
- Public demo URL (issue #158) can launch directly off this fleet.

Cons:
- High up-front cost: 50 Linux Hetzner CX22 ≈ €200/month; macOS via Tart on
  existing fleet adds capacity pressure on the Mac mini host. Total fleet cost
  realistic at €250-350/month before optimization.
- Long lead time to first demo iteration: provisioning, role authorship, MCP
  catalog, secret planting, and approval planting are all new code; getting all
  five dimensions varied across 50 hosts before showing the founder anything is
  weeks of work.
- Risks over-investing in the wrong demo shape before we know which dimensions
  the founder, customers, and analysts care about most.

### B. Record-replay against a small synthetic dataset (no real fleet), generate fake scan output as marketing video

Pros:
- Cheapest. Fastest to publish.

Cons:
- Defeats the founder's stated requirement ("not comfortable until I see it in
  action"). The whole point of the demo is verification, not video.
- Reeve's entire thesis is "evidence anyone can re-run." A demo that cannot be
  re-run is the worst possible artifact for this product.
- Synthetic data tends to be too clean: real Reeve output includes oddities,
  edge cases, signing failures, surface mismatches. Hiding those defeats the
  pitch.

### C. Phased rollout: Phase 1 = 20 endpoints, Linux-only, populated end to end; Phase 2 = expand to 50 with macOS mix; Phase 3 = public-facing demo URL *(chosen)*

Pros:
- Phase 1 (~€80/month) costs ~⅓ of full fleet and proves the end-to-end pipeline:
  provisioning, planting, scanning, aggregating, presenting. Founder can verify
  the story before we scale.
- Each phase is a real demo, not a rehearsal. Phase 1 alone is enough to drive
  internal review, claim-audit grounding, and an analyst conversation.
- Failures discovered in Phase 1 (role bugs, MCP-server picks, secret patterns
  that the scanner does not yet catch) are cheap to fix at 20 endpoints; they
  would be expensive at 50.
- Phases naturally align with existing GitHub issues: Phase 1 lives inside the
  new demo-fleet epic; Phase 3 lives inside the existing #157 (static fleet
  aggregator) and #158 (public demo site) issues.
- Cost stays under control: Phase 1 spins down between demo runs if needed;
  Phase 2 commits to a steady-state spend only after Phase 1 proves the
  artifact is worth keeping live.

Cons:
- Two rounds of provisioning and role iteration vs one.
- Phase 1 is Linux-only — does not yet exercise the macOS sandbox-exec
  profiling path on demo endpoints. Mitigated by the existing 5-profile macOS
  release-validation fleet, which covers the macOS path for acceptance even
  while the demo fleet is Linux-only.

### D. Hand-curated single-endpoint demo (one carefully populated laptop, recorded scan)

Pros:
- Trivial to build.

Cons:
- Cannot demonstrate fleet-level claims (Step 04 "Assess", drift, cross-endpoint
  aggregation). Those are the most-contested claims in the current site copy
  precisely because they require multi-endpoint evidence.
- Worse than C in every dimension that matters for founder confidence.

## Decision

**Adopt Option C.** Build the demo fleet in three phases. Each phase is a complete
demo at its scale; the next phase is gated on the prior phase succeeding.

**Phase 1 — 20 endpoints, Linux-only, end-to-end populated.** Five department
personas × 4 endpoints each: engineering, marketing, finance, HR, sales. Each
endpoint is provisioned by Terraform (Hetzner Cloud), configured by Ansible roles
(one role per persona), and populated with a planted dataset on a planting role.
Reeve is installed via the production curl-install path on every endpoint, runs
the scheduled scan, and the resulting AIBOMs are aggregated to a single signed
fleet bundle. A static-site renderer produces an internal-only demo page from
that bundle.

**Phase 2 — expand to 50 endpoints, add macOS coverage.** Add 30 endpoints across
the same personas plus two new ones (executive, IT-admin). 10 of the new
endpoints are macOS via Tart on the existing Mac mini host, picked to exercise
the desktop-app-only surfaces (Claude Desktop without Claude Code, Codex App
without Codex CLI). The remaining 20 are additional Linux endpoints to
populate the long tail of department × assistant combinations.

**Phase 3 — public-facing demo URL.** Once Phase 2 has been running for ≥2
weeks of nightly scan refreshes without manual intervention, the demo dataset
is wired to a public-facing static site (issue #158) for analyst, prospect, and
press review. Public access is read-only; the data behind it is a fixed scan
snapshot refreshed on a schedule, never live.

**Variation matrix.** Every phase populates endpoints along five dimensions, with
the variant list locked at ADR time so reviewers can audit what the demo is and
is not exercising:

| Dimension | Variants in Phase 1 |
|---|---|
| Department persona | engineering · marketing · finance · HR · sales |
| AI assistants installed | Claude Desktop · Claude Code · Codex CLI · Codex App · Cursor · Continue · Zed · VS Code MCP · Antigravity *(if reachable)* · pi.dev *(if reachable)* |
| MCP servers | clean signed current · clean unsigned · vulnerable (pinned CVE in deps) · over-privileged-by-design (declares "read file" / observed touches network) · typo-squatted (e.g. `mcp-filesystem` vs `mcp-filesytem`) |
| Chat-log content | clean · planted AWS access keypair · planted Stripe API key · planted OpenAI API key · planted Anthropic API key · planted OAuth client secret |
| Approval state | no approvals · allow-once only · saturated always-allow · mixed |

**Role catalog.** Each department persona is a single Ansible role that asserts:

- which AI assistants are installed (declared in role variables)
- which MCP servers are configured per assistant
- which chat-log contents are written (using a separate `planted-secrets` role
  invoked by the persona role with department-flavored content)
- which approvals are pre-written into the surface config (using a separate
  `approval-state` role)

Roles are department-flavored but build on shared sub-roles so MCP catalog and
conversation-secret fixtures are not duplicated. PII, customer-list, and
non-public-data classifiers are deliberately out of Phase 1 until issue #184
decides whether Reeve should classify them at all. The role catalog is itself
committed to the repository so the demo dataset is reproducible from clean
Terraform + Ansible on any contributor's machine.

**Provisioning stack.** Terraform module `infra/demo-fleet/terraform/` targets
the Hetzner Cloud provider (already used by `run-fleet.sh`) for Linux and
documents the manual provisioning of macOS-via-Tart for Phase 2. Ansible
playbooks live in `infra/demo-fleet/ansible/` with role-per-persona and
shared sub-roles for MCP catalog, secret planting, and approval planting.

**Aggregation.** Scan results from each endpoint are uploaded to a known S3
bucket (or equivalent) and fed to the existing static fleet aggregator (issue
#157). The aggregator emits a single signed fleet AIBOM bundle that is the
demo's canonical artifact.

## Rationale

This decision honors three existing commitments:

- **Founder-conviction launches and the public contract-test corpus** (per
  `docs/v1-spec.md` §Next step and `CLAUDE.md`). The contract-test corpus is for
  schema fidelity; the demo fleet is for behavioral fidelity. Both are required
  for credible launch.
- **Scanners are an attack surface** (per `CLAUDE.md` §Security thesis). The
  demo fleet exercises Reeve against vulnerable MCP servers and typo-squatted
  packages — i.e., it puts Reeve in the situation the security thesis is about
  and confirms the scanner does not get owned by what it scans.
- **Track all TODOs as GitHub issues** (per `feedback_track_todos_as_issues.md`
  and repo issue #103). Every concrete sub-task that comes out of this ADR is
  filed as a GitHub issue immediately upon ADR acceptance.

Phasing is the right cost discipline. Reeve is pre-launch; €80/month for Phase 1
is defensible founder spend and lets us iterate on what a Reeve demo actually
should show. €250-350/month for the full 50 + macOS fleet without first
validating the demo's shape is premature.

The variant matrix is locked at ADR time on purpose. The five dimensions are
the dimensions of Reeve's value proposition. Picking which variants populate
the fleet is a *design decision*, not a tactical one — if we pick the wrong
variants, the demo will fail to demonstrate the points the copy makes.

## Plain-language summary

Reeve's job is to inventory the AI assistants on your computers and prove
the inventory is real. To demonstrate that, we have to point Reeve at a
realistic set of computers and have it produce a realistic inventory. The
release validation fleet we already operate proves Reeve installs and
runs correctly on 18 different machine profiles. That is necessary, but
it is not a demo — those machines are deliberately clean, because their
job is to show "did the binary install" not "does Reeve actually find
the interesting stuff."

This decision creates a second, separate fleet whose job is the demo.
It is built in three steps so we can correct course cheaply:

1. **Phase 1 (~€80/month, ~20 cloud machines).** Five departments —
   engineering, marketing, finance, HR, and sales — with four machines
   each. Each machine is populated to look like a real employee's
   laptop: their AI assistants installed, their connected services
   configured, their chat history written with planted test secrets,
   their approvals clicked.
   Some of those AI tools are deliberately bad — they ship with
   known-vulnerable packages, or claim they can only read files but
   secretly call out to the network, or have been mistyped so they
   look like the real package but are actually a fake. Reeve scans
   all of them. We see what shows up in the inventory and the report
   becomes the demo.

2. **Phase 2 (~€250-350/month, ~50 machines, adds Macs).** Once Phase 1
   proves the story, expand to a full small-organization shape, add
   Macs (where Claude Desktop and the Codex App actually live), and
   add executive and IT-admin endpoints so the demo covers the
   non-technical-leadership end of the spectrum.

3. **Phase 3 (no incremental cost — issue #158).** Wire the demo
   inventory to a public-facing static page on the website so that
   analysts, prospects, and the press can re-run the same inventory
   against the same data themselves and verify it.

Phasing lets us discover what's wrong with the demo while it's still
cheap to fix. If we built all 50 machines on day one with a story that
doesn't land, we'd have to tear them all down. Twenty machines we can
rebuild in an afternoon.

The variation across machines is deliberate. A demo that shows Reeve
finding the same thing on every laptop demonstrates nothing. A demo
that shows Reeve finding *different* things on the engineering laptop
versus the marketing laptop versus the finance laptop demonstrates
that Reeve adapts to the realities of an organization — which is the
whole point of the product.

## Consequences

- **This decision commits the project to:**
  - A new directory `infra/demo-fleet/` containing `terraform/` (Hetzner
    Cloud module for Linux endpoints) and `ansible/` (one role per
    department persona, plus shared sub-roles for MCP catalog, secret
    planting, and approval planting).
  - A locked variant matrix for Phase 1 (the table above). Adding a
    new variant requires either expanding the matrix in this ADR or
    superseding the ADR.
  - A new GitHub epic for Phase 1 with sub-issues per Ansible role,
    per Terraform module, and per aggregation step.
  - Demo dataset is reproducible from clean Terraform + Ansible — no
    hand-curated state allowed.
  - The fleet's signed AIBOM bundle is the canonical demo artifact;
    no derived material may make a claim the bundle does not support.
- **This decision unblocks:**
  - The claim audit (Track A) can resolve PARTIAL items by pointing to
    Phase 1 fleet output as evidence — or, if Phase 1 fails to produce
    the evidence, by pulling the corresponding claim from public copy.
  - Issue #157 (static fleet aggregator) gets a real input dataset.
  - Issue #158 (public demo site) gets a real source.
  - The decision to publish or pull named cyber-insurance carrier
    language is unblocked: once Phase 1 is running, the demo itself
    is enough evidence to ground an analyst conversation that
    surfaces real carrier supplements.
- **This decision forecloses:**
  - Single-endpoint demo as the primary marketing artifact (Option D
    is rejected).
  - Synthetic / pre-recorded demo as the primary marketing artifact
    (Option B is rejected).
  - Big-bang 50-endpoint provisioning before Phase 1 acceptance
    (Option A is rejected).
- **This decision defers:**
  - Whether Phase 3 ever opens to authenticated prospect-specific
    demos (a "your data here" sandbox). Treat as a v2 question.
  - Whether Phase 2's macOS coverage uses Tart on the existing Mac
    mini fleet or moves to a managed Mac host (MacStadium / AWS bare
    metal Mac). Decide at Phase 2 start based on Tart capacity then.
  - Whether the demo aggregator is the same code path as the future
    paid Layer 3 fleet aggregator or a deliberately simpler static-
    site generator. Treat as a #157 implementation question.

## References

- `docs/v1-spec.md` — §Next step (founder-conviction launches, public
  contract-test corpus)
- `CLAUDE.md` — §Security thesis (scanners are an attack surface),
  §Decision protocol (does it fit cleanly into one layer)
- ADR-0007 — live Sigstore acceptance (workflow precedent for cost-aware
  scheduled jobs)
- ADR-0009 — Linux profiling enforcement with observational fallback
  (variant the demo fleet will exercise)
- ADR-0018 — empty discovery is valid inventory (the demo will include
  some genuinely empty endpoints to prove this still produces a clean
  inventory)
- ADR-0019 — conversation-log sensitive-data report (chat-log planting
  pattern follows the two-opt-in design)
- Repo issue #103 — track all TODOs as GitHub issues
- Repo issue #157 — static fleet aggregator (consumes the demo bundle)
- Repo issue #158 — public demo site (Phase 3 target)
- Memory: `reference_reeve_infra.md` — Reeve infra after Reeve-Security
  migration (Hetzner runner substrate, CI conventions)
