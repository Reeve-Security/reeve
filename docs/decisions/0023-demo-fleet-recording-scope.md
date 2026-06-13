# ADR-0023: Demo fleet is a one-shot mixed-platform recording artifact

- **Status:** Accepted 2026-05-14
- **Decides:** Amendment to ADR-0020 demo-fleet execution scope after founder clarified that the fleet is needed for a recorded end-to-end launch demo, not a long-running live environment.
- **Related:** ADR-0020, ADR-0022, Issue #191, Issue #192, Issue #109, Issue #111, Issue #158

## Context

ADR-0020 created the demo-fleet plan: a populated, department-flavored
fleet separate from the release-validation fleet. After acceptance, two
questions needed correction:

1. The founder clarified the near-term goal: record one credible
   end-to-end demo, preserve the signed artifacts, and tear down paid
   infrastructure. The immediate need is not a continuously running
   public demo environment.
2. A Linux-only first phase is not buyer-credible. Marketing, HR,
   finance, sales, and executive personas usually live on Windows or
   macOS. A serious fleet demo needs mixed-platform evidence.

This ADR amends ADR-0020's execution plan without changing Reeve's
product architecture. Reeve remains inventory and signed evidence, not a
proxy, governance workflow, or runtime enforcement layer. See ADR-0022.

## Options considered

### A. Keep ADR-0020 unchanged

Run the original phased plan: 20 Linux endpoints first, then expand to 50
with macOS, then wire to a public demo site.

Pros: cheapest first apply and simplest Terraform surface.

Cons: optimizes for infrastructure comfort instead of buyer credibility.
It delays Windows/macOS evidence even though those platforms carry the
non-developer personas the launch story needs.

### B. Shrink to 3-5 endpoints and record once

Build a small recordable dataset, capture the video, and avoid a full
fleet.

Pros: fastest and cheapest.

Cons: weakens the fleet claim. It shows a working scanner, not a
cross-organization inventory story. It also fails the founder's goal of
showing Reeve across realistic endpoint variety.

### C. Build a full mixed-platform fleet only for a one-shot recording *(chosen)*

Plan 50 mixed-platform endpoints, validate all Terraform and Ansible
locally or through dry-run first, then apply cloud resources for a
bounded recording window. Preserve signed artifacts and tear down paid
infrastructure after recording.

Pros: buyer-credible, preserves the 50-endpoint showpiece, includes
Windows and macOS early, avoids long-running cloud spend, and keeps
every infrastructure decision scoped to the demo.

Cons: requires more planning before the first apply. Provider surfaces
are broader: Hetzner for Linux, AWS or Azure for Windows, Tart for macOS.

## Decision

Adopt Option C. ADR-0020 remains the historical design record; this ADR
amends its near-term execution plan.

The Phase 1 demo target is now:

- 50 endpoints total for the recording dataset;
- approximately 30 Linux endpoints on Hetzner;
- approximately 15 Windows endpoints on AWS or Azure;
- approximately 5 macOS endpoints on the existing Mac mini / Tart
  substrate;
- five primary department personas: engineering, marketing, finance, HR,
  and sales, with executive and IT-admin variants allowed if the
  recording script needs them;
- infrastructure created for the recording window, then destroyed;
- signed per-endpoint artifacts plus a signed fleet manifest as the
  canonical demo evidence.

Paid cloud apply is not the next step. Planning artifacts are the next
step. The project should not spend cloud money until these artifacts
exist and pass review:

1. endpoint variant matrix;
2. Terraform modules for Linux, Windows, and macOS orchestration;
3. Ansible role catalog for personas and shared planting roles;
4. local or single-host dry run proving at least one persona can be
   planted, scanned, signed, and rendered;
5. recording script mapping scenes to exact endpoints and artifacts;
6. verified CVE/source list;
7. written safety boundary for planted vulnerabilities.

Cloudflare R2 may be used as the demo artifact bucket: per-endpoint
AIBOMs, sensitive-data reports, sigstore bundles, fleet manifest, static
HTML report, and recording-support assets. R2 is not part of Reeve's
product architecture. It is a replaceable S3-compatible object store for
the demo.

## Safety boundary

The demo may plant vulnerable versions, package signatures, typo-squatted
names, suspicious config, drift evidence, and conversation-log test
secrets. It must not execute exploit payloads.

Allowed:

- install or simulate a vulnerable version so Reeve can inventory it;
- pin package/version evidence to a verified CVE or vendor advisory;
- plant typo-squatted or over-privileged MCP server registrations;
- plant benign test secrets that match Reeve's shipped secret-pattern
  rules;
- show scan-to-scan config drift.

Forbidden:

- triggering RCE chains;
- running live exploit payloads;
- exfiltrating secrets;
- staging malware;
- compromising demo hosts for realism.

The demo proves Reeve surfaces evidence. It does not prove Reeve secures
or fixes the endpoint. Existing customer patching, MDM, SIEM, SOAR, and
GRC tools take action.

## Central corpus boundary

The central MCP corpus is not demo infrastructure. It is the long-term
data moat tracked by #109 and #111. Work on #111 should run in parallel
with demo planning because it is pure code and public-data ingestion.

The demo may reference a seed corpus only if it exists and is signed.
Until then, public copy must say only what is shipped or attribute
third-party findings to their primary sources.

## Rationale

This preserves the long-term vision. Reeve is still endpoint inventory
plus signed evidence. The mixed-platform fleet is a proof environment,
not a new hosted product. R2 and AWS/Azure are disposable substrates for
creating the proof, not architectural dependencies.

The one-shot model also controls cost. The expensive part of Windows is
keeping it on. For a bounded recording window, cloud cost is minor
compared with the engineering value of showing buyer-realistic Windows
endpoints.

The safety boundary keeps the demo from becoming an exploit show. Reeve
does not need to trigger payloads to prove value. Inventorying vulnerable
versions, suspicious registrations, granted approvals, planted test
secrets, and scan drift is the product.

## Plain-language summary

We are not building a permanent demo cloud right now. We are building a
movie set.

The movie set needs to look like a real company: Linux developer boxes,
Windows finance and sales laptops, macOS executive or creative machines,
different AI assistants, different MCP servers, different approval states,
and some intentionally risky but inert evidence.

We build the set, run Reeve, capture signed evidence, record the video,
save the artifacts, and tear the rented set down.

R2 is just the storage closet for the movie set. It holds the JSON files,
signature bundles, manifest, and static report while we record and review.
It is not Reeve's product. If we later choose S3, customer-owned buckets,
or self-hosted storage, the product story does not change.

The central MCP corpus is different. That is not a movie set. That is
the long-term data asset: a public inventory of MCP servers and their
metadata. It should start in parallel, but it is tracked separately.

## Consequences

- **This decision commits the project to:** a 50-endpoint mixed-platform
  one-shot recording dataset; no paid cloud apply before local/dry-run
  planning artifacts pass review; no exploit payload execution; signed
  per-endpoint artifacts plus a signed fleet manifest; R2 only as a
  replaceable demo artifact store.
- **This decision unblocks:** issue #191 rescoping, Terraform/Ansible
  planning, recording-script work, and parallel #111 central-corpus
  bootstrap.
- **This decision forecloses:** treating the near-term demo as a
  long-running hosted fleet, using provider choices as product
  architecture, shrinking the launch proof to a 3-5 endpoint scanner
  demo, or triggering real exploits on demo hosts.
- **This decision defers:** whether #158 becomes a public always-on demo
  site, whether demo artifacts remain hosted after launch, and whether
  future Layer 3 product storage uses R2, S3, customer-owned buckets, or
  self-hosting.

## References

- [ADR-0020: Demo fleet is a phased, department-flavored, populated dataset -- not the validation fleet](0020-demo-fleet-design.md)
- [ADR-0022: Reeve is a config reader and on-endpoint profiler, not an MCP proxy](0022-config-reader-not-proxy.md)
- Issue #191
- Issue #192
- Issue #109
- Issue #111
- Issue #158
