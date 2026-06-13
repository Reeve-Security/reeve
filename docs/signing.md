# How Reeve signs things — a grounding document

This is a plain-language walkthrough of how Reeve signs its outputs, what
"signing" actually means here, what we commit to, and where the sharp
edges are. It exists so the founder (and anyone else reading cold) can
hold an end-to-end mental model without piecing it together from ADRs.

The last section is explicit hole-poking prompts. Read those first if
you're short on time.

---

## 1. The 30-second version

Reeve produces two files per scan: a CycloneDX document and an AIBOM
sidecar. Those two files need a cryptographic signature so that when
they land on an auditor's desk, or get ingested into Dependency-Track,
or get shown to a customer's security team, **nobody in the middle
could have altered them.** A tampered document would show a broken
signature, and verification fails. That's the whole job of signing.

The signing system we use is called **Sigstore**. It's the emerging
industry standard for software supply-chain signing, run as free
public-good infrastructure by the Linux Foundation's OpenSSF.
Kubernetes, GitHub, npm, Python (PyPI), and a growing list of major
projects already sign with it. Picking Sigstore means Reeve slots
into an ecosystem that already exists rather than inventing our own
format.

---

## 2. What "signing" means, concretely

Imagine a notarized letter. A notary public watches you sign the
letter, stamps it, and keeps a log entry saying "this letter was
signed by this person on this date." Later, anyone presented with the
letter can:

1. Check the notary stamp is real (not a forgery).
2. Look up the log entry for corroboration.
3. Verify the signature matches the contents of the letter — any
   tampering would break the match.

Digital signing works the same way, except:

- The "notary" is a certificate authority (in our case, **Fulcio**).
- The "log" is a public append-only database (in our case, **Rekor**).
- The "signature" is a mathematical function of the document's bytes
  plus the signer's cryptographic key.

**The key twist** (and this is what confuses most people at first):
traditional signing means you keep a secret private key on your
laptop forever. If that key leaks, attackers can sign as you until
you notice and rotate. Sigstore avoids this with **keyless signing**:

- The signer proves their identity via an **OIDC identity** (OIDC is
  the industry-standard "log in with X" protocol). An OIDC identity
  can be a human (GitHub / Google / Microsoft account), a CI
  workflow (e.g., GitHub Actions workflow running in your repo), or
  a machine workload (SPIFFE, AWS IAM Roles Anywhere, Azure Managed
  Identity, etc.).
- Fulcio verifies the OIDC identity and issues a certificate that's
  only valid for ~10 minutes, stamped with that identity.
- The signer signs with that cert inside the 10-minute window.
- The cert expires and can never be used again.

So there's no long-lived secret to lose. An attacker who steals a
signing environment ten minutes after it signed cannot impersonate
that identity.

**Important**: "OIDC identity" does **not** mean "a human with a
browser." In the majority of production deployments, the OIDC
identity is a CI workflow or a workload identity — no human logs in,
no browser appears, no laptop is involved. §4 walks through who
actually holds the OIDC identity in each deployment pattern, and §5
shows what that looks like day-to-day.

---

## 3. The five components of a Sigstore-signed thing

When Reeve produces a scan, the output is a bundle with five pieces.
This is what matters mechanically:

| Piece | What it is | Purpose |
|---|---|---|
| The signed **envelope** (DSSE) | Standardized container format | Holds the next three pieces in a tamper-evident way |
| The **in-toto Statement** | A small JSON document listing what's being vouched for (the CycloneDX digest + the AIBOM sidecar digest) | Identifies which specific files this signature covers |
| The **Fulcio certificate** | Short-lived, issued by Sigstore, contains the signer's OIDC identity | Proves who signed |
| The **Rekor inclusion proof** | Public log entry with timestamp | Proves when signed, and that the signature was recorded before the cert expired |
| The **signature bytes** | The actual cryptographic signature | What makes all of this tamper-evident |

All five pieces get packaged into one file: `<scan-id>.sigstore.json`.
That file is what Reeve emits alongside the CycloneDX + AIBOM sidecar
triplet.

### Surface-config bundles

System-wide custom-surface configuration uses the same signing idea for
a different artifact. The deployer-owned file is usually named
`surfaces.yaml`. If it is signed, the adjacent bundle is named
`surfaces.yaml.sigstore.json`, and generation metadata is named
`surfaces.provenance.json`.

The signed statement covers exactly the `surfaces.yaml` bytes. If an
attacker edits the config after signing, Reeve detects the hash mismatch
and refuses the file. If the signer identity does not match
`--signer-identity-regexp` or the build-time
`REEVE_SURFACE_CONFIG_SIGNER_IDENTITY_REGEXP`, Reeve refuses the file.

Unsigned configs remain allowed by default for migration and pilots, but
Reeve prints a warning. Production deployments should pass
`--require-signed-config`; then missing signatures fail closed.

Offline tests can use `scripts/build-surface-config-bundle-fixture.py`
to create deterministic fixture bundles. Fixture bundles are accepted
only when `REEVE_ACCEPT_FIXTURE_SURFACE_CONFIG_SIGNATURE=1` is set.
Production bundles should be created with `cosign sign-blob` and
verified by Reeve with `cosign verify-blob`.

---

## 4. Who signs, and when — the four deployment patterns

**The single most important operational distinction**: signing
authority sits at the **organization** level, not the endpoint level.
A fleet of 500 laptops does not produce 500 signing identities. One
organizational identity signs on the fleet's behalf, or a small
number of them (production CI, staging CI, audit team, etc.). This
section maps the four real-world patterns.

| Pattern | Where the scan runs | Where signing happens | OIDC identity | When to use |
|---|---|---|---|---|
| **A** *(enterprise default)* | On each endpoint, unsigned | Central service, batch-signs | CI workflow or workload identity (one per organization) | Fleet of >10 endpoints; most production deployments |
| **B** | Central CI, against a snapshot of the fleet | Same central CI | CI workflow identity | Pilot deployments; small or highly centralized fleets |
| **C** *(v1.x roadmap)* | On each endpoint | On each endpoint, locally | Enterprise-issued workload identity (SPIFFE, IAM Roles Anywhere, etc.) | Zero-trust deployments with mature machine-identity infra |
| **D** *(rare; individual use)* | On a developer laptop | On that laptop, interactively | Individual human OIDC (GitHub / Google / Microsoft via browser) | One-off attestations: contractors, researchers, auditors publishing a single signed report |

Patterns **A and B are the common enterprise shapes**. Pattern C is on
the roadmap (ADR-0004 explicitly defers SPIFFE + private OIDC issuers
to v1.x). **Pattern D is the edge case** — it's the only pattern that
involves a browser prompt, and most organizations will never use it
in production.

Reeve's own releases use Pattern B internally: a GitHub Actions
workflow signs each release with the workflow's own OIDC identity
(`repo:Reeve-Security/reeve:ref:refs/tags/v0.1.0` or similar). No
human logs in anywhere in the release pipeline.

§5 walks through each pattern's operational shape.

---

## 5. Day-to-day operations — what using Reeve actually feels like

Signing is a background concern in most daily flows. This section
says what you actually do, what you see, and what changes compared
to not having Reeve at all.

### 5.1 Pattern A — Fleet endpoints → central signer (the enterprise default)

500 laptops. One signer identity for the whole organization. No
laptop ever talks to OIDC or Sigstore.

**On each endpoint** (scheduled by MDM, cron, or endpoint agent):

```
$ aibom-cli scan --target ~ --output-dir /var/cache/reeve-scans
Scan complete: 9 components found
  cursor: 4
  claude-code: 5
Output: /var/cache/reeve-scans/scan-<id>.cdx.json
        /var/cache/reeve-scans/scan-<id>.aibom.json
```

2-5 seconds. No browser prompt. No network access beyond whatever
your endpoint-management tool already does for uploads. No OIDC. No
signing. The laptop just produces two JSON files.

**A follow-up step** (part of your existing MDM workflow) ships those
JSON files to a central collection point — an S3 bucket, an internal
ingestion API, a SIEM, whatever your security team already uses to
collect endpoint evidence.

**A central signing service** (a scheduled GitHub Actions workflow,
GitLab CI pipeline, or internal daemon — whatever your organization
already uses for CI) picks up the batch on a schedule:

```yaml
# Runs in CI — not on any laptop
name: Nightly Reeve signing pass
on:
  schedule: [{ cron: "0 2 * * *" }]
permissions:
  id-token: write        # CI identity → OIDC keyless
  contents: read
jobs:
  sign-batch:
    runs-on: ubuntu-latest
    steps:
      - run: aws s3 sync s3://reeve-unsigned/ ./in/
      - run: |
          for scan in ./in/*.aibom.json; do
            aibom-cli sign --input-dir ./in --scan-id $(basename $scan) --output-dir ./out
          done
      - run: aws s3 sync ./out/ s3://reeve-signed/
```

The CI workflow's OIDC identity — something like
`repo:mycorp/reeve-signer:ref:refs/heads/main` — signs each scan.
Every signed scan in your fleet carries that one identity, not 500
individual identities. Signatures accumulate in your SBOM platform
(Dependency-Track, Snyk, Wiz, Orca, etc.).

**What changes in your day**: endpoint owners see nothing. Security
team owns the central signer workflow (one YAML file, committed
once). SBOM platform has one allowlist entry
(`repo:mycorp/reeve-signer:*`). Post-setup operational effort: zero.

### 5.2 Pattern B — Central CI scans a snapshot

Architecturally simpler, at the cost of reduced fidelity. Your
endpoint-management tooling (Jamf, Intune, Workspace ONE, or an
Ansible/Salt-style config agent) pulls snapshots of employees' MCP
config directories into a central location nightly. A single CI job
scans that snapshot and signs the output.

```yaml
name: Nightly central MCP inventory
on:
  schedule: [{ cron: "0 3 * * *" }]
permissions:
  id-token: write
  contents: read
jobs:
  inventory:
    runs-on: ubuntu-latest
    steps:
      - run: mdm-snapshot-pull /opt/mcp-configs
      - run: |
          aibom-cli scan \
            --target /opt/mcp-configs \
            --output-dir ./out \
            --sign
      - uses: actions/upload-artifact@v4
        with: { path: ./out/ }
```

One scan, one signature, one OIDC identity (CI's). Endpoints
themselves never run Reeve.

**Tradeoff**: simpler ops, lower fidelity. Depends entirely on what
the snapshotting process captures. If MDM misses workspace-local
`.mcp.json` files scattered under user home directories, Reeve
misses them too.

**Use this if**: running a pilot, fleet is small (<50 endpoints), or
your MDM already snapshots home directories comprehensively enough
for your use case.

### 5.3 Pattern C — Workload identity on endpoints (v1.x roadmap)

Endpoints sign directly, using enterprise-issued machine identity
(SPIFFE, AWS IAM Roles Anywhere, Azure Managed Identity, GCP
Workload Identity, or your identity provider's agent equivalent). A
private Sigstore deployment inside the enterprise accepts those
workload identities.

```
$ aibom-cli scan --target ~ --sign --sigstore-instance=private
# uses the laptop's SPIFFE identity — no browser, no human
```

**Requires**:
- Private Fulcio + Rekor deployment (Chainguard sells this hosted;
  enterprises also self-host).
- Machine-identity infrastructure already deployed to endpoints.
- Reeve configured to point at the private Sigstore instance.

**Deferred to Reeve v1.x.** ADR-0004 explicitly lists this under
"Self-hosted OIDC issuers (SPIFFE, private Dex) deferred to v1.x."
Zero enterprises are blocked on it today; it's the natural upgrade
path for mature zero-trust deployments.

### 5.4 Pattern D — Interactive human signing (rare; individual use)

One developer, one laptop, one browser prompt, one signature. Used
when an individual is publishing a specific attestation — a security
researcher publishing findings, a contractor producing a signed
report for a client, an auditor preparing an evidence file for a
specific engagement.

```
$ aibom-cli scan --target ~ --sign
[cosign] opening browser → oauth2.sigstore.dev → code CGJF-LZLF
[cosign] Fulcio cert issued for user@github.com
[cosign] Rekor entry #18234921
Signed. Output: out/scan-<id>.sigstore.json
```

The individual's personal GitHub / Google / Microsoft identity gets
stamped into the Fulcio cert and permanently logged in Rekor.

**This is not the enterprise default.** Nobody should be running
this across a fleet. If your security team is telling 500 employees
to "log into Sigstore in their browser every Monday," the
deployment architecture is wrong — redesign to Pattern A.

### 5.5 Consuming Reeve output in your SBOM pipeline

Your existing SBOM platform (Dependency-Track, Snyk, Wiz, Orca,
JFrog Xray, etc.) ingests Reeve's CycloneDX document. Sigstore
verification happens on ingest:

1. Platform fetches `scan-<id>.sigstore.json` + the CDX + AIBOM pair.
2. Platform calls `cosign verify-blob` (or an embedded Sigstore
   library) against the bundle.
3. If verification passes, the platform consumes the CycloneDX as
   normal SBOM data. If it fails, the platform rejects the ingest
   and logs the failure.

Verification takes ~500ms per bundle. The first time a platform
sees a Reeve-signed bundle, it needs to fetch Sigstore's trust roots
via TUF (a few KB, cached after that).

**What changes in your day**: you add one allowlist entry to your
SBOM platform telling it "accept signatures from
`repo:mycorp/reeve-signer:*`." After that, ingestion is automatic.
Any scan that wasn't signed by your allowed identity gets rejected —
which is exactly what you want: that's the tamper-detection working.

### 5.6 When something goes wrong

Failure modes you'll actually see, in order of likelihood:

**(a) cosign not installed on the machine running the signing step.**
`aibom-cli scan --sign-mode real` (and `REEVE_SIGN_MODE=real`) exits
non-zero before writing any artifact with a message that names the
binary path that was tried, points at install instructions, mentions
the `REEVE_COSIGN_BIN` override, and tells the operator to pass
`--sign-mode fixture` / `--skip-sign` if they wanted the deterministic
fixture path. Explicit real-signing never silently downgrades to a
fixture bundle (ADR-0006). In Pattern A this shows up in the
central-signer CI, not on endpoints. `--sign-mode auto` (the legacy
default) keeps the warn-and-fixture behavior so demos and
ad-hoc runs stay convenient; release pipelines must pin
`--sign-mode real`. Until issue #11's native sigstore-rs maturity gate
passes, cosign is a prerequisite for the real-signing environment.

**(b) OIDC provider unreachable.**
GitHub / Google / Microsoft auth is down, or a corporate egress
filter blocks `token.actions.githubusercontent.com`. Signing fails
with `OIDC authentication timed out after 60s`. Recovery: retry, or
fall back to unsigned output (`--skip-sign`) and re-sign the batch
later when OIDC is back.

**(c) Sigstore public infrastructure unreachable.**
Fulcio or Rekor outage, or air-gapped network with no private
Sigstore. Same symptom as (b), different error message: `Sigstore
endpoint unreachable`. Same recovery. Sigstore public-good has
~99.9% uptime historically; this is rare but real. Plan accordingly
in production CI (retry logic, dead-letter queue for unsigned
scans).

**(d) Verification fails because the signer's OIDC identity isn't in
your allowlist.**
Your SBOM platform receives a bundle signed by an identity you
haven't approved. Platform rejects ingest with
`crypto.oidc_subject_not_allowed`. **This is a feature, not a bug**
— it's the system catching an unauthorized source. Recovery: add
the identity to your allowlist if legitimate, or investigate if not.

**(e) Verification fails because the artifact hash doesn't match.**
Someone modified the AIBOM file between signing and verification.
Platform rejects with `cdx.externalReferences.hash_mismatch` or
`attestation.subject_role_mismatch`. This is the system doing
exactly what signing exists to do — catching tampering.
Investigate the storage / upload chain.

### 5.7 Performance numbers (on typical hardware in 2026)

| Operation | Time |
|---|---|
| Endpoint scan, no signing (Pattern A default) | 2-5 seconds |
| Central CI signing step, per bundle | 1-2 seconds |
| Central CI signing, 500-bundle batch | 10-20 minutes |
| Verify schema/semantic stages only | ~200ms per bundle |
| Verify with `--verify-crypto` (structural bundle checks + allowlist facts) | ~200-500ms per bundle |
| Independent `cosign verify-blob` Fulcio/Rekor proof | ~500-800ms per bundle after trust-root cache warm-up |
| Bundle file size on disk | 5-15 KB |
| CycloneDX document size | 1-5 KB per component |
| AIBOM sidecar size | 2-10 KB per component |
| Interactive Pattern D signing (first OIDC flow) | +10-30 seconds for browser auth |

**Cost for a 500-endpoint enterprise**: nightly scan + central sign
takes ~20 CI minutes. At typical CI pricing (~$0.008/minute on
GitHub-hosted runners), that's ~$5/month for the signing step
itself. Signing cost is not an economic concern.

### 5.8 What you configure once, then forget

After initial setup, the only Reeve configuration that typically
needs touching is the **identity allowlist** — the list of OIDC
issuers + subjects you trust.

Lives in `~/.config/reeve/allowlist.yaml` (or passed via
`--allowlist path`):

```yaml
# Trusted OIDC identity providers
oidc_issuers:
  - https://token.actions.githubusercontent.com
  - https://accounts.google.com

# Who is allowed to sign AIBOM bundles we accept
trusted_signers:
  - issuer: https://token.actions.githubusercontent.com
    subject_pattern: "repo:mycorp/reeve-signer:.*"
  - issuer: https://accounts.google.com
    subject_pattern: "security-team@mycorp.com"
```

Update when CI pipelines change or a new trusted team is onboarded.
Otherwise untouched.

**Other knobs** (rarely touched):

- `--strict` profile — rejects any scan whose observed capability
  exceeds declared (stricter than default warn-mode).
- `--sign-mode real|fixture|auto` — selects signing backend. `real`
  requires cosign and fails loudly if missing (use in release
  pipelines). `fixture` always emits the deterministic placeholder
  bundle (tests, demos, offline). `auto` (default) keeps legacy
  behavior: real if cosign is available, else warn and emit fixture.
  Also settable via the `REEVE_SIGN_MODE` environment variable.
- `--skip-sign` — shortcut for `--sign-mode fixture`. Emits the
  fixture bundle for local inspection or endpoint-side (Pattern A).
- `REEVE_COSIGN_BIN` — override the cosign binary path (defaults to
  `cosign` on `PATH`). Useful in locked-down environments and in
  tests that need to simulate cosign being absent.
- `--allowlist` — override the default config path.
- `--sigstore-instance` — point at a private Sigstore deployment
  (v1.x).

### 5.9 Offline and air-gapped environments

| What you're doing | Works offline? |
|---|---|
| Scanning for MCP configs | ✅ Yes |
| Running validator structural stages | ✅ Yes |
| Verifying fixture bundles | ✅ Yes |
| Verifying real signed bundles (after first trust-root fetch) | ✅ Yes with cached TUF metadata |
| Producing a real signed bundle | ❌ Requires OIDC + Fulcio + Rekor |
| Full air-gap end-to-end | ❌ Needs private Sigstore deployment (v1.x roadmap) |

Pattern A partially addresses air-gap: endpoints produce unsigned
output fully offline; only the central signing step needs network
(for OIDC + Fulcio + Rekor). Enterprises with strict air-gap
requirements (defense, financial institutions with segmented
networks) can push signing to a network-connected bastion. Full
air-gapped operation — signing without any Sigstore connectivity —
requires Pattern C's private Sigstore deployment, v1.x roadmap.

### 5.10 How to debug a verification failure

Two commands you'll actually run:

**Reeve's own verifier with verbose output:**
```
$ aibom-cli verify ./out/ --verify-crypto --verbose
Stage schema-validation ... PASS
Stage semantic-validation ... PASS
Stage canonicalization ... PASS
Stage hash-match ... PASS
Stage attestation-shape ... PASS
Stage crypto-verification ... FAIL: crypto.oidc_subject_not_allowed
  expected subject pattern: repo:mycorp/reeve-signer:.*
  actual subject: repo:otheruser/fork
  source: ./out/scan-XXX.sigstore.json
```

`--verify-crypto` is Reeve's structural bundle gate. It checks the
bundle shape, signed subject hashes, allowlist facts, and fixture-bundle
markers. It does not replace public Sigstore verification.

**Prove the public Sigstore chain with cosign**:
```
$ cosign verify-blob --bundle ./out/scan-XXX.sigstore.json ./out/scan-XXX.aibom.json
Verification for scan-XXX.aibom.json -- [cosign output]
```

**Look up the Rekor entry directly** (public URL, anyone can check):
```
$ curl https://search.sigstore.dev/?hash=<sha256-of-artifact>
```

Returns every Rekor entry referencing that artifact hash. Gives you
the signer identity, timestamp, and cert details independently of
Reeve and cosign — third-source verification.

---

## 6. Who uses Sigstore today (the trust argument)

This is the most-asked question in enterprise reviews. The short
answer: **Sigstore is the industry convergence point for software
supply-chain signing as of 2024-2026.** It is backed by large,
credible organizations and used in production at significant scale.
Names that matter:

- **The Linux Foundation** runs the OpenSSF, which runs Sigstore as a
  graduated project. Same foundation home that owns Kubernetes.
- **Google** is a top contributor; Google's Distroless container
  images are all signed with Sigstore.
- **GitHub** has first-class Sigstore integration; GitHub Actions
  provenance attestations use Sigstore under the hood. The green
  "verified" badges on GitHub release pages come from this.
- **Kubernetes** signs every release binary with Sigstore. Has since
  ~2022.
- **npm** added Sigstore-based provenance to the registry in 2023
  (`npm publish --provenance` produces a signed attestation).
- **Python (PyPI)** integrated Sigstore for PEP 740 attestations in
  2024.
- **Chainguard** is a commercial company built on top of Sigstore;
  valued at ~$700M last raise (Series C, 2024).
- **SLSA** (the software supply-chain level standard from Google +
  Linux Foundation) recommends Sigstore as its reference
  implementation.
- **NIST guidance** and **US federal supply-chain security
  executive orders** both name transparent signing infrastructure
  — Sigstore is the practical answer.

A project choosing Sigstore in 2026 is choosing the same tool that
Kubernetes, npm, PyPI, and federal-contract-compliant software
vendors chose. It is not a novel or risky technology choice. The
opposite choice — rolling our own signing scheme — would be the
risky one and would be the thing enterprise buyers would ask about.

---

## 7. The tradeoffs (where we take on real cost)

Signing is not free. Three real tradeoffs worth knowing:

### 7.1 Rekor is public

Every signed artifact is logged in Rekor, a public append-only
transparency log. Anyone with an internet connection can read every
entry. This is a **security feature** — transparency is what makes
tampering detectable — but it means:

- Signer identity (GitHub username, CI workflow identity, etc.) is
  publicly visible.
- The hash of the signed artifact is publicly visible. An attacker
  who can guess what artifact a given hash represents gets some
  information.
- Timing is publicly visible. Rekor shows exactly when each signature
  happened.

For most Reeve use cases this is fine. For defense contractors or
financial-compliance scenarios where even signing *timing* is
sensitive, the answer is to run a **private Fulcio + private Rekor**
inside the enterprise. Sigstore fully supports this. Chainguard and a
few others sell hosted private-Sigstore. Reeve's v1.x roadmap
(ADR-0004's deferred list) adds configuration for pointing at a
private deployment.

### 7.2 Dependency on cosign binary (v0.1 only)

Reeve v0.1 performs the actual signing by shelling out to the
`cosign` command-line tool (the official Sigstore CLI, the same one
every other Sigstore integration uses). This means whichever
environment runs the signing step (central signer in Pattern A, CI
in Pattern B) needs `cosign` installed (available via Homebrew, apt,
or the official install script). Endpoints in Pattern A do not need
cosign — they produce unsigned output.

This is a real friction point for the signing environment. Issue #11's
native sigstore-rs migration gate tracks when Reeve can replace the
cosign shell-out with native Rust calls. Once a released crate satisfies
that gate and parity tests pass, no external binary is needed. Until
then, README documents the prerequisite clearly and `--sign-mode auto`
fails soft for non-release runs.
**Enforcement (v0.1, per ADR-0006).** The v0.1 decision is recorded
in ADR-0006:

- Cosign is **only** a prerequisite in the environment that actually
  performs real signing. Endpoints that emit unsigned/fixture output
  (Pattern A, local dev, CI that runs fixture-based tests) never
  need cosign.
- An **explicit real-signing request** — `--sign-mode real` or
  `REEVE_SIGN_MODE=real` — fails closed with a clear error when
  cosign is missing. It never silently downgrades to a fixture
  bundle. The error names the binary path that was tried, points at
  cosign install instructions, mentions the `REEVE_COSIGN_BIN`
  override, and tells the operator how to opt into the fixture path
  instead.
- The **deterministic fixture path** (`--sign-mode fixture`,
  `--skip-sign`) stays available for tests, demos, and offline
  workflows. It does not depend on cosign at all.
- **Auto mode** (`--sign-mode auto`, also the default when no flag
  is passed) keeps the legacy warn-and-fallback behavior so local
  runs stay ergonomic. Release pipelines must not use it; they pin
  `--sign-mode real`.
- **Release acceptance.** A Reeve v0.1 release build is accepted
  only when the release job installs cosign (the workflow already
  does this via `sigstore/cosign-installer`) and runs signing with
  `--sign-mode real` (or `REEVE_SIGN_MODE=real`) so a missing-cosign
  regression fails the build instead of quietly producing a
  fixture-bundled release artifact.

### 7.3 OIDC identity provider outage

Sigstore's keyless flow requires an OIDC identity provider (GitHub,
Google, Microsoft, or your private identity provider) to be
available at the moment of signing. If GitHub's auth servers are
down, you can't sign. This is rare — major identity providers have
~99.99% uptime — but it's a real dependency. Sigstore has a
**Timestamp Authority** in development that partially mitigates this
by decoupling signing-time from identity-verification-time, but it's
not standard yet. Reeve inherits this limitation.

For production pipelines this means signing failure modes need to be
handled (retry logic, fallback behavior, dead-letter queue for
unsigned scans). For v0.1 this is noted; for v1.x it should be
solved properly.

---

## 8. How to verify a Reeve-signed thing yourself

The cleanest thing about using an industry-standard signing system is
that you don't have to trust Reeve's own verifier. You can verify any
Reeve output with **any Sigstore-compatible tool** — our
implementation and their implementation should agree. Try this with
any Sigstore-signed project:

```bash
# Install cosign
brew install cosign  # or scoop / apt / official installer

# Given a Reeve scan output:
cosign verify-blob \
  --bundle scan-XXX.sigstore.json \
  --certificate-identity-regexp 'https://github.com/Reeve-Security/reeve/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  scan-XXX.aibom.json

# Output: "Verified OK"
```

That command reads the Sigstore bundle, checks the Fulcio certificate
chains to the public-good Sigstore root, verifies the Rekor inclusion
proof, checks that the signer identity matches the expected pattern
(Reeve's GitHub Actions), and verifies the cryptographic signature
over the file content. All of that happens without Reeve's code in
the loop. **If we screw up our implementation, cosign will tell
you.** That's the entire point of using an open standard.

---

## 9. What we commit to (and what we don't)

We commit to:

- Every official Reeve release binary is signed by Reeve's GitHub
  Actions CI via Sigstore keyless. Anyone can verify with cosign.
- Every AIBOM sidecar + CycloneDX document Reeve produces (in any
  context where signing is enabled) is wrapped in a Sigstore bundle
  v0.3 conforming to ADR-0004 (DSSE-wrapped in-toto Statement, two
  subjects, sha256 digests, etc.).
- Reeve's verifier (`aibom-cli verify`) is interoperable: it will
  accept bundles produced by cosign, by sigstore-python, by
  sigstore-go, by any other Sigstore-ecosystem tool. And bundles
  Reeve produces will verify in any of those tools.

We do NOT commit to:

- Guaranteeing Sigstore's public infrastructure will be available at
  every signing moment. If OIDC providers or Fulcio are down, signing
  fails.
- Protecting the privacy of signing identities in the public Rekor
  log. If you need private logging, use a private Sigstore deployment
  (v1.x).
- Protecting against compromise of the Sigstore infrastructure itself.
  If Fulcio's private keys leak, everyone using public Sigstore has a
  problem, and we inherit it. (This is why Sigstore has transparency
  logs, public monitoring, and regular key rotations — the system is
  designed to detect + recover from compromise.)
- The cosign binary being installed on end-user signing environments.
  That's a prerequisite they manage, until v0.1.x ships native Rust.

---

## 10. How this fits Reeve's business story

Reeve's core claim (`docs/positioning.md`): "we produce evidence, not
safety claims." Signing is what makes evidence **portable and
auditable** without requiring the consumer to trust us specifically.
A customer running Reeve on their fleet + feeding outputs into
Dependency-Track gets:

- **Tamper-evidence**: Dependency-Track can verify the signatures
  haven't been altered.
- **Signer identity**: policy engines can enforce "only accept
  AIBOMs signed by our CI, not ad-hoc laptop signings."
- **Audit trail**: if a CVE drops and we need to prove which scans
  saw the vulnerable package when, Rekor timestamps give us legally
  defensible proof-of-time.

None of this is marketing. Each point has a concrete Sigstore
feature backing it. Without signing, the AIBOM is a file someone
claims came from Reeve. With signing, it's cryptographically
verifiable evidence that nothing between the scan and the auditor's
desk altered it. **That's the difference between "here's a report"
and "here's evidence for your compliance file."**

---

## 11. Questions to poke holes with

Use these as starting points when stress-testing the plan:

1. **"Does every laptop in my fleet need to log in to Sigstore?"**
   No. Pattern A (§5.1) is the enterprise default and endpoints never
   touch OIDC. One organization-level identity (typically a CI
   workflow) signs batches of scans on the fleet's behalf. §4
   walks through the four patterns.

2. **"What happens if Sigstore's public infrastructure is
   compromised?"** Reeve inherits the ecosystem's failure mode;
   mitigation is transparency logs, public monitoring, and key
   rotation. We don't solve this alone — we rely on the fact that
   Sigstore compromise is detectable in the public Rekor log.

3. **"What if my customer is a defense contractor and can't have
   public Rekor entries?"** v1.x private Sigstore deployment.
   Chainguard sells this. Until we support it, we don't sell into
   those customers.

4. **"Why not just use PGP / traditional signing?"** Key management.
   PGP puts a long-lived private key on every signer's machine;
   rotation is brutal; key discovery (who signed what, with which
   key) is a separate problem. The industry moved away from PGP for
   supply-chain signing specifically because of these issues.

5. **"What if cosign is compromised?"** Real concern. Mitigated by
   cosign being signed by Sigstore itself (dogfooding), widely
   reviewed, and Reeve's path to native sigstore-rs after the
   maturity gate passes.

   **Native sigstore-rs migration gate:** Reeve will not replace
   `cosign` until a released `sigstore-rs` crate satisfies the full
   ADR-0004 contract: DSSE, in-toto Statement with two subjects,
   bundle v0.3, Rekor v2 `dsse`, GitHub Actions OIDC, and fail-closed
   production signing. The live checklist is
   `docs/research/sigstore-rs-maturity.md`.

6. **"What's the cost model — are we locked into paying Sigstore?"**
   No. Sigstore public-good infrastructure is free; OpenSSF pays
   for hosting. Our only cost is the CI minutes for signing (cents
   per day at typical fleet scale). Private deployments (if a
   customer needs one) are an enterprise-vendor cost borne by the
   enterprise, not us.

7. **"If I disable signing, does Reeve still work?"** Yes.
   `--skip-sign` produces unsigned output. Every downstream
   validation stage except crypto-verification still runs. Customers
   opting out of signing get a strictly weaker guarantee, but the
   tool still functions. Pattern A's endpoint-side step is
   effectively this — unsigned output that gets signed later.

8. **"How is this different from SLSA?"** SLSA is a standard that
   defines *levels* of supply-chain integrity. Sigstore is the
   *tool* you use to achieve SLSA Levels 3 and 4. Reeve's signed
   output could be claimed as meeting specific SLSA levels; we
   haven't claimed anything explicitly yet. A v1.x positioning
   question.

9. **"What happens if my CI workflow identity gets rotated or the
   repo gets renamed?"** Historical signatures are already logged in
   Rekor and remain verifiable as long as Sigstore trust roots are
   maintained. New signatures under the new identity will appear as
   a separate entry in your allowlist. Not destructive; just an
   allowlist update.

10. **"Can an attacker who steals a 10-minute Fulcio cert abuse
    it?"** Yes, but only within those 10 minutes. Every use is
    logged in Rekor publicly, so the abuse is detectable in real
    time by monitoring Rekor for unexpected entries under your
    identity. The threat window is very small versus traditional
    key-theft scenarios.

11. **"Is Sigstore mandatory for Reeve, or could we swap it
    later?"** Not mandatory in principle. The ADR-0004 decision is
    specific to v0.1. If a strictly better supply-chain signing
    standard emerged (it hasn't and isn't on the horizon as of
    April 2026), we could migrate. We chose Sigstore because the
    ecosystem won't converge on anything else anytime soon. Being
    early on Sigstore is being aligned with where everything is
    going.

---

## Further reading (all optional)

- Sigstore's own landing page: `https://www.sigstore.dev`
- "What is Sigstore and why does it matter?" — Dan Lorenc's talks on
  YouTube. Dan co-founded Sigstore at Google; 30-minute intro talks
  exist at several conferences.
- Kubernetes using Sigstore: `https://kubernetes.io/blog/2022/10/03/kubernetes-has-officially-joined-the-sigstore-ecosystem/`
- SLSA standard: `https://slsa.dev`
- Chainguard (the Sigstore-based company): `https://chainguard.dev`

None of these are required reading. This document is standalone. Ask
questions directly instead of reading further — faster feedback loop.
