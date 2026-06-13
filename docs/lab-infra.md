# Lab infrastructure plan

Issue #29 tracks post-v0.1 lab infrastructure for two separate uses:

1. **Trusted-branch CI capacity** using ephemeral self-hosted runners.
2. **Demo fleet evidence** using many disposable endpoints that emit signed AIBOMs.

This is deliberately lab tooling, not a product surface. It must not add a hosted dashboard, runtime enforcement, new protocol adapters, or always-on scanner services to v0.1.

## Scope boundary

Allowed in this repo:

- Documentation for the target lab architecture.
- Small scripts under `tools/lab/` that operate on existing Reeve outputs.
- Reproducible image/provisioning notes that can later become Packer/virsh/Tart inputs.

Not allowed for v0.1:

- Hosted dashboard or database.
- New scanner adapters beyond MCP.
- Windows sandbox support.
- Runtime blocking or auto-remediation.
- Long-lived secrets in CI runners or demo endpoints.

## Tier 1: ephemeral self-hosted CI

Self-hosted runners are only for trusted branches or manually approved internal PRs. Fork PRs and tagged release builds stay on GitHub-hosted runners so untrusted code and release provenance do not depend on a mutable local host.

Required guardrails before any runner is registered:

| Guardrail | Requirement |
| --- | --- |
| Ephemeral job VM | Each ephemeral job VM boots from a known image and is destroyed after the run. No always-on host runner executes jobs directly. |
| Image provenance | Images are rebuilt with Packer weekly and on toolchain bumps. Image config lives in git and can be signed/reviewed. |
| Secret model | No long-lived credentials on the runner. Use GitHub OIDC and Sigstore keyless flows only. |
| Routing | Workflow gates must allow only internal trusted branches/labels. Fork PRs stay on GitHub-hosted runners. |
| Network | Runner VM egress is allowlisted to GitHub, crates.io, rust-lang endpoints, Fulcio, Rekor, and OS update mirrors needed for image rebuilds. |
| Re-image cadence | Destroy job VM after each run; rebuild base images weekly and after toolchain changes. |

Hardware target:

- Apple Silicon Mac mini for macOS runner jobs.
- Ubuntu NUC for Linux runner jobs.
- No Windows CI runner until Windows sandbox support is in scope after v1.

## Tier 2: demo fleet

Demo fleet endpoints prove Reeve can collect signed AIBOM evidence from
many employee profiles, not only developer workstations. The fleet is
for demos and validation, not continuous monitoring SaaS.

Substrate target:

- libvirt/KVM on the Ubuntu NUC for Linux and Windows guests.
- Tart on Apple Silicon for a small number of macOS guests, within Apple licensing limits.
- Packer for image baking.
- cloud-init for Linux first boot.
- unattend.xml for Windows first boot.
- virsh/Tart CLI scripts for lifecycle.

Endpoint archetypes:

The canonical archetype catalog lives in
[`docs/demo-archetypes.md`](demo-archetypes.md). It defines 12 profiles:
seven developer profiles and five non-developer profiles across macOS,
Linux, and Windows. Windows support is in scope for discovery and
observational profiling; Windows sandbox enforcement remains out of
scope until AppContainer work lands.

At least 30% of demo endpoints should use non-developer archetypes.
This keeps the demo aligned with the actual buying question: "which AI
tools are registered across employee endpoints?"

## Evidence collection contract

Each endpoint runs Reeve locally and writes artifacts to a shared directory or copies them to a collector directory:

```bash
aibom-cli scan --target "$HOME" \
  --introspect-execute --introspect-execute-yes \
  --profile --profile-yes \
  --policy-check \
  --sign-mode real \
  --output-dir /srv/reeve-lab/$HOSTNAME
```

The collector is file-based only:

- No HTTP service.
- No database.
- No agent callback channel.
- No secret ingestion.
- Only existing Reeve JSON artifacts are read.

Use `tools/lab/aggregate.sh` to summarize collected AIBOM sidecars for demos.

## Promotion checklist

Before enabling self-hosted CI or demo fleet automation:

- [ ] Runner jobs are ephemeral VM-per-job, not host-level long-lived runners.
- [ ] Fork PRs remain GitHub-hosted.
- [ ] Tagged releases remain GitHub-hosted.
- [ ] Runner network egress policy is documented and applied.
- [ ] No long-lived secrets exist in images, runners, or shared mounts.
- [ ] Demo collection uses only files under an explicit lab output directory.
- [ ] Demo scripts live under `tools/lab/`, not `crates/`.
