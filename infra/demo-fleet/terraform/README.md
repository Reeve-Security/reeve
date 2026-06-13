# Demo Fleet Terraform

No cloud resources are created by default. `recording.tfvars.example`
keeps all endpoint maps empty so `terraform plan` is safe once provider
plugins are installed.

Provider modules:

- `modules/linux-hetzner`: Linux endpoints on Hetzner Cloud.
- `modules/windows-azure`: Windows endpoint input contract for Azure.
- `modules/macos-tart`: macOS endpoint input contract for Tart on the
  existing Mac mini.

The Windows and macOS modules intentionally start as contracts plus
outputs. They prevent Terraform callers from inventing a different
endpoint schema while provider-specific resource wiring is reviewed.

Paid apply requires a real `recording.tfvars` and founder approval.

## Tooling

Use OpenTofu or Terraform. The helper scripts prefer `tofu`, fall back to
`terraform`, and honor `TERRAFORM_BIN` when set.

```bash
TERRAFORM_BIN=terraform infra/demo-fleet/scripts/teardown-dry-run.sh
```

## No-spend validation

From the repository root:

```bash
infra/demo-fleet/scripts/teardown-dry-run.sh
```

This defaults to `recording.tfvars.example`, where all endpoint maps are
empty. It validates formatting, provider/module shape, and destroy-plan
command wiring without credentials or cloud spend after providers have
been installed.

For scene-critical review-map validation:

```bash
infra/demo-fleet/scripts/teardown-dry-run.sh --review
```

This uses `recording.tfvars.review.example` and still never applies.
If provider credentials are required by the local Terraform/OpenTofu
version, pass them through normal environment variables; do not commit
secrets or `recording.tfvars`.

## Recording-window teardown

After paid apply, run the same helper with the real, local-only
`recording.tfvars` before teardown:

```bash
infra/demo-fleet/scripts/teardown-dry-run.sh \
  --tfvars infra/demo-fleet/terraform/recording.tfvars \
  --plan-out /tmp/reeve-demo-fleet-destroy.tfplan
```

Review the plan. Actual destroy remains manual and requires founder
approval for the recording window.
