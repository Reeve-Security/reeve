# Demo Fleet Scaffold

This directory owns issue #191: the one-shot mixed-platform recording
dataset from ADR-0023. It is demo infrastructure, not Reeve product
architecture.

## Current Scope

This scaffold is intentionally no-spend:

- Terraform modules exist, but default endpoint maps are empty.
- Ansible roles create local fixtures and scan commands, but do not install
  real third-party AI apps by default.
- `scripts/local-dry-run.sh` proves scene-critical planted endpoints can
  produce fixture-signed AIBOMs and fixture-signed sensitive-data reports on
  the local machine.
- Paid cloud apply remains blocked until founder approves a bounded
  recording window.

## Layout

| Path | Purpose |
|---|---|
| `variant-matrix.md` | Stable 50-endpoint recording matrix |
| `terraform/` | Dry-run-friendly root and provider module stubs |
| `ansible/` | Persona roles plus shared planting/scanning roles |
| `scripts/local-dry-run.sh` | Local no-cloud proof of planted scan output |
| `scripts/teardown-dry-run.sh` | No-spend destroy-plan rehearsal |
| `scripts/upload-artifacts.sh` | Validate and optionally upload signed recording artifacts |

## Safety Boundary

Allowed:

- vulnerable-version metadata or simulated advisory slots;
- typo-squatted names;
- over-privileged MCP registrations;
- scan-to-scan config drift;
- benign planted test secrets that match shipped Reeve rules.

Forbidden:

- exploit payload execution;
- RCE triggering;
- secret exfiltration;
- malware staging;
- live compromise of demo hosts.

Narration must say: Reeve surfaced evidence. It must not say: Reeve
secured or fixed the endpoint.

## Local Dry Run

Run from the repository root:

```bash
infra/demo-fleet/scripts/local-dry-run.sh
```

The script creates temporary home directories for three scene-critical
endpoints from the matrix:

| Endpoint | Purpose |
|---|---|
| `eng-linux-02` | consent ladder shape (`MR`, `TL`, `PO`, `SG`) |
| `eng-linux-06` | sensitive-data report shape (`MR`, `SR`, `SG`) |
| `fin-win-03` | vulnerable-version placeholder shape (`MR`, `VV-01`, `SG`) |

Each endpoint gets local fixture configs under its temporary target root.
No platform-specific cloud resources are created.

Then it runs:

```bash
cargo run -p aibom-cli -- scan \
  --no-system-config \
  --target "$TARGET" \
  --output-dir "$OUT" \
  --sign-mode fixture \
  --include-conversation-metadata \
  --scan-conversation-secrets
```

Expected result:

- one `*.aibom.json` / `*.cdx.json` / `*.sigstore.fixture.json` triplet per
  endpoint;
- one `*.sensitive-data.json` /
  `*.sensitive-data.sigstore.fixture.json` pair per endpoint because the dry
  run enables secret scanning;
- one positive secret-pattern finding on the `SR` endpoint;
- one `fleet/fleet-manifest.json` containing endpoint artifact paths,
  roles, sizes, and SHA-256 digests;
- one `fleet/fleet-manifest.sigstore.fixture.json` signed fixture bundle
  for local dry-run;
- one `fleet/report.html` generated from the same evidence directory.

Fixture signing is acceptable for local dry-run only. Recording-window
artifacts should use `--sign-mode real` when cosign/OIDC is available:

```bash
cargo run -p aibom-cli -- fleet-manifest \
  --evidence-dir "$RECORDING_OUT" \
  --output "$RECORDING_OUT/fleet/fleet-manifest.json" \
  --bundle "$RECORDING_OUT/fleet/fleet-manifest.sigstore.json" \
  --recording-scope "recording window YYYY-MM-DD" \
  --sign-mode real
```

## Terraform

Do not run paid apply until the no-spend gate is green.

Safe commands:

```bash
cd infra/demo-fleet/terraform
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform plan -var-file=recording.tfvars.example
```

`recording.tfvars.example` keeps all endpoint maps empty. Real endpoint
maps must be reviewed before any cloud apply.

`recording.tfvars.review.example` maps a small scene-critical subset from
`variant-matrix.md`. It is for plan review only. Do not apply it.

Teardown rehearsal:

```bash
infra/demo-fleet/scripts/teardown-dry-run.sh
infra/demo-fleet/scripts/teardown-dry-run.sh --review
```

The script runs `init -backend=false`, `fmt -check`, `validate`, and
`plan -destroy -refresh=false`. It never applies and never destroys.
Default mode uses the empty tfvars file. `--review` exercises the
scene-critical endpoint map shape but still stays no-spend because it is
only a plan.

## Ansible

Dry-run shape:

```bash
cd infra/demo-fleet/ansible
ansible-playbook -i inventory/local.yml playbooks/plant-and-scan.yml --check
```

Real recording hosts should use provider-generated inventory, not the
local inventory file.

## Artifact Layout

R2 or any S3-compatible bucket is only a demo artifact bucket.

```text
demo-fleet/
  recording-YYYYMMDD/
    endpoints/<endpoint-id>/
      scan-*.aibom.json
      scan-*.cdx.json
      scan-*.sigstore.json
      scan-*.sensitive-data.json
      scan-*.sensitive-data.sigstore.json
    fleet/
      fleet-manifest.json
      fleet-manifest.sigstore.json
      report.html
```

No-spend upload validation:

```bash
infra/demo-fleet/scripts/upload-artifacts.sh \
  --source "$RECORDING_OUT" \
  --bucket "$REEVE_DEMO_ARTIFACT_BUCKET" \
  --prefix "recording-YYYYMMDD"
```

This only validates the tree and prints the S3 destination. It does not use
network or upload anything unless `--execute` is passed.

Recording-window upload:

```bash
AWS_ENDPOINT_URL_S3="$R2_ENDPOINT_URL" \
infra/demo-fleet/scripts/upload-artifacts.sh \
  --source "$RECORDING_OUT" \
  --bucket "$REEVE_DEMO_ARTIFACT_BUCKET" \
  --prefix "recording-YYYYMMDD" \
  --execute
```

The script refuses to upload fixture Sigstore bundles unless
`--allow-fixture` is passed. Recording artifacts should use real signing.

## Recording Gate

Before paid apply:

- `variant-matrix.md` reviewed;
- Terraform plan reviewed with real endpoint maps;
- Ansible role catalog reviewed;
- local dry run produces both signed artifact families;
- teardown dry run succeeds against empty tfvars and review tfvars;
- upload dry run validates the artifact tree and destination prefix;
- review tfvars maps only approved scene-critical endpoint IDs;
- recording script references endpoint IDs from matrix;
- vulnerable evidence has no named CVE unless separately verified;
- founder approves recording window and teardown.
