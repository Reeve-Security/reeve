#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TFDIR="${ROOT}/infra/demo-fleet/terraform"
TFVARS="${TFDIR}/recording.tfvars.example"
PLAN_OUT="${TFDIR}/teardown-dry-run.tfplan"
SKIP_INIT=0

usage() {
  cat <<'USAGE'
usage: infra/demo-fleet/scripts/teardown-dry-run.sh [--review] [--tfvars PATH] [--plan-out PATH] [--skip-init]

No-spend teardown rehearsal. Runs init/validate plus a destroy plan with
refresh disabled. It never applies, never destroys, and defaults to the
empty recording.tfvars.example.

Options:
  --review       use terraform/recording.tfvars.review.example
  --tfvars PATH  use explicit tfvars file
  --plan-out PATH
                 write plan to PATH (default: terraform/teardown-dry-run.tfplan)
  --skip-init    skip init when providers are already installed
USAGE
}

abspath() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$(pwd)" "$1" ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --review)
      TFVARS="${TFDIR}/recording.tfvars.review.example"
      shift
      ;;
    --tfvars)
      if [[ $# -lt 2 ]]; then
        echo "--tfvars requires PATH" >&2
        exit 2
      fi
      TFVARS="$2"
      shift 2
      ;;
    --plan-out)
      if [[ $# -lt 2 ]]; then
        echo "--plan-out requires PATH" >&2
        exit 2
      fi
      PLAN_OUT="$2"
      shift 2
      ;;
    --skip-init)
      SKIP_INIT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

TFVARS="$(abspath "${TFVARS}")"
PLAN_OUT="$(abspath "${PLAN_OUT}")"

if [[ -n "${TERRAFORM_BIN:-}" ]]; then
  TF="${TERRAFORM_BIN}"
elif command -v tofu >/dev/null 2>&1; then
  TF="tofu"
elif command -v terraform >/dev/null 2>&1; then
  TF="terraform"
else
  echo "missing OpenTofu/Terraform; install tofu or terraform, or set TERRAFORM_BIN" >&2
  exit 1
fi

if [[ ! -f "${TFVARS}" ]]; then
  echo "tfvars not found: ${TFVARS}" >&2
  exit 1
fi

mkdir -p "$(dirname "${PLAN_OUT}")"
export TF_IN_AUTOMATION=1

if [[ "${SKIP_INIT}" -eq 0 ]]; then
  "${TF}" -chdir="${TFDIR}" init -backend=false -input=false
fi

"${TF}" -chdir="${TFDIR}" fmt -check -recursive
"${TF}" -chdir="${TFDIR}" validate
"${TF}" -chdir="${TFDIR}" plan \
  -destroy \
  -refresh=false \
  -input=false \
  -var-file="${TFVARS}" \
  -out="${PLAN_OUT}"

echo "teardown dry-run PASS"
echo "tfvars: ${TFVARS}"
echo "plan: ${PLAN_OUT}"
