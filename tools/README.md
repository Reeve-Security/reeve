# Tools Boundary

`tools/` is the reusable open-source side of the repo: deployment helpers,
MDM templates, validation labs, and related automation that supports Reeve's
published install and test path.

`private/` is the internal-only side of the repo. Keep run evidence, customer
material, secrets, GTM notes, and any environment-specific outputs there. Do
not move those artifacts into `tools/` or any tracked directory.

Tracked files under `tools/` must stay reusable and placeholder-only:

- no Terraform state, Ansible inventories, or evidence outputs;
- no real VPS IPs, tokens, customer names, or personal workstation paths;
- example IPs use documentation ranges such as `203.0.113.0/24`; and
- local run inputs belong under `private/phase1-input/`.

CI enforces this with `scripts/check-tools-oss-readiness.py` plus gitleaks.
