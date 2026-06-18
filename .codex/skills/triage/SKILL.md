---
name: triage
description: >
  Standard Reeve process for taking a finding, bug, or feature from intake to a
  merged fix. Use when the user says "triage this", "work issue #N", "intake this
  finding", "create an advisory for this", "open a PR for this", or pastes a
  security review / bug report to turn into tracked work. Covers classification
  (public issue vs private advisory), branching, the Opus-build / Codex-verify
  loop, and PR creation — all via the `gh` CLI. This file is the single source of
  truth; AGENTS.md points Codex here.
---

# Triage: issue & PR workflow

You (the agent) are the author; `gh` is the executor. Generate every title, body,
and JSON payload into a file, then `gh` ships the file — the human never hand-types
a description. Run this **one item at a time**: these steps create advisories and
PRs (real side effects), so the human approves each before it ships.

## Repo variables (edit if these change)
- REPO: `<OWNER>/reeve`
- TEST: `cargo test`
- DEFAULT BRANCH: `main`

---

## Step 0 — Classify
- **PRIVATE (advisory)** — weaponizable from the text alone: RCE, privilege
  escalation, secret/credential leak, sandbox escape, auth bypass. Never put these
  in a public issue.
- **PUBLIC (issue)** — correctness, "claims a property it doesn't deliver",
  resource exhaustion without a clear exploit primitive, features, refactors.

Items sharing a root cause or the same code path become ONE tracked item with a
task list — never parallel branches on the same file.

## Step 1 — Intake

**Public issue** — write body to `issue.md` (Evidence / Impact / Acceptance, where
Acceptance is the negative test that must pass), then:
```bash
gh issue create --repo <OWNER>/reeve --title "<title>" --label security,high --body-file issue.md
```

**Private advisory** — write `advisory.json`. Required: `summary`, `description`,
`vulnerabilities[]`. Set EITHER `severity` OR `cvss_vector_string`, never both.
`"start_private_fork": true` creates the private fork in the same call.
```json
{
  "summary": "<short title>",
  "description": "<impact + evidence (file:line) + workaround>",
  "severity": "critical",
  "vulnerabilities": [{ "package": { "ecosystem": "other", "name": "aibom-cli" },
    "vulnerable_version_range": "<= current", "patched_versions": "" }],
  "start_private_fork": true
}
```
```bash
gh api repos/<OWNER>/reeve/security-advisories --method POST --input advisory.json
```
Auth note: for `gh` OAuth/classic PAT auth, `repo` scope is sufficient for this
endpoint when the user is a repository security manager or administrator.
`repository_advisories:write` is not a valid `gh auth refresh` scope in all auth
flows; do not block on `gh auth refresh -s repository_advisories:write`. If POST
returns 403, verify role/permission first. Fine-grained PATs or GitHub Apps need
the "Repository security advisories" repository permission (write). The response
has the GHSA id and private-fork URL; clone that fork and work there, NOT in the
public repo.

## Step 2 — Branch
- Public: `gh issue develop <N> --repo <OWNER>/reeve --base main --checkout`
- Private: clone the advisory's private fork, branch off `main` there.

## Step 3 — Build (Opus)
Implement the fix AND a negative test that fails before the fix and passes after.
The test is the definition of done.

## Step 4 — Verify (Codex)
Hand Codex the diff AND the original finding. It checks the fix against its own
report, not just that it compiles, and confirms the negative test genuinely fails
without the fix. Loop Opus <-> Codex until Codex signs off.

## Step 5 — Gate
Run `cargo test`. Must be green. This is the real gate; agent agreement is the
quality layer on top, not a substitute. Never proceed on a red/skipped test.

## Step 6 — PR
Write body to `pr.md` with `Closes #<N>` (or advisory reference) and a
`Codex sign-off: yes` line. Then:
```bash
gh pr create --repo <OWNER>/reeve --base main --title "<Fix: ...>" --body-file pr.md
```
Advisory work: open the PR inside the private fork. After merge + fixed release,
publish the advisory (deletes the private fork; with a patched version set,
Dependabot points users at the safe version).

## Guardrails
- Never push directly to `main` — everything goes through a PR.
- Never open a public issue for a PRIVATE-track item.
- Never merge with a red/skipped acceptance test.
- Never parallelize two items touching the same file.
