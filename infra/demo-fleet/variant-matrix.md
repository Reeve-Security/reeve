# Demo Fleet Variant Matrix

This is the scene-first endpoint matrix for the one-shot recording
dataset in ADR-0023 and issue #191. It gives the recording script stable
endpoint IDs before Terraform and Ansible exist.

The matrix is allowed to change during #191 implementation, but changes
must preserve the recording scenes in [`docs/demo-script.md`](../../docs/demo-script.md)
or update that script in the same PR.

## Evidence Codes

| Code | Meaning |
|---|---|
| `MR` | MCP registration evidence from default config discovery |
| `TL` | MCP tools list from explicit `--introspect-execute` |
| `PO` | Profile-observed behavior from explicit `--profile` |
| `GP` | Granted-permission / approval-state evidence |
| `SR` | Sensitive-data report from conversation-secret opt-ins |
| `VV-N` | Vulnerable-version or advisory evidence slot; exact CVE/advisory label must be verified before it is named publicly |
| `DR` | Config-drift evidence between two scans |
| `SG` | Signed endpoint artifact and fleet-manifest evidence |

## Platform Shape

| Platform | Count | Purpose |
|---|---:|---|
| Linux | 30 | developer-heavy and cheap fleet breadth |
| Windows | 15 | buyer-realistic finance, HR, sales, marketing endpoints |
| macOS | 5 | executive, creative, and desktop-app-heavy endpoints |
| **Total** | **50** | one-shot recording dataset |

## Endpoint Matrix

| Endpoint ID | OS | Persona | Assistant mix | Evidence slots | Recording scenes | Notes |
|---|---|---|---|---|---|---|
| `eng-linux-01` | Linux | Engineering | Claude Code, Cursor, VS Code MCP | MR, SG | 1, 2, 8 | Clean baseline developer endpoint |
| `eng-linux-02` | Linux | Engineering | Claude Code, Codex CLI, Continue | MR, TL, PO, SG | 3 | Consent ladder endpoint |
| `eng-linux-03` | Linux | Engineering | Cursor, VS Code MCP | MR, GP, DR, SG | 7 | Drift pair: new MCP registration |
| `eng-linux-04` | Linux | Engineering | Claude Code, custom MCP | MR, TL, PO, VV-02, SG | 4 | Advisory label not assigned in current v0.1 script |
| `eng-linux-05` | Linux | Engineering | Codex CLI, VS Code MCP | MR, GP, SG | 5 | Saturated always-allow variant |
| `eng-linux-06` | Linux | Engineering | Claude Code, Codex CLI | MR, SR, SG | 6 | Planted OpenAI/Anthropic test secret report |
| `mkt-linux-01` | Linux | Marketing | Claude Desktop, image MCP | MR, SG | 1 | Clean non-developer Linux variant |
| `mkt-linux-02` | Linux | Marketing | Claude Desktop, custom MCP | MR, TL, SG | 9 optional | Corpus-match candidate if #111 ships |
| `mkt-linux-03` | Linux | Marketing | Cursor, VS Code MCP | MR, GP, SG | 1 | Mixed approvals |
| `mkt-linux-04` | Linux | Marketing | Continue, custom MCP | MR, PO, SG | 1 | Observed network attempt candidate |
| `mkt-linux-05` | Linux | Marketing | Claude Code | MR, SR, SG | 1 | Planted API-key report |
| `mkt-linux-06` | Linux | Marketing | Codex CLI | MR, DR, SG | 7 | Drift reserve |
| `fin-linux-01` | Linux | Finance | Codex CLI, spreadsheet MCP | MR, SG | 1 | Clean finance Linux variant |
| `fin-linux-02` | Linux | Finance | Claude Desktop, Codex CLI | MR, GP, SG | 1 | Approval-state reserve |
| `fin-linux-03` | Linux | Finance | Continue, custom MCP | MR, TL, SG | 1 | Tools-list reserve |
| `fin-linux-04` | Linux | Finance | Claude Code | MR, SR, SG | 6 | Planted Stripe/AWS test secret report |
| `fin-linux-05` | Linux | Finance | Cursor | MR, PO, SG | 1 | Profile-observed reserve |
| `fin-linux-06` | Linux | Finance | VS Code MCP | MR, DR, SG | 1 | Drift reserve |
| `hr-linux-01` | Linux | HR | Claude Desktop | MR, SG | 1 | Clean HR Linux variant |
| `hr-linux-02` | Linux | HR | Claude Desktop, custom MCP | MR, TL, SG | 1 | Resume-workflow MCP registration |
| `hr-linux-03` | Linux | HR | Codex CLI | MR, GP, SG | 1 | Approval-state reserve |
| `hr-linux-04` | Linux | HR | Claude Desktop | MR, SR, SG | 6 | Planted OAuth test secret report |
| `hr-linux-05` | Linux | HR | Continue | MR, PO, SG | 1 | Profile-observed reserve |
| `hr-linux-06` | Linux | HR | VS Code MCP | MR, DR, SG | 1 | Drift reserve |
| `sales-linux-01` | Linux | Sales | Cursor, CRM MCP | MR, SG | 1 | Clean sales Linux variant |
| `sales-linux-02` | Linux | Sales | Codex CLI | MR, GP, SG | 1 | Mixed approvals |
| `sales-linux-03` | Linux | Sales | Claude Code, custom MCP | MR, TL, SG | 1 | Tools-list reserve |
| `sales-linux-04` | Linux | Sales | Continue | MR, PO, SG | 1 | Profile-observed reserve |
| `sales-linux-05` | Linux | Sales | Claude Desktop | MR, SR, SG | 1 | Planted API-key report |
| `sales-linux-06` | Linux | Sales | VS Code MCP | MR, DR, SG | 1 | Drift reserve |
| `eng-win-01` | Windows | Engineering | Cursor, VS Code MCP | MR, SG | 1 | Clean Windows developer endpoint |
| `eng-win-02` | Windows | Engineering | Codex CLI, VS Code MCP | MR, PO, SG | 1 | Windows observational profile reserve |
| `eng-win-03` | Windows | Engineering | Claude Code, Cursor | MR, GP, SG | 1 | Approval-state reserve |
| `mkt-win-01` | Windows | Marketing | Claude Desktop, image MCP | MR, SG | 2 | Default inventory scene |
| `mkt-win-02` | Windows | Marketing | Cursor | MR, GP, SG | 1 | Mixed approvals |
| `mkt-win-03` | Windows | Marketing | Claude Desktop | MR, SR, SG | 1 | Planted API-key report |
| `fin-win-01` | Windows | Finance | Codex CLI, spreadsheet MCP | MR, SG | 2 | Default inventory scene |
| `fin-win-02` | Windows | Finance | Claude Desktop | MR, GP, SG | 1 | Approval-state reserve |
| `fin-win-03` | Windows | Finance | Codex CLI, custom MCP | MR, VV-01, SG | 4, 8, 9 optional | Advisory label not assigned in current v0.1 script |
| `hr-win-01` | Windows | HR | Claude Desktop | MR, SG | 1 | Clean HR Windows endpoint |
| `hr-win-02` | Windows | HR | Claude Desktop, custom MCP | MR, TL, SG | 1 | Tools-list reserve |
| `hr-win-03` | Windows | HR | Claude Desktop | MR, GP, SG | 5 | Approval scene |
| `sales-win-01` | Windows | Sales | Cursor, CRM MCP | MR, SG | 1 | Clean sales Windows endpoint |
| `sales-win-02` | Windows | Sales | Codex CLI | MR, PO, SG | 3 | Windows observational profile scene |
| `sales-win-03` | Windows | Sales | Claude Desktop, CRM MCP | MR, VV-03, SG | 4 | Advisory label not assigned in current v0.1 script |
| `eng-macos-01` | macOS | Engineering | Claude Code, Cursor, VS Code MCP | MR, TL, PO, SG | 3 | macOS sandbox profile scene |
| `mkt-macos-01` | macOS | Marketing | Claude Desktop, image MCP | MR, SG | 1 | Creative workflow endpoint |
| `fin-macos-01` | macOS | Finance | Codex CLI, spreadsheet MCP | MR, SR, SG | 1 | Planted secret reserve |
| `hr-macos-01` | macOS | HR | Claude Desktop | MR, GP, SG | 1 | HR approval reserve |
| `sales-macos-01` | macOS | Sales | Cursor, CRM MCP | MR, GP, SG | 5 | Approval scene |

## Recording Gates

- `VV-*` rows cannot show named CVEs unless a follow-up verification pins
  the CVE/advisory source. #192 closed with no named CVEs in the current
  v0.1 demo script.
- Scene 9 cannot be recorded unless #111 emits a signed registry
  reference artifact.
- Windows `PO` rows must be narrated as observational.
- `SR` rows must show redacted reports only.
- Paid cloud apply remains blocked until #191 planning artifacts pass
  review and founder approves the recording window.
