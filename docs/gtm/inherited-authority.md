# Inherited authority

AI agent approvals do not bypass OS privilege controls. They turn past user
consent into persistent agent authority.

This is the buyer-facing risk Reeve should explain clearly: agents can remember
"always approve" choices, and a compromised user session, endpoint, or agent can
inherit those saved approvals. The OS still sees ordinary user-context activity,
and EDR may still alert on behavior. The missing inventory is the persistent
agent-authority state itself.

## Technical deck line

Headline: AI approvals are inherited authority.

- AI agents persist saved approvals such as command allow-lists, tool grants,
  and project-scoped permission decisions.
- When the user, session, or agent process is compromised, the attacker can
  inherit those saved actions without asking the user again.
- Risk is highest when the terminal is already elevated, authentication is
  cached, UAC is weakened, or the saved approval includes an elevation primitive
  such as `sudo`, `runas`, or `osascript ... with administrator privileges`.
- Traditional endpoint tools may observe the resulting process behavior, but
  they usually do not inventory the saved AI-agent approvals that made the path
  available.
- Reeve models that surface as `granted-permission` evidence and
  `capabilities.granted[]`.

## Executive deck line

Headline: AI tools created a new authority surface.

- Traditional supply-chain risk starts with a compromised package.
- AI-agent risk can start with a compromised user or agent inheriting saved
  approvals.
- SBOM, DLP, and EDR tools do not provide a durable inventory of persistent
  AI-agent approval state.
- Reeve is the inventory and trust layer for that surface.

## Red lines

- Do not claim AI approvals bypass UAC, `sudo`, TCC, or EDR.
- Do not claim EDR never alerts.
- Do not claim runtime enforcement from this feature. Reeve records evidence.
- Do not imply every saved approval is dangerous. Policy determines risk from
  scope, command shape, path sensitivity, and elevation behavior.

## Product hooks

- Umbrella tracker: [#4](https://github.com/Reeve-Security/reeve/issues/4)
- Scanner implementation tracker:
  [#83](https://github.com/Reeve-Security/reeve/issues/83)
- Schema decision:
  [ADR-0008](../decisions/0008-granted-source-amendment.md)
