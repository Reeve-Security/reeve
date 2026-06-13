# ADR-0021: Customer secret rule packs use a versioned public schema

- **Status:** Accepted 2026-05-14
- **Decides:** Issue #178 customer conversation-secret rule pack contract
- **Related:** ADR-0019, Issue #165, Issue #171, Issue #178, `schema/sensitive-data-report-v0.1.0.json`, `schema/secret-rule-pack-v0.1.0.json`

## Context

ADR-0019 separates conversation-log sensitive-data findings from the AIBOM.
Issue #171 added the second opt-in content pattern scan with a built-in
default rule pack for common secret classes: AWS access keys, JWTs, Stripe
keys, OAuth client secrets, OpenAI keys, and Anthropic keys.

Customers also need to scan for patterns only they understand: internal
token prefixes, customer identifiers, project names, regulated-data
markers, and organization-specific allow/deny patterns. Those rules will
often be checked into customer repositories and reviewed by security,
privacy, and legal teams.

That makes the rule file itself a public contract. Reeve needs a stable
schema for customer rule packs before adding `--conversation-rules-file`.

## Options considered

### A. Hardcode every supported pattern in Reeve

Reeve would continue to ship only built-in patterns. Customers would file
issues or patches for new rule classes.

Pros: simplest scanner behavior and least configuration surface.

Cons: cannot model customer-specific identifiers, forces private business
taxonomy into upstream code, and makes customers wait for releases before
they can detect their own sensitive patterns.

### B. Accept ad hoc regex files

Reeve would take a plain list of regular expressions with minimal metadata.

Pros: fast to build and easy for engineers to understand.

Cons: poor auditability. A report could say "custom rule matched" without
stable rule identity, version, confidence, or reviewer-readable
description. It also risks unsafe regex features and makes reproduction
hard months later.

### C. Publish a versioned secret-rule-pack schema *(chosen)*

Reeve defines `schema/secret-rule-pack-v0.1.0.json`. Customer rule packs
must validate against that schema before scanning. Each rule has a stable
`ruleId`, `patternClass`, `confidence`, `description`, and regex. The
report records rule pack identity, version, and digest, not rule content
or matched values.

Pros: auditable, reproducible, compatible with customer code review, and
consistent with Reeve's schema-first thesis.

Cons: requires schema maintenance and migration policy for future rule
pack versions.

## Decision

Customer secret rule packs will use a published JSON Schema contract.

The first schema version should include, at minimum:

- `rulePackId`;
- `rulePackVersion`;
- `rules[]`;
- `rules[].ruleId`;
- `rules[].patternClass`;
- `rules[].confidence`;
- `rules[].description`;
- `rules[].regex`;
- a safe-regex validation requirement.

Rule packs are operator-supplied input. Reeve records their identity and
SHA-256 digest in the sensitive-data report so findings can be reproduced
without serializing rule content or matched values.

Implementation exposes this through `--conversation-rules-file`. Custom
rules extend the built-in pack when `--scan-conversation-secrets` is set.
Reports store each customer pack as
`<rulePackId>@<rulePackVersion>:<sha256-of-rule-content>` under
`inputs.customRules[].canonicalId`.

The default built-in rule pack remains shipped and locked. Customer rule
packs extend coverage; they do not weaken the privacy rule from ADR-0019.
Findings still serialize only pointer-style evidence: redacted path,
pattern class, rule id, match count, confidence, and human-review marker.

Starter templates may ship after the schema and custom rule loading land.
Templates are useful, but they are not required for the first public
contract.

## Rationale

Reeve's core advantage is portable evidence. Portable evidence requires
portable inputs. If a customer scans with a private rule pack, an auditor
must be able to see which rule pack version was used and verify that a
later scan used the same definitions.

The report should bind to exact rule definitions through a digest, but it
must not expose those definitions by default. A rule named
`acme.project-codename` could itself leak business context. Recording
identity and digest is enough for reproducibility while keeping the
customer's taxonomy in their environment.

Safe-regex enforcement is part of the scanner threat model. Reeve must not
let untrusted or poorly reviewed rules turn endpoint scanning into a denial
of service through catastrophic backtracking.

Schema-first also matches the rest of the project. Customers can validate
rule files in CI before deploying them through MDM, the same way they can
validate AIBOM and sensitive-data report artifacts.

## Plain-language summary

Reeve should ship useful default secret checks, but every company has its
own idea of "sensitive." One company may care about IDs that start with
`ACME-`. Another may care about internal project names or regulated
record numbers.

Customers need a way to teach Reeve those patterns without sending them
to us and without waiting for a new Reeve release.

This decision says customer rules are real product surface, not a loose
text file. They get a schema, version, IDs, descriptions, and a digest.
That lets a security team review rule changes before rollout and lets an
auditor reproduce why a finding appeared.

The sensitive-data report still stays privacy-safe. It says a rule
matched, where to look, and how many times. It does not print the secret,
the surrounding conversation, or the customer's private rule definitions.

Think of it as a smoke alarm with customer-swappable sensors. The alarm
tells you which sensor fired and where. It does not store the fire.

## Consequences

- **This decision commits the project to:** publishing a
  `secret-rule-pack-v0.1.0` schema before custom rule loading is treated
  as shipped; validating custom rule packs before scanning; recording
  rule pack identities and digests in sensitive-data reports; and keeping
  raw matches, snippets, secret hashes, and rule contents out of findings.
- **This decision unblocks:** Issue #178 implementation,
  customer-defined conversation-secret patterns, CI validation for rule
  packs, and later starter templates.
- **This decision forecloses:** accepting unversioned ad hoc regex lists
  as the long-term customer interface, and claiming customer-configurable
  rules before schema validation and tests exist.
- **This decision defers:** exact JSON field naming, template pack
  contents, paid aggregation behavior, and whether future versions support
  non-regex match engines.

## References

- [ADR-0019: Conversation-log scanning uses a separate opt-in sensitive-data report](0019-conversation-log-sensitive-data-report.md)
- Issue #165
- Issue #171
- Issue #178
- `schema/sensitive-data-report-v0.1.0.json`
