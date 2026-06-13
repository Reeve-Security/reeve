package reeve.policy

import rego.v1

policy_02_verdicts := array.concat(policy_02_unverified_verdicts, policy_02_subject_verdicts)

policy_02_unverified_verdicts := [verdict |
  input.aibom
  allowlist := object.get(input.config, "publisher_allowlist", [])
  count(allowlist) > 0
  not input.signature.verified
  verdict := {
    "id": "policy-02-unverified-signature",
    "policyId": "publisher-allowlist",
    "bomRef": null,
    "status": "deny",
    "justification": "Publisher allowlist is configured, but no verified signature subject fact is available",
    "references": ["/signature/verified", "/config/publisher_allowlist"],
  }
]

policy_02_subject_verdicts := [verdict |
  input.aibom
  allowlist := object.get(input.config, "publisher_allowlist", [])
  count(allowlist) > 0
  input.signature.verified
  subject := object.get(input.signature, "subject", "")
  not subject in allowlist
  verdict := {
    "id": "policy-02-subject-not-allowed",
    "policyId": "publisher-allowlist",
    "bomRef": null,
    "status": "deny",
    "justification": sprintf("Verified publisher subject is not in the configured allowlist: %s", [subject]),
    "references": ["/signature/subject", "/config/publisher_allowlist"],
  }
]
