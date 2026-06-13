package reeve.policy

import rego.v1

# Policy #14 - sensitive secret pattern
#
# Warns on unsuppressed pattern findings in the separate sensitive-data
# report. A warning means "needs human review", not "confirmed leak".

policy_14_verdicts := array.concat(policy_14_malformed_verdicts, policy_14_finding_verdicts)

policy_14_malformed_verdicts := [verdict |
  report := input.sensitiveDataReport
  inputs := object.get(report, "inputs", {})
  object.get(inputs, "contentPatternScan", false)
  count(object.get(inputs, "rulePacks", [])) == 0
  verdict := {
    "id": "policy-14-missing-rule-pack",
    "policyId": "sensitive-secret-pattern",
    "bomRef": null,
    "status": "deny",
    "justification": "Sensitive-data report enabled content pattern scanning but records no rule-pack identity; policy cannot audit which rules matched.",
    "references": [
      "/sensitiveDataReport/inputs/contentPatternScan",
      "/sensitiveDataReport/inputs/rulePacks",
    ],
  }
]

policy_14_finding_verdicts := [verdict |
  report := input.sensitiveDataReport
  some i
  finding := report.findings[i]
  not object.get(finding, "suppressed", false)
  pattern_class := object.get(finding, "patternClass", "unknown")
  verdict := {
    "id": sprintf("policy-14-finding-%03d", [i]),
    "policyId": "sensitive-secret-pattern",
    "bomRef": null,
    "status": "warn",
    "justification": sprintf(
      "Sensitive-data report contains %s pattern evidence that needs human review; this is not proof of a confirmed leak.",
      [pattern_class],
    ),
    "references": [
      sprintf("/sensitiveDataReport/findings/%d", [i]),
      "/sensitiveDataReport/inputs/contentPatternScan",
    ],
  }
]
