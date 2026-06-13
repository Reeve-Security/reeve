package reeve.policy

import rego.v1

policy_05_verdicts := [verdict |
  max_age := object.get(input.config, "max_scan_age_seconds", null)
  max_age != null
  policy_time := object.get(input.config, "policy_time", null)
  policy_time != null
  scan_time := time.parse_rfc3339_ns(input.aibom.scan.timestamp)
  now_time := time.parse_rfc3339_ns(policy_time)
  age_seconds := (now_time - scan_time) / 1000000000
  age_seconds > max_age
  verdict := {
    "id": "policy-05-scan-too-old",
    "policyId": "maximum-scan-age",
    "bomRef": null,
    "status": "deny",
    "justification": sprintf("AIBOM scan is older than configured maximum age: %d seconds > %d seconds", [age_seconds, max_age]),
    "references": ["/aibom/scan/timestamp", "/config/max_scan_age_seconds", "/config/policy_time"],
  }
]

policy_05_verdicts := [] if {
  object.get(input.config, "max_scan_age_seconds", null) == null
}

policy_05_verdicts := [] if {
  object.get(input.config, "policy_time", null) == null
}

policy_05_verdicts := [] if {
  max_age := object.get(input.config, "max_scan_age_seconds", null)
  max_age != null
  policy_time := object.get(input.config, "policy_time", null)
  policy_time != null
  scan_time := time.parse_rfc3339_ns(input.aibom.scan.timestamp)
  now_time := time.parse_rfc3339_ns(policy_time)
  age_seconds := (now_time - scan_time) / 1000000000
  age_seconds <= max_age
}
