package reeve.policy

import rego.v1

# Policy #13 - sensitive-data volume threshold
#
# Warns when an opt-in sensitive-data report inventories unusually large
# conversation/session stores. This policy works only on the separate
# sensitive-data report, not on the AIBOM sidecar.

sensitive_data_max_file_count := object.get(input.config, "sensitive_data_max_file_count", 1000)

sensitive_data_max_total_bytes := object.get(input.config, "sensitive_data_max_total_bytes", 104857600)

policy_13_verdicts := array.concat(policy_13_file_count_verdicts, policy_13_total_bytes_verdicts)

policy_13_file_count_verdicts := [verdict |
  report := input.sensitiveDataReport
  some i
  surface := report.surfaces[i]
  file_count := object.get(surface, "fileCount", 0)
  file_count > sensitive_data_max_file_count
  verdict := {
    "id": sprintf("policy-13-file-count-%03d", [i]),
    "policyId": "sensitive-data-volume",
    "bomRef": null,
    "status": "warn",
    "justification": sprintf(
      "Sensitive-data report inventories %d files for %s; review retention and access controls.",
      [file_count, object.get(surface, "surface", "unknown")],
    ),
    "references": [
      sprintf("/sensitiveDataReport/surfaces/%d/fileCount", [i]),
      "/config/sensitive_data_max_file_count",
    ],
  }
]

policy_13_total_bytes_verdicts := [verdict |
  report := input.sensitiveDataReport
  some i
  surface := report.surfaces[i]
  total_bytes := object.get(surface, "totalBytes", 0)
  total_bytes > sensitive_data_max_total_bytes
  verdict := {
    "id": sprintf("policy-13-total-bytes-%03d", [i]),
    "policyId": "sensitive-data-volume",
    "bomRef": null,
    "status": "warn",
    "justification": sprintf(
      "Sensitive-data report inventories %d bytes for %s; review retention and access controls.",
      [total_bytes, object.get(surface, "surface", "unknown")],
    ),
    "references": [
      sprintf("/sensitiveDataReport/surfaces/%d/totalBytes", [i]),
      "/config/sensitive_data_max_total_bytes",
    ],
  }
]
