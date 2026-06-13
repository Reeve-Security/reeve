package reeve.policy

import rego.v1

policy_09_verdicts := [verdict |
  minimum_versions := object.get(input.config, "minimum_package_versions", {})
  count(minimum_versions) > 0
  some i
  component := input.aibom.components[i]
  bom_ref := component["bom-ref"]
  package_key := purl_package_key(bom_ref)
  minimum := minimum_versions[package_key]
  current := purl_version(bom_ref)
  semver_less(current, minimum)
  verdict := {
    "id": sprintf("policy-09-%03d", [i]),
    "policyId": "no-version-downgrade",
    "bomRef": bom_ref,
    "status": "deny",
    "justification": sprintf("Package %s version %s is below configured minimum %s", [package_key, current, minimum]),
    "references": [sprintf("/aibom/components/%d/bom-ref", [i]), sprintf("/config/minimum_package_versions/%s", [package_key])],
  }
]

policy_09_verdicts := [] if {
  count(object.get(input.config, "minimum_package_versions", {})) == 0
}

policy_09_verdicts := [] if {
  minimum_versions := object.get(input.config, "minimum_package_versions", {})
  count(minimum_versions) > 0
  not some_downgrade(minimum_versions)
}

some_downgrade(minimum_versions) if {
  some component in input.aibom.components
  bom_ref := component["bom-ref"]
  package_key := purl_package_key(bom_ref)
  minimum := minimum_versions[package_key]
  current := purl_version(bom_ref)
  semver_less(current, minimum)
}

purl_package_key(bom_ref) := package_key if {
  parts := split(bom_ref, "@")
  count(parts) > 1
  package_key := concat("@", array.slice(parts, 0, count(parts) - 1))
}

purl_version(bom_ref) := version if {
  parts := split(bom_ref, "@")
  count(parts) > 1
  version := parts[count(parts) - 1]
}

semver_less(current, minimum) if {
  current_parts := semver_numbers(current)
  minimum_parts := semver_numbers(minimum)
  semver_numbers_less(current_parts, minimum_parts)
}

semver_numbers(version) := [to_number(parts[i]) |
  parts := split(version, ".")
  some i
  i < count(parts)
]

semver_numbers_less(current, minimum) if {
  current[0] < minimum[0]
}

semver_numbers_less(current, minimum) if {
  current[0] == minimum[0]
  current[1] < minimum[1]
}

semver_numbers_less(current, minimum) if {
  current[0] == minimum[0]
  current[1] == minimum[1]
  current[2] < minimum[2]
}
