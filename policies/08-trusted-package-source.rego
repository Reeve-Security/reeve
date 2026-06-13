package reeve.policy

import rego.v1

policy_08_verdicts := [verdict |
  trusted_sources := object.get(input.config, "trusted_package_sources", [])
  count(trusted_sources) > 0
  some i
  component := input.aibom.components[i]
  bom_ref := component["bom-ref"]
  not trusted_package_source(bom_ref, trusted_sources)
  verdict := {
    "id": sprintf("policy-08-%03d", [i]),
    "policyId": "trusted-package-source",
    "bomRef": bom_ref,
    "status": "deny",
    "justification": sprintf("Package source for %s is outside configured trusted sources", [bom_ref]),
    "references": [sprintf("/aibom/components/%d/bom-ref", [i]), "/config/trusted_package_sources"],
  }
]

policy_08_verdicts := [] if {
  count(object.get(input.config, "trusted_package_sources", [])) == 0
}

trusted_package_source(bom_ref, trusted_sources) if {
  some source in trusted_sources
  normalized_bom_ref := lower(bom_ref)
  normalized_source := lower(source)
  normalized_bom_ref == normalized_source
}

trusted_package_source(bom_ref, trusted_sources) if {
  some source in trusted_sources
  normalized_bom_ref := lower(bom_ref)
  normalized_source := lower(source)
  startswith(normalized_bom_ref, sprintf("%s/", [normalized_source]))
}
