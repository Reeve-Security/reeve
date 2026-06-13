package reeve.policy

import rego.v1

policy_11_verdicts := array.concat(policy_11_warn_verdicts, policy_11_deny_verdicts)

policy_11_warn_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  caps := array.concat(component.capabilities.declared, component.capabilities.observed)
  unknown_ids := sort({cap.id |
    some cap in caps
    is_unknown_extension(cap.id)
  })
  count(unknown_ids) > 0
  lower(input.config.profile) != "strict"
  verdict := {
    "id": sprintf("policy-11-%03d", [i]),
    "policyId": "no-unknown-extension-capability",
    "bomRef": component["bom-ref"],
    "status": "warn",
    "justification": sprintf(
      "Capability ids for %s use extension namespaces outside allowlist: %s",
      [component["bom-ref"], concat(", ", unknown_ids)],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/declared", [i]),
      sprintf("/aibom/components/%d/capabilities/observed", [i]),
    ],
  }
]

policy_11_deny_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  caps := array.concat(component.capabilities.declared, component.capabilities.observed)
  unknown_ids := sort({cap.id |
    some cap in caps
    is_unknown_extension(cap.id)
  })
  count(unknown_ids) > 0
  lower(input.config.profile) == "strict"
  verdict := {
    "id": sprintf("policy-11-%03d", [i]),
    "policyId": "no-unknown-extension-capability",
    "bomRef": component["bom-ref"],
    "status": "deny",
    "justification": sprintf(
      "Capability ids for %s use extension namespaces outside allowlist: %s",
      [component["bom-ref"], concat(", ", unknown_ids)],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/declared", [i]),
      sprintf("/aibom/components/%d/capabilities/observed", [i]),
    ],
  }
]
