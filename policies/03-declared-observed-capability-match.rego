package reeve.policy

import rego.v1

policy_03_verdicts := array.concat(policy_03_rule_a_verdicts, policy_03_rule_b_verdicts)

policy_03_rule_a_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  has_declared_core(component)
  extras := [cap |
    cap := component.capabilities.observed[_]
    observed_extra_core(component, cap)
  ]
  count(extras) > 0
  ids := sort({cap.id | cap := extras[_]})
  verdict := {
    "id": sprintf("policy-03-rule-a-%03d", [i]),
    "policyId": "declared-observed-capability-match",
    "bomRef": component["bom-ref"],
    "status": "deny",
    "justification": sprintf(
      "Observed undeclared core capabilities for %s: %s",
      [component["bom-ref"], concat(", ", ids)],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/declared", [i]),
      sprintf("/aibom/components/%d/capabilities/observed", [i]),
    ],
  }
]

policy_03_rule_b_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  not has_declared_core(component)
  has_declared_mcp(component)
  extras := [cap |
    cap := component.capabilities.observed[_]
    observed_extra_core(component, cap)
  ]
  count(extras) > 0
  ids := sort({cap.id | cap := extras[_]})
  verdict := {
    "id": sprintf("policy-03-rule-b-%03d", [i]),
    "policyId": "declared-observed-capability-match",
    "bomRef": component["bom-ref"],
    "status": "warn",
    "justification": sprintf(
      "Observed concrete core capabilities for %s but declarations are only mcp:* stubs: %s",
      [component["bom-ref"], concat(", ", ids)],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/declared", [i]),
      sprintf("/aibom/components/%d/capabilities/observed", [i]),
    ],
  }
]
