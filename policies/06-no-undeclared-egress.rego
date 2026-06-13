package reeve.policy

import rego.v1

policy_06_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  declared_hosts := {cap.qualifiers.host |
    some cap in component.capabilities.declared
    cap.id == "net:egress"
    cap.qualifiers.host
  }
  undeclared_observed := [cap |
    some cap in component.capabilities.observed
    cap.id == "net:egress"
    not declared_hosts[cap.qualifiers.host]
  ]
  count(undeclared_observed) > 0
  hosts := sort({cap.qualifiers.host | cap := undeclared_observed[_]})
  verdict := {
    "id": sprintf("policy-06-%03d", [i]),
    "policyId": "no-undeclared-egress",
    "bomRef": component["bom-ref"],
    "status": "deny",
    "justification": sprintf(
      "Observed network egress to undeclared hosts for %s: %s",
      [component["bom-ref"], concat(", ", hosts)],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/declared", [i]),
      sprintf("/aibom/components/%d/capabilities/observed", [i]),
    ],
  }
]
