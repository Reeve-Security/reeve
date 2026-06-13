package reeve.policy

import rego.v1

policy_07_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  has_declared_exec := count([cap |
    some cap in component.capabilities.declared
    cap.id == "exec:subprocess"
  ]) > 0
  observed_exec := [cap |
    some cap in component.capabilities.observed
    cap.id == "exec:subprocess"
  ]
  count(observed_exec) > 0
  not has_declared_exec
  cmds := sort({cap.qualifiers.cmd | cap := observed_exec[_]; cap.qualifiers.cmd})
  verdict := {
    "id": sprintf("policy-07-%03d", [i]),
    "policyId": "no-exec-without-capability",
    "bomRef": component["bom-ref"],
    "status": "deny",
    "justification": sprintf(
      "Observed subprocess execution without declared exec:subprocess capability for %s. Commands: %s",
      [component["bom-ref"], concat(", ", cmds)],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/declared", [i]),
      sprintf("/aibom/components/%d/capabilities/observed", [i]),
    ],
  }
]
