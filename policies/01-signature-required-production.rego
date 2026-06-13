package reeve.policy

import rego.v1

policy_01_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  is_production_profile
  is_stdio_transport(component)
  not has_sigstore_signature(component)
  verdict := {
    "id": sprintf("policy-01-%03d", [i]),
    "policyId": "signature-required-production",
    "bomRef": component["bom-ref"],
    "status": "deny",
    "justification": sprintf(
      "Unsigned stdio MCP server %s in production target. Signature required per policy #01.",
      [component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d", [i]),
      "/aibom/provenance",
    ],
  }
]

is_production_profile if {
  lower(input.config.profile) == "production"
} else := true if {
  lower(input.config.profile) == "strict"
}

is_stdio_transport(component) if {
  component.transport.type == "stdio"
} else := true if {
  component.transport.command
}

has_sigstore_signature(component) := true if {
  component.provenance.sigstoreBundle
} else := true if {
  input.aibom.provenance
  some p in input.aibom.provenance
  p.bomRef == component["bom-ref"]
  p.sigstoreBundle
} else := false
