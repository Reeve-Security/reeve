package reeve.policy

import rego.v1

policy_10_verdicts := array.concat(policy_10_warn_verdicts, policy_10_deny_verdicts)

policy_10_warn_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  has_declared_mcp(component)
  lower(input.config.profile) != "strict"
  not has_sigstore_signature(component)
  verdict := {
    "id": sprintf("policy-10-%03d", [i]),
    "policyId": "unsigned-mcp-registration",
    "bomRef": component["bom-ref"],
    "status": "warn",
    "justification": sprintf(
      "Unsigned MCP entry %s. Strict profile denies unsigned MCP servers.",
      [component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d", [i]),
      "/aibom/provenance",
    ],
  }
]

policy_10_deny_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  has_declared_mcp(component)
  lower(input.config.profile) == "strict"
  not has_sigstore_signature(component)
  verdict := {
    "id": sprintf("policy-10-%03d", [i]),
    "policyId": "no-unsigned-mcp-strict",
    "bomRef": component["bom-ref"],
    "status": "deny",
    "justification": sprintf(
      "Unsigned MCP entry %s in strict profile. All MCP servers must carry a valid Sigstore signature.",
      [component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d", [i]),
      "/aibom/provenance",
    ],
  }
]

has_sigstore_signature(component) := true if {
  component.provenance.sigstoreBundle
} else := true if {
  input.aibom.provenance
  some p in input.aibom.provenance
  p.bomRef == component["bom-ref"]
  p.sigstoreBundle
} else := false
