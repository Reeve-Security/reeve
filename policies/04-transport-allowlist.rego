package reeve.policy

import rego.v1

policy_04_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  transport := transport_type(component)
  not transport_in_allowlist(transport, input.config.transportAllowlist)
  verdict := {
    "id": sprintf("policy-04-%03d", [i]),
    "policyId": "transport-allowlist",
    "bomRef": component["bom-ref"],
    "status": "deny",
    "justification": sprintf(
      "Transport %s for %s is not in the permitted allowlist.",
      [transport, component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d/transport", [i]),
    ],
  }
]

transport_type(component) := "stdio" if {
  component.transport.type == "stdio"
} else := "http-sse" if {
  component.transport.type == "http-sse"
} else := "websocket" if {
  component.transport.type == "websocket"
} else := "unknown" if {
  component.transport.type == "unknown"
} else := component.transport.type

transport_in_allowlist(transport, allowlist) := true if {
  allowlist
  some allowed in allowlist
  lower(allowed) == lower(transport)
} else := true if {
  not allowlist
} else := false
