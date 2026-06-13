package reeve.policy

import rego.v1

core_ids := {
  "env:read",
  "exec:subprocess",
  "fs:read",
  "fs:write",
  "ipc:connect",
  "net:egress",
  "net:listen",
  "secret:read",
}

verdicts := array.concat(
  array.concat(
    array.concat(
      array.concat(
        array.concat(
          array.concat(
            array.concat(policy_01_verdicts, policy_02_verdicts),
            policy_03_verdicts,
          ),
          array.concat(policy_04_verdicts, policy_05_verdicts),
        ),
        array.concat(
          array.concat(policy_06_verdicts, policy_07_verdicts),
          policy_08_verdicts,
        ),
      ),
      array.concat(
        array.concat(policy_09_verdicts, policy_10_verdicts),
        policy_11_verdicts,
      ),
    ),
    policy_12_verdicts,
  ),
  array.concat(policy_13_verdicts, policy_14_verdicts),
)

is_core_id(id) if {
  id in core_ids
}

core_declared(component, cap) if {
  some declared in component.capabilities.declared
  is_core_id(declared.id)
  declared.id == cap.id
  declared.qualifiers == cap.qualifiers
}

observed_extra_core(component, cap) if {
  some observed in component.capabilities.observed
  observed == cap
  is_core_id(observed.id)
  not core_declared(component, observed)
}

has_declared_core(component) if {
  some cap in component.capabilities.declared
  is_core_id(cap.id)
}

has_declared_mcp(component) if {
  some cap in component.capabilities.declared
  startswith(cap.id, "mcp:")
}

component_capability(component, cap) if {
  some declared in component.capabilities.declared
  declared == cap
}

component_capability(component, cap) if {
  some observed in component.capabilities.observed
  observed == cap
}

extension_namespace(id) := ns if {
  parts := split(id, ":")
  count(parts) > 1
  ns := parts[0]
}

is_unknown_extension(id) if {
  not is_core_id(id)
  ns := extension_namespace(id)
  not ns in input.config.extension_allowlist
}
