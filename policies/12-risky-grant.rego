package reeve.policy

import rego.v1

# Policy #12 — risky-grant
#
# Flags granted permissions that match high-risk patterns:
#  - destructive commands (rm, dd, mkfs, etc.)
#  - elevation primitives (sudo, runas, osascript)
#  - wildcard subprocess approvals from agent-level "skip prompts" config
#  - pipe-capable download commands (curl, wget)
#  - broad filesystem write grants (/etc, /, /usr, Windows drive/user roots)
#  - broad filesystem MCP registration roots
#  - secret-path access (~/.ssh, ~/.aws, /etc/passwd, etc.)

risky_destructive_commands := {"rm", "dd", "mkfs", "format", "shred", "wipefs", "fdisk"}

risky_elevation_commands := {"sudo", "runas", "osascript", "pkexec", "doas"}

risky_pipe_commands := {"curl", "wget"}

risky_wildcard_commands := {"*", "all"}

risky_broad_write_prefixes := {"/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/boot"}

risky_secret_paths := {
  "/etc/passwd",
  "/etc/shadow",
  "/etc/master.passwd",
  "/etc/sudoers",
  "/private/etc/passwd",
  "/private/etc/shadow",
  "/private/etc/master.passwd",
  "/private/etc/sudoers",
}

risky_secret_path_substrings := [
  "/.ssh/",
  "/.aws/",
  "/.gcp/",
  "/.azure/",
  "/.config/gcloud/",
  "/.kube/",
  "/.docker/",
  "/id_rsa",
  "/id_ed25519",
  "/id_ecdsa",
  "credentials",
  "secret",
  "token",
]

risky_windows_secret_path_substrings := [
  "\\.ssh\\",
  "\\.aws\\",
  "\\.gcp\\",
  "\\.azure\\",
  "\\.kube\\",
  "\\.docker\\",
  "\\appdata\\roaming\\claude\\",
  "\\appdata\\local\\claude\\",
  "\\id_rsa",
  "\\id_ed25519",
  "\\id_ecdsa",
  "credentials",
  "secret",
  "token",
]

# ── rule A: destructive command grant ───────────────────────────────────

policy_12_rule_a_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  some j
  grant := component.capabilities.granted[j]
  grant.id == "exec:subprocess"
  grant.qualifiers.cmd in risky_destructive_commands
  verdict := {
    "id": sprintf("policy-12-rule-a-%03d-%03d", [i, j]),
    "policyId": "risky-grant",
    "bomRef": component["bom-ref"],
    "status": "warn",
    "justification": sprintf(
      "Granted destructive command %s for %s",
      [grant.qualifiers.cmd, component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/granted/%d", [i, j]),
    ],
  }
]

# ── rule B: elevation primitive grant ───────────────────────────────────

policy_12_rule_b_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  some j
  grant := component.capabilities.granted[j]
  grant.id == "exec:subprocess"
  grant.qualifiers.cmd in risky_elevation_commands
  verdict := {
    "id": sprintf("policy-12-rule-b-%03d-%03d", [i, j]),
    "policyId": "risky-grant",
    "bomRef": component["bom-ref"],
    "status": "deny",
    "justification": sprintf(
      "Granted elevation primitive %s for %s",
      [grant.qualifiers.cmd, component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/granted/%d", [i, j]),
    ],
  }
]

# ── rule C: install-pipe grant (curl | sh style) ────────────────────────

policy_12_rule_c_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  some j
  grant := component.capabilities.granted[j]
  grant.id == "exec:subprocess"
  grant.qualifiers.cmd in risky_pipe_commands
  verdict := {
    "id": sprintf("policy-12-rule-c-%03d-%03d", [i, j]),
    "policyId": "risky-grant",
    "bomRef": component["bom-ref"],
    "status": "warn",
    "justification": sprintf(
      "Granted pipe-capable download command %s for %s",
      [grant.qualifiers.cmd, component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/granted/%d", [i, j]),
    ],
  }
]

# ── rule C2: wildcard subprocess approval ──────────────────────────────

policy_12_rule_c2_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  some j
  grant := component.capabilities.granted[j]
  grant.id == "exec:subprocess"
  grant.qualifiers.cmd in risky_wildcard_commands
  verdict := {
    "id": sprintf("policy-12-rule-c2-%03d-%03d", [i, j]),
    "policyId": "risky-grant",
    "bomRef": component["bom-ref"],
    "status": "warn",
    "justification": sprintf(
      "Granted wildcard subprocess approval for %s",
      [component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/granted/%d", [i, j]),
    ],
  }
]

# ── rule D: broad filesystem write grant ────────────────────────────────

policy_12_rule_d_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  some j
  grant := component.capabilities.granted[j]
  grant.id == "fs:write"
  broad_filesystem_path(grant.qualifiers.path)
  verdict := {
    "id": sprintf("policy-12-rule-d-%03d-%03d", [i, j]),
    "policyId": "risky-grant",
    "bomRef": component["bom-ref"],
    "status": "warn",
    "justification": sprintf(
      "Granted broad filesystem write access to %s for %s",
      [grant.qualifiers.path, component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/granted/%d", [i, j]),
    ],
  }
]

broad_filesystem_path(path) if {
  broad_prefix := risky_broad_write_prefixes[_]
  broad_path_match(path, broad_prefix)
  path != "/tmp"
}

broad_filesystem_path(path) if {
  posix_user_home_root(path)
}

broad_filesystem_path(path) if {
  windows_drive_root(path)
}

broad_filesystem_path(path) if {
  windows_user_home_root(path)
}

broad_filesystem_path(path) if {
  lower(path) == "%userprofile%"
}

broad_path_match(path, prefix) if {
  path == prefix
}

broad_path_match(path, prefix) if {
  prefix != "/"
  startswith(path, sprintf("%s/", [prefix]))
}

posix_user_home_root(path) if {
  regex.match("^/(Users|home)/[^/]+/?$", path)
}

windows_drive_root(path) if {
  regex.match("^[A-Za-z]:[\\\\/]*$", path)
}

windows_user_home_root(path) if {
  regex.match("^[A-Za-z]:[\\\\/]Users[\\\\/][^\\\\/]+[\\\\/]*$", path)
}

# ── rule E: secret-path access grant ────────────────────────────────────

policy_12_rule_e_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  some j
  grant := component.capabilities.granted[j]
  grant.id in {"fs:read", "fs:write"}
  grant.qualifiers.path in risky_secret_paths
  verdict := {
    "id": sprintf("policy-12-rule-e-%03d-%03d", [i, j]),
    "policyId": "risky-grant",
    "bomRef": component["bom-ref"],
    "status": "deny",
    "justification": sprintf(
      "Granted access to sensitive path %s for %s",
      [grant.qualifiers.path, component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/granted/%d", [i, j]),
    ],
  }
]

policy_12_rule_e_verdicts_substring := [verdict |
  some i
  component := input.aibom.components[i]
  some j
  grant := component.capabilities.granted[j]
  grant.id in {"fs:read", "fs:write"}
  secret_like_path(grant.qualifiers.path)
  verdict := {
    "id": sprintf("policy-12-rule-e-%03d-%03d-sub", [i, j]),
    "policyId": "risky-grant",
    "bomRef": component["bom-ref"],
    "status": "warn",
    "justification": sprintf(
      "Granted access to secret-like path %s for %s",
      [grant.qualifiers.path, component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/granted/%d", [i, j]),
    ],
  }
]

secret_like_path(path) if {
  some sub in risky_secret_path_substrings
  contains(path, sub)
}

secret_like_path(path) if {
  normalized := windows_path_normalized(path)
  some sub in risky_windows_secret_path_substrings
  contains(normalized, sub)
}

windows_path_normalized(path) := lower(replace(path, "/", "\\"))

# ── rule F: broad filesystem MCP registration root ──────────────────────

policy_12_rule_f_verdicts := [verdict |
  some i
  component := input.aibom.components[i]
  has_declared_mcp(component)
  some j
  cap := component.capabilities.declared[j]
  cap.id in {"fs:read", "fs:write"}
  broad_filesystem_path(cap.qualifiers.path)
  verdict := {
    "id": sprintf("policy-12-rule-f-%03d-%03d", [i, j]),
    "policyId": "risky-grant",
    "bomRef": component["bom-ref"],
    "status": "warn",
    "justification": sprintf(
      "Registered filesystem MCP exposes broad path %s for %s",
      [cap.qualifiers.path, component["bom-ref"]],
    ),
    "references": [
      sprintf("/aibom/components/%d/capabilities/declared/%d", [i, j]),
    ],
  }
]

policy_12_verdicts := array.concat(
  array.concat(
    array.concat(
      array.concat(
        policy_12_rule_a_verdicts,
        policy_12_rule_b_verdicts,
      ),
      array.concat(
        policy_12_rule_c_verdicts,
        policy_12_rule_c2_verdicts,
      ),
    ),
    policy_12_rule_d_verdicts,
  ),
  array.concat(
    array.concat(
      policy_12_rule_e_verdicts,
      policy_12_rule_e_verdicts_substring,
    ),
    policy_12_rule_f_verdicts,
  ),
)
