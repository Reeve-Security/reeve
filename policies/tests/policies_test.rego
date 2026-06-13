package reeve.policy

import rego.v1

base_input := {
  "aibom": {
    "components": [{
      "bom-ref": "pkg:test/basic@1.0.0",
      "capabilities": {
        "declared": [{
          "id": "fs:read",
          "qualifiers": {},
        }],
        "observed": [{
          "id": "fs:read",
          "qualifiers": {},
        }],
      },
    }],
  },
  "config": {
    "profile": "default",
    "extension_allowlist": ["mcp"],
  },
  "signature": {
    "present": false,
    "verified": false,
  },
}

test_policy_01_noop if {
  verdicts := data.reeve.policy.policy_01_verdicts with input as base_input
  count(verdicts) == 0
}

test_policy_02_noop if {
  verdicts := data.reeve.policy.policy_02_verdicts with input as base_input
  count(verdicts) == 0
}

test_policy_02_denies_verified_subject_outside_allowlist if {
  input_doc := object.union(base_input, {
    "config": object.union(base_input.config, {"publisher_allowlist": ["repo:trusted/publisher:ref:refs/heads/main"]}),
    "signature": {
      "present": true,
      "verified": true,
      "issuer": "https://token.actions.githubusercontent.com",
      "subject": "repo:evil/publisher:ref:refs/heads/main",
    },
  })
  verdicts := data.reeve.policy.policy_02_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "deny"
  verdicts[0].policyId == "publisher-allowlist"
}

test_policy_02_ignores_claimed_cdx_publisher_when_signature_subject_allowed if {
  input_doc := object.union(base_input, {
    "cyclonedx": {"components": [{"bom-ref": "pkg:test/basic@1.0.0", "publisher": "Untrusted Claimed Publisher"}]},
    "config": object.union(base_input.config, {"publisher_allowlist": ["repo:trusted/publisher:ref:refs/heads/main"]}),
    "signature": {
      "present": true,
      "verified": true,
      "issuer": "https://token.actions.githubusercontent.com",
      "subject": "repo:trusted/publisher:ref:refs/heads/main",
    },
  })
  verdicts := data.reeve.policy.policy_02_verdicts with input as input_doc
  count(verdicts) == 0
}

test_policy_03_rule_a_deny if {
  input_doc := {
    "aibom": {
      "components": [{
        "bom-ref": "pkg:test/deny@1.0.0",
        "capabilities": {
          "declared": [{
            "id": "fs:read",
            "qualifiers": {},
          }],
          "observed": [
            {
              "id": "fs:read",
              "qualifiers": {},
            },
            {
              "id": "net:egress",
              "qualifiers": {"host": "api.untrusted.example", "port": 443, "scheme": "https"},
            },
          ],
        },
      }],
    },
    "config": base_input.config,
    "signature": base_input.signature,
  }
  verdicts := data.reeve.policy.policy_03_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "deny"
  verdicts[0].policyId == "declared-observed-capability-match"
}

test_policy_03_rule_b_warn if {
  input_doc := {
    "aibom": {
      "components": [{
        "bom-ref": "pkg:test/warn@1.0.0",
        "capabilities": {
          "declared": [{
            "id": "mcp:tool:call",
            "qualifiers": {"tool_name": "open_page"},
          }],
          "observed": [{
            "id": "exec:subprocess",
            "qualifiers": {"cmd": "env"},
          }],
        },
      }],
    },
    "config": base_input.config,
    "signature": base_input.signature,
  }
  verdicts := data.reeve.policy.policy_03_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "warn"
}

test_policy_04_noop if {
  verdicts := data.reeve.policy.policy_04_verdicts with input as base_input
  count(verdicts) == 0
}

test_policy_05_noop if {
  verdicts := data.reeve.policy.policy_05_verdicts with input as base_input
  count(verdicts) == 0
}

test_policy_05_denies_stale_scan_when_age_limit_configured if {
  input_doc := object.union(base_input, {
    "aibom": object.union(base_input.aibom, {"scan": {"timestamp": "2026-04-20T00:00:00Z"}}),
    "config": object.union(base_input.config, {
      "max_scan_age_seconds": 86400,
      "policy_time": "2026-04-22T00:00:00Z",
    }),
  })
  verdicts := data.reeve.policy.policy_05_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "deny"
  verdicts[0].policyId == "maximum-scan-age"
}

test_policy_06_noop if {
  verdicts := data.reeve.policy.policy_06_verdicts with input as base_input
  count(verdicts) == 0
}

test_policy_07_noop if {
  verdicts := data.reeve.policy.policy_07_verdicts with input as base_input
  count(verdicts) == 0
}

test_policy_08_noop if {
  verdicts := data.reeve.policy.policy_08_verdicts with input as base_input
  count(verdicts) == 0
}

test_policy_08_allows_delimited_trusted_package_source if {
  input_doc := object.union(base_input, {
    "aibom": object.union(base_input.aibom, {"components": [object.union(base_input.aibom.components[0], {"bom-ref": "pkg:npm/%40scope/tool@1.0.0"})]}),
    "config": object.union(base_input.config, {"trusted_package_sources": ["pkg:npm"]}),
  })
  verdicts := data.reeve.policy.policy_08_verdicts with input as input_doc
  count(verdicts) == 0
}

test_policy_08_denies_untrusted_package_source if {
  input_doc := object.union(base_input, {
    "aibom": object.union(base_input.aibom, {"components": [object.union(base_input.aibom.components[0], {"bom-ref": "pkg:github/evil/tool@1.0.0"})]}),
    "config": object.union(base_input.config, {"trusted_package_sources": ["pkg:npm"]}),
  })
  verdicts := data.reeve.policy.policy_08_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "deny"
  verdicts[0].policyId == "trusted-package-source"
}

test_policy_08_denies_prefix_spoofed_package_source if {
  input_doc := object.union(base_input, {
    "aibom": object.union(base_input.aibom, {"components": [object.union(base_input.aibom.components[0], {"bom-ref": "pkg:npm-malicious/evil@1.0.0"})]}),
    "config": object.union(base_input.config, {"trusted_package_sources": ["pkg:npm"]}),
  })
  verdicts := data.reeve.policy.policy_08_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "deny"
  verdicts[0].policyId == "trusted-package-source"
}

test_policy_09_noop if {
  verdicts := data.reeve.policy.policy_09_verdicts with input as base_input
  count(verdicts) == 0
}

test_policy_09_denies_version_below_configured_floor if {
  input_doc := object.union(base_input, {
    "aibom": object.union(base_input.aibom, {"components": [object.union(base_input.aibom.components[0], {"bom-ref": "pkg:npm/%40modelcontextprotocol/server-filesystem@2.2.0"})]}),
    "config": object.union(base_input.config, {"minimum_package_versions": {"pkg:npm/%40modelcontextprotocol/server-filesystem": "2.3.1"}}),
  })
  verdicts := data.reeve.policy.policy_09_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "deny"
  verdicts[0].policyId == "no-version-downgrade"
}

test_policy_10_noop if {
  verdicts := data.reeve.policy.policy_10_verdicts with input as base_input
  count(verdicts) == 0
}

test_policy_10_warns_unsigned_mcp_in_default_profile if {
  input_doc := mcp_registration_input("default", "pkg:npm/%40modelcontextprotocol/server-filesystem")
  verdicts := data.reeve.policy.policy_10_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "warn"
  verdicts[0].policyId == "unsigned-mcp-registration"
}

test_policy_10_denies_unsigned_mcp_in_strict_profile if {
  input_doc := mcp_registration_input("strict", "pkg:npm/%40modelcontextprotocol/server-filesystem")
  verdicts := data.reeve.policy.policy_10_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "deny"
  verdicts[0].policyId == "no-unsigned-mcp-strict"
}

test_policy_11_warns_unknown_extension if {
  input_doc := {
    "aibom": {
      "components": [{
        "bom-ref": "pkg:test/ext@1.0.0",
        "capabilities": {
          "declared": [{
            "id": "com.example.product:custom-op",
            "qualifiers": {"mode": "enhanced"},
          }],
          "observed": [{
            "id": "com.example.product:custom-op",
            "qualifiers": {"mode": "enhanced"},
          }],
        },
      }],
    },
    "config": base_input.config,
    "signature": base_input.signature,
  }
  verdicts := data.reeve.policy.policy_11_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "warn"
}

test_policy_12_noop_for_ordinary_grant if {
  input_doc := granted_input([{
    "id": "fs:read",
    "qualifiers": {"path": "/Users/alice/projects"},
    "source": "granted",
  }])
  verdicts := data.reeve.policy.policy_12_verdicts with input as input_doc
  count(verdicts) == 0
}

test_policy_12_warns_destructive_command_grant if {
  input_doc := granted_input([{
    "id": "exec:subprocess",
    "qualifiers": {"cmd": "rm", "argCount": 3},
    "source": "granted",
  }])
  verdicts := data.reeve.policy.policy_12_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "warn"
  verdicts[0].policyId == "risky-grant"
}

test_policy_12_warns_wildcard_subprocess_grant if {
  input_doc := granted_input([{
    "id": "exec:subprocess",
    "qualifiers": {"cmd": "*", "argCount": 0},
    "source": "granted",
  }])
  verdicts := data.reeve.policy.policy_12_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "warn"
  verdicts[0].policyId == "risky-grant"
}

test_policy_12_denies_elevation_grant if {
  input_doc := granted_input([{
    "id": "exec:subprocess",
    "qualifiers": {"cmd": "sudo", "argCount": 2},
    "source": "granted",
  }])
  verdicts := data.reeve.policy.policy_12_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "deny"
  verdicts[0].policyId == "risky-grant"
}

test_policy_12_warns_broad_write_grant_without_flagging_user_path if {
  allowed_input := granted_input([{
    "id": "fs:write",
    "qualifiers": {"path": "/Users/alice/projects"},
    "source": "granted",
  }])
  allowed_verdicts := data.reeve.policy.policy_12_verdicts with input as allowed_input
  count(allowed_verdicts) == 0

  broad_input := granted_input([{
    "id": "fs:write",
    "qualifiers": {"path": "/etc/ssh"},
    "source": "granted",
  }])
  broad_verdicts := data.reeve.policy.policy_12_verdicts with input as broad_input
  count(broad_verdicts) == 1
  broad_verdicts[0].status == "warn"
}

test_policy_12_warns_windows_home_broad_write_grant if {
  input_doc := granted_input([{
    "id": "fs:write",
    "qualifiers": {"path": "C:\\Users\\alice"},
    "source": "granted",
  }])
  verdicts := data.reeve.policy.policy_12_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "warn"
}

test_policy_12_warns_broad_filesystem_mcp_registration_root if {
  input_doc := mcp_filesystem_root_input("C:\\Users\\alice")
  verdicts := data.reeve.policy.policy_12_verdicts with input as input_doc
  count(verdicts) == 2
  statuses := {verdict.status | some verdict in verdicts}
  statuses == {"warn"}
}

test_policy_12_denies_exact_secret_path_grant if {
  input_doc := granted_input([{
    "id": "fs:read",
    "qualifiers": {"path": "/etc/shadow"},
    "source": "granted",
  }])
  verdicts := data.reeve.policy.policy_12_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "deny"
}

test_policy_12_warns_secret_substring_grant if {
  input_doc := granted_input([{
    "id": "fs:read",
    "qualifiers": {"path": "/Users/alice/.ssh/id_ed25519"},
    "source": "granted",
  }])
  verdicts := data.reeve.policy.policy_12_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "warn"
}

test_policy_12_warns_windows_secret_path_grant if {
  input_doc := granted_input([{
    "id": "fs:read",
    "qualifiers": {"path": "C:\\Users\\alice\\AppData\\Roaming\\Claude\\.credentials.json"},
    "source": "granted",
  }])
  verdicts := data.reeve.policy.policy_12_verdicts with input as input_doc
  count(verdicts) == 1
  verdicts[0].status == "warn"
}

test_policy_13_noop_under_sensitive_data_thresholds if {
  verdicts := data.reeve.policy.policy_13_verdicts with input as sensitive_input({
    "surfaces": [{
      "surface": "claude-desktop",
      "fileCount": 2,
      "totalBytes": 2048,
    }],
    "findings": [],
    "inputs": {"contentPatternScan": false, "rulePacks": []},
  }, {
    "sensitive_data_max_file_count": 10,
    "sensitive_data_max_total_bytes": 4096,
  })
  count(verdicts) == 0
}

test_policy_13_warns_sensitive_data_file_count_threshold if {
  verdicts := data.reeve.policy.policy_13_verdicts with input as sensitive_input({
    "surfaces": [{
      "surface": "claude-desktop",
      "fileCount": 11,
      "totalBytes": 2048,
    }],
    "findings": [],
    "inputs": {"contentPatternScan": false, "rulePacks": []},
  }, {
    "sensitive_data_max_file_count": 10,
    "sensitive_data_max_total_bytes": 4096,
  })
  count(verdicts) == 1
  verdicts[0].status == "warn"
  verdicts[0].policyId == "sensitive-data-volume"
}

test_policy_13_warns_sensitive_data_total_bytes_threshold if {
  verdicts := data.reeve.policy.policy_13_verdicts with input as sensitive_input({
    "surfaces": [{
      "surface": "claude-desktop",
      "fileCount": 2,
      "totalBytes": 4097,
    }],
    "findings": [],
    "inputs": {"contentPatternScan": false, "rulePacks": []},
  }, {
    "sensitive_data_max_file_count": 10,
    "sensitive_data_max_total_bytes": 4096,
  })
  count(verdicts) == 1
  verdicts[0].status == "warn"
  verdicts[0].policyId == "sensitive-data-volume"
}

test_policy_14_noop_for_clean_sensitive_data_report if {
  verdicts := data.reeve.policy.policy_14_verdicts with input as sensitive_input({
    "surfaces": [{
      "surface": "claude-desktop",
      "fileCount": 2,
      "totalBytes": 2048,
    }],
    "findings": [],
    "inputs": {"contentPatternScan": true, "rulePacks": [{"id": "reeve-default-conversation-secrets"}]},
  }, {})
  count(verdicts) == 0
}

test_policy_14_warns_unsuppressed_secret_pattern_finding if {
  verdicts := data.reeve.policy.policy_14_verdicts with input as sensitive_input({
    "surfaces": [],
    "findings": [{
      "patternClass": "aws-access-key",
      "suppressed": false,
    }],
    "inputs": {"contentPatternScan": true, "rulePacks": [{"id": "reeve-default-conversation-secrets"}]},
  }, {})
  count(verdicts) == 1
  verdicts[0].status == "warn"
  verdicts[0].policyId == "sensitive-secret-pattern"
  contains(verdicts[0].justification, "needs human review")
}

test_policy_14_ignores_suppressed_secret_pattern_finding if {
  verdicts := data.reeve.policy.policy_14_verdicts with input as sensitive_input({
    "surfaces": [],
    "findings": [{
      "patternClass": "aws-access-key",
      "suppressed": true,
      "suppressionId": "known-test-key",
    }],
    "inputs": {"contentPatternScan": true, "rulePacks": [{"id": "reeve-default-conversation-secrets"}]},
  }, {})
  count(verdicts) == 0
}

test_policy_14_denies_malformed_pattern_scan_without_rule_pack if {
  verdicts := data.reeve.policy.policy_14_verdicts with input as sensitive_input({
    "surfaces": [],
    "findings": [],
    "inputs": {"contentPatternScan": true, "rulePacks": []},
  }, {})
  count(verdicts) == 1
  verdicts[0].status == "deny"
  verdicts[0].policyId == "sensitive-secret-pattern"
}

test_sensitive_report_input_does_not_run_aibom_publisher_policy if {
  input_doc := sensitive_input({
    "surfaces": [],
    "findings": [],
    "inputs": {"contentPatternScan": false, "rulePacks": []},
  }, {
    "publisher_allowlist": ["repo:trusted/publisher:ref:refs/heads/main"],
  })
  verdicts := data.reeve.policy.verdicts with input as input_doc
  count(verdicts) == 0
}

granted_input(grants) := object.union(base_input, {
  "aibom": object.union(base_input.aibom, {"components": [{
    "bom-ref": "pkg:test/granted@1.0.0",
    "capabilities": {
      "declared": [{
        "id": "fs:read",
        "qualifiers": {},
      }],
      "observed": [{
        "id": "fs:read",
        "qualifiers": {},
      }],
      "granted": grants,
    },
  }]}),
})

mcp_registration_input(profile, bom_ref) := {
  "aibom": object.union(base_input.aibom, {"components": [{
    "bom-ref": bom_ref,
    "capabilities": {
      "declared": [{
        "id": "mcp:modelcontextprotocolserver-filesystem",
        "qualifiers": {},
      }],
      "observed": [],
    },
  }]}),
  "config": object.union(base_input.config, {"profile": profile}),
  "signature": base_input.signature,
}

mcp_filesystem_root_input(path) := {
  "aibom": object.union(base_input.aibom, {"components": [{
    "bom-ref": "pkg:npm/%40modelcontextprotocol/server-filesystem",
    "capabilities": {
      "declared": [
        {
          "id": "mcp:modelcontextprotocolserver-filesystem",
          "qualifiers": {},
        },
        {
          "id": "fs:read",
          "qualifiers": {"path": path},
        },
        {
          "id": "fs:write",
          "qualifiers": {"path": path},
        },
      ],
      "observed": [],
      "granted": [],
    },
  }]}),
  "config": base_input.config,
  "signature": base_input.signature,
}

sensitive_input(report, config) := {
  "sensitiveDataReport": report,
  "config": object.union(base_input.config, config),
}
