# Reeve Demo

`make demo` runs the default offline demo from a clean checkout.

The demo:

- builds `aibom-cli`
- creates a local fixture target under `target/reeve-demo/target`
- scans seeded MCP and approval-state configs without executing MCP servers
- runs policy evaluation
- validates the generated AIBOM triplet
- verifies the fixture bundle structurally
- prints a short inventory, grant, policy, and declared-vs-observed delta summary

The default demo does not use the network and does not require `cosign`.
It uses `--sign-mode fixture`, matching the release-readiness runner.
Real Fulcio/Rekor proof is covered by the live Sigstore acceptance workflow,
not by this offline demo.

Run:

```bash
make demo
```

Outputs land in `target/reeve-demo/`.
