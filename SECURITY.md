# Security Policy

Reeve is a security tool. Its thesis is that scanners themselves are
an attack surface — so we take the integrity of this project
seriously.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a
public GitHub issue for security reports.

Preferred channel: security@reeseskye.io.

We acknowledge reports within three business days and aim to publish
a fix or mitigation within 90 days of receipt.

## Supported versions

Pre-1.0. Each minor version (`0.N`) is supported until the next minor
release. Once Reeve reaches 1.0, formal long-term-support windows
will be published.

## Scope

**In scope:**

- Signature verification bypass (Sigstore, Rekor, package-registry
  hash checks).
- Sandbox escape in the capability-profiling stage (Landlock,
  seccomp, `sandbox-exec`).
- Policy engine logic errors that cause verdicts to be misreported.
- Supply-chain integrity of the Reeve distribution itself (release
  binary signatures, source tarball hashes, build provenance).
- Filesystem read-scope expansion beyond documented MCP config paths
  or sandbox profiling boundaries.

**Out of scope for v1:**

- Runtime enforcement bypass. v1 reports only; enforcement is a
  deferred design goal.
- Vulnerabilities in scanned MCP servers themselves. Those belong to
  the server's authors — report them there.
- Issues that require privileged local access beyond what a normal
  developer workflow provides.

## Filesystem read scope

Reeve's v0.1 filesystem read contract is documented in
[`docs/scope.md`](docs/scope.md). In short, the scanner reads only the
built-in MCP configuration paths listed there, relative to the scan
target root, plus bounded workspace searches for the documented MCP
config filenames. Those workspace searches may enumerate directory
metadata below the target root up to documented depth limits; they do
not read arbitrary file contents. Reeve does not read source code,
browser state, email, documents, network shares, secret stores, cloud
credential files, SSH private keys, or other users' home directories as
discovery input.

Capability profiling is a separate stage. When enabled, local stdio
MCP servers run under the documented sandbox boundary: macOS uses
`sandbox-exec` default-deny rules with denied-action logging, while
Linux currently records an observational strace fallback per ADR-0009.
Sandbox escape or misreported observed behavior remains in scope.

A malicious PR that adds a new adapter path, broadens a glob, or adds a
workspace walk without updating the public contract should be caught in
review and CI. `scripts/check-scope-docs.py` compares the Rust MCP
`SurfaceSpec` registry against `docs/scope.md`; CI fails if a surface,
path, glob, workspace-search filename, max depth, or parser root is not
documented.

## Coordinated disclosure

We credit reporters in the release notes unless anonymity is
requested.
