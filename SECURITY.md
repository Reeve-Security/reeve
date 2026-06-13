# Security Policy

Reeve is a security tool. Scanners are an attack surface, so we take
vulnerability reports seriously.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do **not** open a public
GitHub issue for security reports.

Use GitHub's private vulnerability reporting: open the **Security** tab on
this repository and choose **Report a vulnerability**.

We review security reports as project capacity allows. Fix timing depends on
severity, exploitability, and release risk.

## Supported versions

Security fixes target the latest released version unless a release note says
otherwise.

## Scope

In scope:

- Signature verification bypasses.
- Sandbox escape during capability profiling.
- Policy engine errors that misreport verdicts.
- Supply-chain integrity of Reeve releases and build provenance.
- Filesystem reads beyond documented config paths or profiling boundaries.

Out of scope:

- Runtime enforcement bypass. Reeve reports evidence; it does not enforce at
  runtime.
- Vulnerabilities in scanned MCP servers. Report those to the server authors.
- Issues that require privileged local access beyond a normal developer
  workflow.

## Filesystem read scope

Default scans read AI-agent configuration files and write output to the
selected output directory. They do not execute registered tools unless the
operator passes explicit execution or profiling flags.

Reeve does not read source code, browser state, email, documents, network
shares, secret stores, or SSH private keys as discovery input. When an
operator points `--target` at a shared home parent such as `/Users` or
`C:\Users`, Reeve checks known config paths in each immediate child home.

Opt-in sensitive-data scanning writes a separate redacted report and must not
serialize raw secret values.
