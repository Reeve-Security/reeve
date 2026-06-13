# Windows Claude Desktop validation

This lab validates issue #100 before any cloud demo recording. It proves Reeve can see the Windows Claude Desktop MCP config at:

```text
%APPDATA%\Claude\claude_desktop_config.json
```

No exploit payloads, customer data, or real secrets belong in this lab.

## No-VM proof

The CLI regression test `scan_windows_claude_desktop_config_produces_registration_evidence` creates a Windows-shaped profile under a temp target and runs:

```bash
cargo test -p aibom-cli --test cli_e2e scan_windows_claude_desktop_config_produces_registration_evidence
```

Pass means:

- `AppData/Roaming/Claude/claude_desktop_config.json` is discovered.
- The AIBOM has one component for the configured MCP server.
- Evidence kind is `mcp-registration`, not `mcp-tools-list`.
- Evidence reference points at the Windows Claude Desktop AppData config.

## Real Windows smoke

Use this after a Windows VM exists. A cheap short-lived Azure VM is enough.

1. Install or copy a Reeve Windows binary onto the VM.
2. Create a benign Claude Desktop config:

   ```powershell
   New-Item -ItemType Directory -Force "$env:APPDATA\Claude" | Out-Null
   @'
   {
     "mcpServers": {
       "win-filesystem": {
         "command": "npx",
         "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\Public\\Documents"]
       }
     }
   }
   '@ | Set-Content -Encoding utf8 "$env:APPDATA\Claude\claude_desktop_config.json"
   ```

3. Run a default scan:

   ```powershell
   .\aibom-cli.exe scan --no-system-config --target "$env:USERPROFILE" --output-dir .\out --sign-mode fixture
   ```

4. Inspect the AIBOM:

   ```powershell
   Select-String -Path .\out\*.aibom.json -Pattern "Claude","claude_desktop_config.json","mcp-registration"
   ```

Pass means the real VM produces the same evidence shape as the no-VM test. Keep `--introspect-execute` off for default demo scans unless the recording explicitly shows the consent step.
