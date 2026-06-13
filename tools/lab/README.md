# Reeve lab tools

Lab tools support issue #29 demo and CI-lab workflows. They are not part of the shipping CLI and must stay outside `crates/`.

Current tool:

- `aggregate.sh` — reads a directory tree of Reeve AIBOM sidecars and renders a small Markdown summary for demos.
- `test-vps/` — provisions a disposable Ubuntu VPS and validates the
  signed deployment template end-to-end for issue #62.
- `test-mac/` — clones disposable Tart macOS VMs and validates signed
  install + launchd scan paths for issues #99 / #144.
- `test-windows/` — validates Windows Claude Desktop discovery for
  issue #100 before the cloud demo fleet.

Fleet content contract:

- [`docs/demo-archetypes.md`](../../docs/demo-archetypes.md) defines the
  12 required developer and non-developer endpoint archetypes for issue
  #191.

Input contract:

- Files named `*.aibom.json` anywhere below the input directory.
- Symlinked artifacts are skipped.
- Individual AIBOM sidecars over 20 MiB are skipped.
- Existing Reeve AIBOM schema fields only.
- No network access, no database, no secret reads.

Example:

```bash
tools/lab/aggregate.sh schema/examples/fixtures > /tmp/reeve-lab-summary.md
```

Phase 1 VPS validation:

```bash
cd tools/lab/test-vps
less README.md
```

macOS Tart validation:

```bash
cd tools/lab/test-mac
less README.md
```

Windows Claude Desktop validation:

```bash
cd tools/lab/test-windows
less README.md
```
