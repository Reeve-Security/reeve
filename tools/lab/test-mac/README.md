# macOS Tart validation

This lab validates Reeve on disposable macOS VMs created with Tart. It is the
macOS sibling of `tools/lab/test-vps/`: one profile, one clean endpoint, signed
release install, signed surface config, launchd-triggered scan, fetched AIBOM
evidence.

Tracked by #99 / #144.

## One-time setup

Tart runs on Apple Silicon macOS hosts.

```bash
brew install cirruslabs/cli/tart cirruslabs/cli/sshpass gh cosign
tart clone ghcr.io/cirruslabs/macos-tahoe-base:latest reeve-mac-base
tart run reeve-mac-base
```

In another terminal, verify SSH:

```bash
sshpass -p admin ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null admin@$(tart ip reeve-mac-base) "uname -a"
```

Stop the base VM after the check:

```bash
tart stop reeve-mac-base
```

Keep `reeve-mac-base`. The fleet driver clones it for each disposable profile.

## Run

```bash
cd tools/lab/test-mac
./run-mac.sh --list
./run-mac.sh mac-empty v0.2.1
./run-mac.sh all v0.2.1
```

Defaults:

- base VM: `reeve-mac-base`
- SSH user/password: `admin` / `admin`
- evidence root: `private/mac-fleet-<date>/<profile>/`

Overrides:

```bash
TART_BASE_VM=reeve-mac-base ./run-mac.sh mac-engineering-stack v0.2.1
TART_SSH_PASSWORD=custom-password ./run-mac.sh mac-empty v0.2.1
KEEP_TART_VM=1 ./run-mac.sh mac-empty v0.2.1     # inspect failed VM
```

## What this first driver proves

- Tart clone/run/delete lifecycle works on the Mac mini.
- Reeve macOS release archive verifies with cosign.
- Signed `surfaces.yaml` verifies with Reeve.
- `tools/deploy/curl-install/install.sh` installs the macOS launchd template.
- `launchctl kickstart` runs the scan.
- AIBOM evidence is fetched and asserted per profile.
- A rigged `sandbox-exec` profile run asserts denied filesystem/network evidence.
- Profiles with saved approval fixtures run a Mac-native granted-permission
  policy smoke. Profiles with known risky saved approvals also assert a
  `risky-grant` verdict.

## Still required for #144 closure

- Decide whether to keep plain SSH or move to Cirrus CLI artifact collection
  after first green run.
