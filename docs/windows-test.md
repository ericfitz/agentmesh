# Windows tests in the local VM (`make windows-test`)

`make windows-test [COMMIT=rev]` runs the Windows checks of a commit (default
`HEAD`) in a dedicated Windows 11 arm64 test VM under VMware Fusion, unattended:
no Fusion window, no copying, no shutdown by hand. Decisions and rationale:
`docs/superpowers/specs/2026-11-15-local-ci-design.md`, section 3.

It is not part of `make verify`. The pre-push hook (`.githooks/pre-push`, when a push touches the Windows path set) and `release/release.sh`'s preflight run it. It has not yet passed a real run: that waits on the VM encryption password in the Keychain, so `.github/workflows/windows.yml` stays as the dispatch-only fallback.

## What it does

1. Resolves `COMMIT` to a full SHA, refuses the source VM, takes the lock (below),
   reads both passwords from the login Keychain.
2. `vmrun revertToSnapshot baseline`, then `start nogui`, then polls
   `checkToolsState` until VMware Tools report `running` (bound: 300 s).
3. Packs `git archive COMMIT` into a zip, copies it and
   `scripts/windows-test/job.ps1` to `C:\amt` in the guest.
4. Runs `job.ps1` as the unelevated guest user `test`. Its 11 steps all run even
   after a failure: `go vet` (default tags, then the four key-provider tags) and
   the unit packages (everything but `internal/conformance`) on arm64 and then
   with `GOARCH=amd64` (x64 under Prism); the parse check of every tracked `.ps1`
   under Windows PowerShell 5.1 and PowerShell 7; the `release\test-install.ps1`
   `-SelfTest`; the install harness under both hosts. The x64 claim covers `go vet`
   and `go test` only: the installer harness still sees an arm64 machine.
5. Copies `results.txt`, `job.out` (UTF-16, converted on the host) and the step
   logs back, prints the summary, powers the VM off and removes the lock.

## One-time setup

The VM is a fresh Windows 11 arm64 install (Eric's decision of 2026-11-15; it is
not a clone of his general-use VM), dedicated to testing: everything in it is
eligible for deletion. The script refuses any `.vmx` inside
`~/Virtual Machines.localized/Windows 11 64-bit Arm.vmwarevm` (the source VM).
Default path:
`~/Virtual Machines.localized/Windows 11 Test VM.vmwarevm/Windows 11 Test VM.vmx`
(`AGENTMESH_WINDOWS_TEST_VMX` overrides it). The guest needs Go, git, Windows
PowerShell 5.1 (built in), PowerShell 7 (`pwsh.exe` on PATH) and VMware Tools, and
a local account `test`. The VM is encrypted, so every `vmrun` call needs `-vp`.

Keychain items (the commands prompt for the value, so nothing is echoed or read
from a file; `-U` makes them update an item that already exists):

```
security add-generic-password -U -s agentmesh-windows-test -a vm-encryption -T /usr/bin/security -w
security add-generic-password -U -s agentmesh-windows-test -a guest-test -T /usr/bin/security -w
```

`vm-encryption` is the VM's encryption password; `guest-test` is the password of
the guest account `test`. Check that a non-interactive read works (exit 0, no
prompt; click "Always Allow" once if one appears):

```
security find-generic-password -s agentmesh-windows-test -a vm-encryption -w >/dev/null
```

vmrun receives the passwords on its command line (`-vp`, `-gp`), so they are
visible to other processes of this Mac while a call runs. The script never prints
or logs them.

## The snapshot

`baseline` is the snapshot every run reverts to. Take it with the VM powered off,
after the guest holds a warm Go module cache and build cache. A run whose results
carry `GOMODCACHE-MISS` (the first module `go.sum` names is not in the guest's
module cache) still passes, only slower, and its summary says
`baseline stale: refresh it (docs/windows-test.md)`.

Refresh `baseline`:

1. Start the VM and log in as `test` (`"$VMRUN" -T fusion -vp ... start <vmx>`, with `VMRUN` as in step 4; with
   the Fusion window if you prefer).
2. In the guest, as `test`, from a current checkout: `go mod download`, then warm
   the build cache: `go vet ./...`, the same with
   `-tags awskms,gcpkms,azurekms,hashivault`, and `go test -run XXX ./...`, each
   for `GOARCH` arm64 and amd64.
3. Power the VM off (`"$VMRUN" stop <vmx> soft`, plus `-vp`).
4. On the Mac:

   ```
   VMRUN="/Applications/VMware Fusion.app/Contents/Library/vmrun"
   VMX="$HOME/Virtual Machines.localized/Windows 11 Test VM.vmwarevm/Windows 11 Test VM.vmx"
   VMPW=$(security find-generic-password -s agentmesh-windows-test -a vm-encryption -w)
   "$VMRUN" -T fusion -vp "$VMPW" deleteSnapshot "$VMX" baseline
   "$VMRUN" -T fusion -vp "$VMPW" snapshot "$VMX" baseline
   ```

`snapshot` and `revertToSnapshot` can fail once with "Cannot read the virtual
machine configuration file"; the script retries a revert once, so do the same by
hand.

## Lock and state directory

State lives in `$AGENTMESH_DEV_STATE`, else
`${XDG_STATE_HOME:-$HOME/.local/state}/agentmesh-dev`:

- `logs/windows-test/<sha>/`: `summary.txt`, `vmrun.log` (redacted calls and
  answers), `src.zip`, `results.txt`, `job.out.txt`, `guest/` (one log per step).
  A run clears its commit's directory first.
- `passes/windows-test/<sha>`: empty file, recorded on exit 0. A run removes its
  commit's earlier record first, so the file always reflects the latest run.
- `windows-test.lock`: `pid start_epoch` of the running script.

Rules: a second run while the lock's PID is alive is refused (exit 2, naming the
PID). The VM running with no lock is refused too (exit 2; stop it with
`vmrun stop "<vmx>" hard`, adding `-vp` for this encrypted VM). A lock whose PID is dead is stale: the next run powers the VM off if it is
running, clears the lock and proceeds. SIGINT and SIGTERM power the VM off and
remove the lock; SIGKILL leaves both, which the next run repairs as above. The
lock is written under a short mutex directory `windows-test.lock.d`; a run killed
with SIGKILL inside that few-millisecond window leaves it and the next run says
which directory to remove.

## Exit codes

- 0: every step passed (the pass is recorded).
- 1: a step failed; the summary names the failed steps and tests.
- 2: usage or a precondition failed: no vmrun, no VM, missing or wrong Keychain
  item or password, source VM path, VM already running, live lock, malformed lock.
- 3: infrastructure failure: Tools never ready, a guest copy failed, the job or a
  vmrun call timed out, the results are incomplete or malformed. The VM is
  powered off and no pass is recorded.

Environment: `AGENTMESH_WINDOWS_TEST_TOOLS_TIMEOUT` (300 s),
`AGENTMESH_WINDOWS_TEST_RUN_TIMEOUT` (2700 s), `AGENTMESH_WINDOWS_TEST_CALL_TIMEOUT`
(120 s), `AGENTMESH_WINDOWS_TEST_POLL_SECONDS` (5), `AGENTMESH_VMRUN`,
`AGENTMESH_SECURITY`, `AGENTMESH_WINDOWS_TEST_VMX`, `AGENTMESH_DEV_STATE`.

## Tests

`make windows-test-selftest` runs the script against a fake `vmrun` and a fake
`security` (`scripts/testdata/windows-test/`); it needs no VM and no Keychain
item. `job.ps1` has no host test: it runs only in the guest.
