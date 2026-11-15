# Local CI: GitHub Actions spend to near zero

Date: 2026-11-15. Status: approved by Eric 2026-11-15 (all controller calls ratified).

## Intent

One person works on agentmesh from one machine. Cloud CI repeats on GitHub's
paid runners what `make verify` already proves locally, so it buys nothing. The
GitHub usage report of 2026-11-14 (Google Doc "GitHub Usage & Cost Reduction
Report") measured about $26 of Actions spend from Nov 1 to 14, about 94% of it
agentmesh `ci.yml` and `windows.yml`, on a pace of about $55 a month. The
largest single job, `gates-selftest`, took 57.6 minutes a run on average.

Goal (Eric): GitHub costs as near zero as possible. Do locally whatever can be
done locally. Release checks run at releases, not on every build.

## Goals, non-goals, anti-goals

- Goals: no paid runner minutes outside a release; every check that ran in
  cloud CI still runs somewhere, locally, at a defined moment; the Windows
  tests run on the local VM unattended; the gate-script selftest gets faster.
- Non-goals: changing what `make verify` proves; changing `release-build.yml`
  (it runs once per release on GitHub's runners for signing and provenance
  attestations, and is dispatched by `release/release.sh`).
- Anti-goals: a check that silently stops running; a VM that must run around the
  clock; a push hook that demands manual steps (starting Fusion, logging in,
  copying files).

## Decisions

Eric's decisions (2026-11-15), recorded here as human-made:

1. Cloud CI does not run on push. Release checks run only at release.
2. The Windows tests run locally on the Windows 11 arm64 VM in VMware Fusion,
   fully automated (approach A below): no manual start, interaction, copying
   or shutdown, and the VM is not kept running.
3. The slow local checks run from a git pre-push hook, only when the push
   touches files that matter to them (option A of three: per-push always, or
   release-only, were the others).
4. Linux test coverage: a Linux container target runs at release and from the
   pre-push hook when Linux-specific files change.
5. `gates-selftest` is not in the CI path or the release path: it runs as its
   own pre-push hook whenever a gate is modified. "Gate" means the gate
   scripts only (option A of three), not the product files its blocks mutate:
   a moved mutation anchor surfaces at the next gate change.
6. The existing Windows VM is Eric's general-use VM. Testing uses a full clone
   of it, dedicated to testing; the clone is stripped of everything not needed
   (non-standard applications, files): everything in the clone is eligible for
   deletion.
7. Windows and Linux test runs are, in practice, release-only for
   platform-neutral code (with the starting path sets, 2 and 9 of the last 150
   commits would have triggered them). Accepted.

## Approaches considered for the Windows run

- **A. `vmrun` drives the whole run (chosen).** Fusion's `vmrun` starts the VM
  headless (`nogui`), reverts and takes snapshots, copies files between host
  and guest and runs programs in the guest through VMware Tools, and takes the
  encryption password (`-vp`) of this encrypted (TPM) VM. One tool already
  installed, nothing resident.
- **B. `vmrun` for lifecycle, OpenSSH for the work.** Live output, but a
  dedicated SSH key and an SSH server in the guest to maintain; Eric's own SSH
  keys are Touch ID-gated, unsuitable for unattended runs. Kept as the fallback
  if approach A's guest operations fail on this VM (see Task 4 spike).
- **C. GitHub self-hosted runner in the VM.** Keeps a GitHub dependency and a
  runner registration to maintain, against the goal.
- UTM was considered: it holds only a macOS VM today, so it would mean
  building a new Windows guest. Not used.

## Current state (measured 2026-11-15)

- `ci.yml`: on push to main, pull_request and workflow_dispatch; 11 Linux jobs
  (verify, verify-testcontainers, gate-negative, gate-negative-no-docker,
  gates-selftest, signing-key-tags, release-check, release-install-check,
  release-lint, m9-exit-selftest, docker-smoke); no concurrency block, no path
  filter.
- `windows.yml`: on push to main and dispatch; `go vet` (default and the four
  key-provider tags), the unit packages and the `install.ps1` harness on
  windows-latest and windows-11-arm.
- `gates-selftest` (Nov 12 CI log, 90 min, 104 blocks): block
  `m7-deps-rule-fires` took 35.6 min, because it plants about 45 probes and
  reruns the whole `scripts/m7-exit-checks.sh --deps-only` after each; that
  script runs `go list -deps` once per package (hundreds of `go` invocations)
  and takes 38 s on this Mac, inside every `make verify` too. Six blocks rerun
  all of `make check-gates` per mutation (about 25 min together). The CATS
  blocks take about 7 min; the other ~90 blocks 7 to 30 s each.
- Eric's VM (source of the clone; never driven by the scripts):
  `~/Virtual Machines.localized/Windows 11 64-bit Arm.vmwarevm`, guest
  `arm-windows11-64`, 2 vCPUs, 8 GiB, NAT, encrypted (vmrun refuses without
  the password), no snapshots known (listing needs the password). Host: 14
  cores, 64 GiB.
- The in-flight branch `adr-0019-spec-1` edits `ci.yml`, `CLAUDE.md`,
  `Makefile`, `scripts/m4-exit-checks.sh` and `scripts/m7-exit-checks.sh`.

## Design

### 1. Cloud workflows (lands on main first)

- `ci.yml`: triggers become `workflow_dispatch` only. The jobs stay as they
  are, so a clean-room run is one dispatch away and costs nothing unused.
- `windows.yml`: triggers become `workflow_dispatch` only. It is deleted in
  the last task, once `make windows-test` has passed a real run; until then it
  is the fallback.
- `release-build.yml`, `publish-image.yml`: unchanged.
- Project `CLAUDE.md` done rule, interim wording in the same commit: work is
  done when `make verify` passes locally on the final commit (CI workflows are
  dispatch-only; Eric 2026-11-15). Final wording in the last task names the
  hook-run checks.
- `docs/release.md`, the Makefile help strings ("its own CI job") and
  `scripts/m9-exit-checks.sh` line 288 (its workflow list) follow the change.
  `release-lint` keeps running `actionlint` over the workflow files.

### 2. Faster import-rule scripts

- `scripts/m7-exit-checks.sh` computes its import data with one `go list`
  call per (tag set, GOOS) pair, for example `go list -deps -json` or `-f`
  over the patterns, and evaluates every rule from that data in the script.
  Same rules, same `[rule NAME]` violation lines, same exit codes (0 ok, 1
  violation, 2 a `go list` failure or an unresolvable import).
- Time m4, m5, m6, m8 and m10 `--deps-only` and apply the same change to any
  that takes more than a few seconds.
- Acceptance (measured, not estimated): `m7-exit-checks.sh --deps-only` under
  5 s on this Mac, and the selftest's `m7-deps-rule-fires` block under 3 min.
  The existing selftest blocks 22 and the others that probe these scripts must
  still pass unchanged in their expectations.
- `gates-selftest` keeps its full assertion vector (every mutation still
  reruns all six `check-gates` checks): Decision 5 removes it from every
  frequent path, so the per-push cost no longer matters.
- Base: this lands after `adr-0019-spec-1` merges to main, or on that branch,
  because the branch edits the same scripts. The plan states which.

### 3. `make windows-test` (approach A)

A script, `scripts/windows-test.sh [COMMIT]` (default HEAD), run by
`make windows-test`:

1. Resolve the test clone's path (never Eric's source VM; the script refuses
   a path equal to it), the VM encryption password and the guest account
   password. Passwords come from the macOS Keychain
   (`security find-generic-password -s <service> -w`), never from a file in
   the repository or `~/.keys`; service names are the builder's to choose and
   are documented. Missing Fusion, VM or Keychain entry: fail fast, naming it.
2. Refuse to start if the VM is already running (`vmrun list`), naming how to
   stop it, unless that VM was started by a previous run of this script (a
   lock file under the data dir records the PID and start time); a stale lock
   from a dead run is cleared.
3. `revertToSnapshot` to the baseline snapshot (name documented), `start
   nogui`, wait for VMware Tools (`checkToolsState` reaches running) with a
   bounded timeout.
4. `git archive COMMIT` to a zip, copy it into the guest, unpack.
5. Run, in PowerShell through `runProgramInGuest`, with all output to a file
   in the guest: `go vet ./...`, `go vet` with the four key-provider tags,
   the unit packages (everything except `internal/conformance`, as
   `windows.yml` does) natively on arm64, then the same `go vet` and unit
   packages with `GOARCH=amd64` (x64 under Prism), then everything
   `windows.yml` runs for PowerShell: the parse check of every `.ps1`, the
   harness `-SelfTest`, and the `install.ps1` harness under both Windows
   PowerShell 5.1 and PowerShell 7 (so the clone carries PowerShell 7). The
   x64 claim covers `go vet` and `go test` only: the installer harness still
   sees an arm64 machine.
6. Copy the result files back to `<scratch or data dir>/windows-test/<commit>/`,
   print a summary on stdout (steps run, passed, failed, names of failed tests),
   exit 0 only when every step passed.
7. Always (trap): power off (`stop hard`; the next run reverts anyway) and
   remove the lock.

The guest's Go version must satisfy go.mod's `toolchain`; with
`GOTOOLCHAIN=auto` (the default) a newer pin downloads in the guest. Module
downloads happen inside the run unless the baseline snapshot carries a warm
module cache; the builder decides after the spike, aiming for a run under 15 min.

State (Definition of Done D): a second run after success starts from the
snapshot again; two overlapping runs are refused by the lock and the
already-running check; a killed run leaves the VM running and a stale lock,
which the next run detects (dead PID), powers off and clears.

Harness tests (Definition of Done C): `scripts/windows-test-selftest.sh` runs
the script against a fake `vmrun` (a shell script on PATH recording its calls
and replaying recorded output) and covers: the happy path's call sequence, a
failed test step (exit 1, failed names in the summary), Tools never ready
(timeout, VM powered off), VM already running, a stale lock, a missing Keychain
entry, and cleanup on SIGINT.

### 4. `make verify-linux`

Runs `make test` and the conformance suites inside a Linux golang container
on linux/arm64, the host's native architecture (my call: an emulated amd64
pass would be slow, and `vet-cross` in `release-check` covers the amd64
compile)
(image pinned by digest), with the repository at the pushed commit mounted read
only and the Postgres suites through testcontainers (Docker socket mounted) or
a sibling Postgres container; the builder picks. Summary on stdout, full log to
a file.

### 5. Pre-push hook

`.githooks/pre-push` (the repository already uses `core.hooksPath .githooks`
for the CATS pre-commit hook). For each pushed ref it reads the local and remote
SHAs from stdin, computes the changed files of the commits being pushed (for a
new remote ref: against `origin/main`), and runs, against the pushed tip commit
(not HEAD: a push may send refs other than HEAD):

- `gates-selftest` when a gate is modified (Decision 5): `scripts/check-gates*.sh`,
  `scripts/m*-exit-checks.sh`, `scripts/ci-gate-negative.sh`,
  `scripts/ci-sim.sh`, `scripts/pen-gate*.sh`, `internal/dbtest/**`, and a
  Makefile diff that touches the gate targets' recipes (`verify`,
  `check-gates*`, `test*`, the `*-check` targets); a Makefile change elsewhere
  does not trigger it. `check-gates-selftest.sh` gains a commit argument (it
  tests HEAD today).
- A pass of any hook check is recorded per (check, commit) under the data dir,
  so a retried push (for example after the remote connection timed out during
  a long hook) does not rerun it (my call).
- `make windows-test` when Windows-relevant files change. Builder's starting
  set (my call): `*_windows.go`, `*.ps1`, `release/**`, `internal/procs/**`,
  `internal/credential/**`, `internal/sessionstate/**`, `go.mod`, `go.sum`.
- `make verify-linux` when Linux-relevant files change: `*_linux.go`,
  `*_unix.go`, `Dockerfile`, `go.mod`, `go.sum` (my call).

A failure blocks the push, naming the check and its log. `git push
--no-verify` bypasses, as for the pre-commit hook. The hook prints which checks
it chose and why. Its path selection gets a table test against recorded change
lists.

### 6. Release preflight

`release/release.sh` runs, before it creates the draft or dispatches
`release-build.yml`: `make verify`, `make verify-linux`, `make windows-test`,
`make release-check`, `make release-lint`, `make release-install-check`,
`make vet-tags`, the tagged key-provider tests the `signing-key-tags` job runs
(`go test -tags awskms,gcpkms,azurekms,hashivault ./internal/server/cmd/
./internal/keyprovider/...`), `make pen-check` (the `pen-gate` job on the
`adr-0019-spec-1` branch), `make docker-smoke` and `scripts/m9-exit-checks.sh`.
Any failure stops the release before anything is published. The preflight
runs against the tag's commit (a worktree), not HEAD. A full preflight pass is
recorded per tag commit, so rerunning `release.sh` for the same tag after a
later-step failure (docs/release.md) does not repeat it; there is no skip flag
(my call). `gates-selftest` is
not part of it (Decision 5). Its harness tests (`release/test-*.sh`) cover the
new step with fakes.

## Coverage after the change

- Every push: `make verify` locally (unchanged), which already includes
  `check-gates` and the negative halves the `gate-negative*` jobs proved.
- Pushes that touch the relevant files: the selftest, Windows, Linux.
- Release: everything above plus the release-only jobs.
- The m5 and m8 `--deps-only` import rules ran on the real tree only in the
  `gates-selftest` job. They move into `make verify` (after Task 2 makes them
  fast), so they run on every push (my call).
- Accepted (Decision 7): Windows and Linux test runs of platform-neutral code
  happen at release.
- Accepted loss: a per-push Windows compile check for pushes outside the
  Windows path set (`vet-cross` moves to release with `release-check`). The
  builder may add `vet-cross` to the pre-push hook if it costs under a minute.

## Tasks, in order

1. Cloud workflows to dispatch-only, interim done rule, doc and m9 follow-ups
   (lands on main now; small).
2. Faster import-rule scripts (after the branch question is settled).
3. Spike (needs Eric): a full clone of Eric's VM (`vmrun clone ... full`, my
   call over a linked clone, since the cleanup diverges it anyway), stripped of
   everything non-standard (Decision 6; the builder lists candidates, Eric
   confirms removals in the guest); Eric stores the two passwords in the
   Keychain and, in the clone, installs Go, Git for Windows and PowerShell 7
   and enables the account for VMware Tools guest operations; then a throwaway script proves headless
   start, a guest command, copy in and out, `GOARCH=amd64 go test` under
   Prism, and the wall time after a revert. Eric takes the baseline snapshot.
   If guest operations fail on the encrypted VM, the fallback is approach B.
4. `scripts/windows-test.sh`, its selftest, `make windows-test`.
5. `make verify-linux`.
6. The pre-push hook and its path-selection tests; the selftest's commit
   argument.
7. The release preflight in `release.sh` with its harness tests.
8. Delete `windows.yml` after a real `make windows-test` pass; final done-rule
   wording in the project CLAUDE.md; ADR 0020 records these decisions.

## Left to the builder

The Keychain service names and snapshot name; the exact `go list` formulation;
the container approach for Postgres in `verify-linux`; whether the baseline
snapshot carries a warm module cache; the final path sets after a look at which
packages hold Windows- and Linux-specific code.
