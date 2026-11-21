# ADR 0020: Local CI

Status: Accepted (Eric, 2026-11-15; decisions 1 to 7 and the fresh-VM deviation). The builder's calls below are plan rulings that Eric ratified on 2026-11-19, which makes them his. `make windows-test` passed its first real run on 2026-11-20 (77e9947), and `windows.yml` was deleted then.

Design: `docs/superpowers/specs/2026-11-15-local-ci-design.md`. Plan: `docs/superpowers/plans/2026-11-15-local-ci.md`. Operator guide for the Windows run: `docs/windows-test.md`.

## Context

One person works on agentmesh from one machine. Cloud CI repeated on GitHub's paid runners what `make verify` already proves locally: about $26 of Actions spend from 2026-11-01 to 2026-11-14, about 94% of it `ci.yml` and `windows.yml`, and the largest job, `gates-selftest`, took 57.6 minutes a run. Eric's goal: GitHub costs as near zero as possible, with every check that ran in cloud CI still running somewhere locally at a defined moment.

## Decisions (Eric, 2026-11-15, human-made)

1. Cloud CI does not run on push. Release checks run only at release.
2. The Windows tests run locally on the Windows 11 arm64 VM in VMware Fusion, fully automated: no manual start, interaction, copying or shutdown, and the VM is not kept running.
3. The slow local checks run from a git pre-push hook, only when the push touches files that matter to them.
4. Linux test coverage: a Linux container target runs at release and from the pre-push hook when Linux-specific files change.
5. `gates-selftest` is not in the CI path or the release path: it runs as its own pre-push check whenever a gate script is modified. A moved mutation anchor surfaces at the next gate change.
6. The existing Windows VM is Eric's general-use VM; testing uses a VM dedicated to testing, and everything in it is eligible for deletion. Superseded in its means by the deviation below.
7. Windows and Linux test runs are, in practice, release-only for platform-neutral code. Accepted.

## Deviation (Eric, 2026-11-15, human-made; supersedes Decision 6's clone)

The test VM is a fresh Windows 11 arm64 install named `Windows 11 Test VM`, not a clone of Eric's VM: guest account `test`, encrypted, snapshot `Baseline` (powered off). The clone and strip steps of the spec are void. `scripts/windows-test.sh` refuses any `.vmx` inside Eric's general-use VM.

## Builder's calls (plan rulings, ratified by Eric 2026-11-19)

- Keychain: service `agentmesh-windows-test`, accounts `vm-encryption` and `guest-test`; passwords never leave the Keychain except on `vmrun`'s command line (accepted by the spec) and are redacted from every log.
- State directory: `AGENTMESH_DEV_STATE`, else `${XDG_STATE_HOME:-$HOME/.local/state}/agentmesh-dev`, holding `logs/<check>/<commit>/`, `passes/<check>/<commit>` and the VM lock; a pass is recorded only after full success.
- Path rules of the hook: pinned in the header of `scripts/pre-push.sh` and encoded in `scripts/pre-push-selftest.sh`.
- `make verify-linux` runs the suites in a linux/arm64 container with a sibling Postgres container (the Chainguard image of `scripts/ci-sim.sh`).
- `hooks-check`: the first step of `make verify` refuses a clone whose `core.hooksPath` is not `.githooks`; it passes under `GITHUB_ACTIONS=true`.

## Consequences

- `ci.yml` is dispatch-only. `windows.yml` was deleted on 2026-11-20, after `make windows-test` passed a real run (77e9947).
- The done rule stays "`make verify` passes locally on the final commit" until that run; its final wording (adding the pre-push checks) waits for it.
- `release/release.sh` runs the preflight (`verify`, `verify-linux`, `windows-test`, the release checks and `m9-exit-checks.sh`) against the tag's commit before publishing.
- The three harness selftests (`windows-test-selftest`, `verify-linux-selftest`, `pre-push-selftest`) are not in any gate; the whole-branch review of 2026-11-19 raised this (Finding 3) and the path set is Eric's call.
