# CLAUDE.md

Guidance for AI agents (and humans) working in this repo. Read this first.

## What this is

A controlled comparison of Linux scheduling frameworks against a combined
memory-hiding and mimicry-starvation attack. A live RAM scanner only catches a
hiding process during the few ms it exposes a page; the scheduler decides
whether the scanner runs in time. We compare the stock scheduler (EEVDF), ~15
ML-augmented schedulers, and a hard CPU-reservation invariant. See `README.md`
and `docs/architecture.md`.

## Structure and ownership

- `sim/` (Member 2): the scheduler simulation and the 15-policy sweep. **The core
  deliverable.** Pure Python, CPU-only, runs on any machine.
- `memory/` (Member 1): V1-V4 hiding payloads (C) and the live RAM scanner. Linux
  kernel 6.12+.
- `detection/` (Member 3): Aqua Tracee policy, per-PID aggregator, local-LLM
  triage, benign workload suite.
- `analysis/`: builds the figures G1-G6 from `results/`.

Respect module boundaries; flag cross-area changes on the issue first.

## Conventions

- Branch per issue off `main`: `feat/<area>-<short>` (e.g. `feat/sim-ocsvm`).
  Never commit to `main` directly; `main` stays green.
- PR into `main`, one review, CI must pass (`python-ci` + `c-build`), squash-merge.
  Fill the PR template; link the issue with "Closes #N".
- `ruff check .` and `make test` must pass. For C changes, `make -C memory check`.
- Keep `sim/` CPU-only and dependency-light. torch/GPU code stays optional and
  import-guarded (see `sim/policies/autoencoder.py`).
- Do not commit `data/`, `results/`, `figures/`, model weights, or `.env` (all
  gitignored).

## Commit and PR messages

Do NOT add "Co-Authored-By", "Generated with Claude Code", "Claude-Session", or
any similar attribution or trailer lines to commits, PRs, or issues. Keep
messages clean and plain.

## Running it

- Setup: `scripts/setup.sh` (or `scripts/setup.ps1` on Windows).
- Smoke: `make sim`. Tests: `make test`.
- Full sweep + figure: `scripts/run_demo.sh`.
- Expected headline result: under mimicry all ~15 ML policies are evaded (the
  disguised hog looks benign), while only the invariant keeps the monitor
  scheduled. If a change breaks that, something is wrong.

## Constraints and gotchas

- `sched_ext` needs kernel 6.12+; `memfd_secret` often needs `secretmem.enable=1`.
  The real-kernel work is a stretch (Milestone 3); the simulation is the
  guaranteed deliverable. Do not make the core depend on the kernel.
- Microsecond scheduling timing inside a VM is noisy; take headline scheduling
  numbers from the simulation or a bare-metal/cloud x86-64 host.
- GitHub from agent sessions: use the REST API (`gh api repos/{owner}/{repo}/...`).
  GraphQL is blocked, so `gh issue create` fails; create issues via
  `POST /repos/{owner}/{repo}/issues`.
