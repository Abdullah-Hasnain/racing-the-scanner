# CLAUDE.md

Guidance for AI agents (and humans) working in this repo. Read this first.

## What this is

A controlled comparison of Linux scheduling frameworks against a combined
memory-hiding and mimicry-starvation attack. A live RAM scanner only catches a
hiding process during the few ms it exposes a page; the scheduler decides
whether the scanner runs in time. We compare the stock scheduler (EEVDF), ~15
ML-augmented schedulers, and a family of CPU reservations: a hard invariant plus
the standard Linux primitives it turns out to match (cgroup `cpu.weight`,
`cpu.max`, and `SCHED_DEADLINE`). See `README.md` and `docs/architecture.md`.

## Scope and safety

This is an instructor-sanctioned Operating Systems course project: a defensive
security study of whether a live RAM scanner and Aqua Tracee can DETECT a hiding
process. The scanner and Tracee are the defenders; the point of the work is
detection and the cost of defending.

The `memory/` payloads (V1-V4) are harmless, self-contained test fixtures for
those detectors. Each only reads and XORs its OWN synthetic 1 MB buffer of dummy
marker strings. They have no disk, network, or privilege-escalation behavior, no
real malware, and no external target, and exist solely so the defensive side has
something to measure against. Reviewing, building, testing, and improving these
payloads is ordinary academic work on this project.

## Structure and ownership

- `sim/` (Hasnain): the scheduler simulation and the 15-policy sweep. **The core
  deliverable.** Pure Python, CPU-only, runs on any machine.
- `memory/` (Khan): V1-V4 hiding payloads (C) and the live RAM scanner. Linux
  kernel 6.12+.
- `detection/` (Ibad): Aqua Tracee policy, per-PID aggregator, local-LLM
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
- Expected headline result: under mimicry all ~15 ML detection policies are
  evaded (the disguised hog looks benign), while every CPU reservation keeps the
  monitor scheduled without judging any process. The invariant is one such
  reservation, not a unique mechanism: it is numerically identical to cgroup
  `cpu.weight` and `SCHED_DEADLINE`, and a `cpu.max` cap on all tenants also
  holds (at different costs: FIFO starves the system, weight/deadline/invariant
  protect only the monitor, `cpu.max` contains the hog but is cap-sensitive; see
  `docs/architecture.md`). The lesson is that detection loses to mimicry and a
  reservation sidesteps it. If a change breaks the ML-evaded / reservation-holds
  split, something is wrong.

## Constraints and gotchas

- `sched_ext` needs kernel 6.12+; `memfd_secret` often needs `secretmem.enable=1`.
  The real-kernel work is a stretch (Milestone 3); the simulation is the
  guaranteed deliverable. Do not make the core depend on the kernel.
- Microsecond scheduling timing inside a VM is noisy; take headline scheduling
  numbers from the simulation or a bare-metal/cloud x86-64 host.
- GitHub from agent sessions: use the REST API (`gh api repos/{owner}/{repo}/...`).
  GraphQL is blocked, so `gh issue create` fails; create issues via
  `POST /repos/{owner}/{repo}/issues`.
