# Roadmap

Staged so a complete result exists even if the real-kernel work is cut. The
simulation core is the guaranteed deliverable; the kernel validation is a
gated stretch.

## Milestone 1 - Environment and skeleton (done in this scaffold)
- Repo, CI, per-OS setup, runnable simulation harness, 15-policy registry,
  memory payload skeletons, detection pipeline skeletons, G4 wired.

## Milestone 2 - Core results (the guaranteed deliverable)
- **sim:** finish and tune all 15 ML policies; run the full sweep with repeats
  and confidence intervals; produce G4 and the mimicry-vs-naive comparison.
- **memory:** finish V2 dwell re-locking and V3 drop-after-use; scanner logs
  catch rate and scan latency to CSV; produce G1 and G2.
- **detection:** end-to-end Tracee -> aggregator -> triage harness; false-alarm
  study on Node/Go/jemalloc; produce G5.
- **integration:** the coupled attack (hiding + starvation) measured across
  policies; produce G3 and G6.

## Milestone 3 - Real-kernel validation (stretch, gated on a 1-day spike)
- Boot a kernel 6.12+ box; load `scx_simple` to confirm the environment.
- Modify `scx_qmap` to read a per-PID weight from a pinned BPF map; reproduce
  the starvation-and-restore result for a subset of policies (baseline, one ML,
  invariant) on the real kernel.
- If the spike fails, the scheduling results stand on the simulation and the
  claim is scoped to "a faithful model", as the proposal states.

## Milestone 4 - Comparison baselines (strengthens the result)
- Add the standard CPU-reservation baselines as scheduling conditions so the
  comparison answers "why not just real-time priority or cgroups": `SCHED_FIFO`,
  cgroup v2 `cpu.max`, `SCHED_DEADLINE`, alongside the ML policies and invariant.

## Milestone 5 - Write-up
- Methodology, results, honest limitations (self-built schedulers, sim fidelity,
  adaptive attacker out of scope, VM timing validity). One-command reproduction
  (`scripts/run_demo.sh`) and a clean README on a fresh clone.

## Optional stretch (Group C neural policies)
- LSTM and 1D-CNN temporal schedulers to add to the sweep, on the GPU machines.
