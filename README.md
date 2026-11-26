# Racing the Scanner

**Comparing baseline, ML-augmented, and invariant Linux scheduling frameworks against memory-hiding and mimicry-starvation attacks.**

Operating Systems course project, Habib University. Three members, five machines.

---

## What this project is

A live RAM scanner can only catch a memory-hiding process during the few milliseconds it exposes a page. The scanner needs CPU to run, so whoever controls the scheduler controls whether the scanner runs in time. Detection is a race for CPU.

We study that race. An unprivileged attacker (1) hides its data with virtual-memory tricks and (2) shapes its CPU timing to look benign so it can hog the processor and delay the scanner past the exposure window. Then we compare how different **scheduling frameworks** keep the monitor running on time under that attack:

- **S0 Baseline:** stock Linux EEVDF (the control).
- **S2 Augmented (ML):** a family of ~15 ML-augmented schedulers, swept through one shared harness.
- **S4 Reservation:** the standard Linux mechanisms (`SCHED_FIFO`, cgroup `cpu.max`, cgroup `cpu.weight`, `SCHED_DEADLINE`), detection-free, to answer "why not just use real-time priority or cgroups?".
- **S3 Invariant:** a hard CPU-reservation floor that guarantees the monitor its share regardless of any model.

Separately, because normal apps (Node.js JIT, Go/Java GC, jemalloc) use the same memory syscalls as the attacker, we test whether pairing Aqua Tracee with a small local-LLM triage layer cuts false alarms.

> Full rationale and the research question live in `docs/architecture.md`. The written proposal is the source of truth for scope.

---

## Repository map

| Path | Owner | What's in it |
|------|-------|--------------|
| `sim/` | Hasnain (@Abdullah-Hasnain) | The scheduler simulation, the ~15 ML policies, the standard reservation baselines, the invariant, the mimicry attacker, metrics. **The core deliverable.** |
| `memory/` | Khan (@khan-slayer) | The four hiding payloads (V1-V4) in C and the live RAM scanner. Linux only. |
| `detection/` | Ibad (@vanodew1) | Aqua Tracee policies, the per-PID log aggregator, the local-LLM triage, benign workload runners. |
| `analysis/` | shared | Builds graphs G1-G6 from `results/`. |
| `docs/` | all | Architecture, hardware roles, per-OS setup guides. |
| `scripts/` | all | Setup, demo, and issue-creation helpers. |
| `.github/` | all | CI workflows and issue/PR templates. |

Everyone reads `docs/architecture.md` and `CONTRIBUTING.md` first.

---

## Quick start (every machine, CPU only)

The whole simulation and the full model sweep need **nothing but Python**. No GPU, no Linux, no root. This is deliberate: the core result is machine-independent so all three of you can work in parallel.

```bash
# 1. Clone
git clone <REPO_URL>
cd racing-the-scanner

# 2. Create an environment (Python 3.11+)
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Smoke test: run one quick simulation
make sim                         # or: python -m sim.run_experiment --policies baseline --runs 3 --smoke

# 4. Run the tests
make test
```

If `make sim` prints a short results table and `make test` passes, your environment is correct. You are ready to pick up your first issue.
Per-machine settings (results folder, LLM URL, sweep defaults) are environment
variables; `.env.example` lists them.

The **full sweep** (all schedulers vs the attack) is:

```bash
python -m sim.run_experiment --policies all --runs 20
python -m sim.run_experiment --policies all --runs 20 --g3   # G3's attack conditions
python -m analysis.make_graphs          # writes G1-G6 into figures/
```

Or in one command, without activating the venv: `scripts/run_demo.sh` (run
`scripts/setup.sh` first). It re-runs the simulation and draws every figure, G1-G6.
The data that needs root or a real kernel (the G1/G2 memory sweeps, the
real-kernel G3 run and the Tracee G5 capture) comes from the committed
`captured/` folder. `scripts/run_demo.sh --live` also re-runs the real-kernel G3
run and the G5 capture on this machine (root via `pkexec`, plus Tracee v0.23.2,
Ollama and the benign runtimes; see `detection/README.md`); the G1/G2 sweeps run
on their own (see `memory/README.md`). The default run takes about 20-25 minutes,
mostly the `--g3` sweep, and prints each step.

Add `--no-mimicry` for the naive-hog control, `--condition none|hiding|starvation`
for one half of the attack, or `--g3` to sweep every condition in both modes into
`results/aggregate_g3.csv` (see `docs/architecture.md`, "Attack conditions").
A policy that raises fails the run with a non-zero exit, naming it; pass
`--continue-on-error` to keep the CSVs of the policies that finished.
Aggregates are medians across runs, with the interquartile range (`_q25`/`_q75`)
for p95 latency, miss rate, and the detectors' ROC-AUC (`roc_auc` vs all
legitimate processes, `roc_auc_benign` vs benign apps only; see "Detection
ROC-AUC" in `docs/architecture.md`).

---

## Which machine does what

Hardware differs a lot across the team, so roles are assigned to avoid idle machines and avoid overloading the small ones. Full detail in `docs/hardware-roles.md`; the short version:

| Machine | Role |
|---------|------|
| Ibad's RTX 5070 Ti (32 GB) | Heaviest: the neural autoencoder policy, local-LLM triage, large sweep runs. |
| GTX 1660 Super PC (16 GB) | Moderate GPU: secondary neural/LLM work, parallel sweep shards. |
| MacBook Pro M1 Pro | Development and compilation, the Python sim, and the Linux VM for memory/kernel testing. |
| Khan's laptop (16 GB) | Lightweight: the CPU model sweep (sklearn is fine here), docs, reviews, PM. |
| Ibad's laptop | Lightweight: benign-workload runs, docs, testing, issue triage. |

The systems pieces (C payloads, the scanner, Tracee, any real `scx` work) need **Linux kernel 6.12 or newer**. Use a VM or a dedicated box. See `docs/setup/linux-wsl.md`. The GPU/LLM pieces want the NVIDIA machines. The Python simulation runs anywhere, which is why it is the backbone.

---

## Working together

- Branch per issue: `feat/<area>-<short>`, e.g. `feat/sim-isolation-forest`. Never commit to `main`.
- Open a pull request, link the issue, get one review, let CI pass, then merge.
- Full conventions, including who owns which files to avoid collisions, are in `CONTRIBUTING.md`.
- The task board is GitHub Issues + Projects. Milestones are in `ROADMAP.md`.

---

## Status

- **Simulation (`sim/`):** done. 15 ML policies, the standard reservations and the invariant, ROC-AUC with IQR, and the four G3 attack conditions. Headline: every ML policy is evaded under mimicry; every reservation keeps the monitor scheduled.
- **Real kernel:** the sched_ext spike passes on kernel 7.0 and the `scx_qmap` per-PID weight demo runs (#10, #11). The coupled attack on the real kernel (`detection/coupled_live.py`) shows stock EEVDF starving the scanner and `cpu.weight` / `SCHED_FIFO` protecting it.
- **Memory (`memory/`):** V1-V4 payloads, the live scanner, and the G1/G2 sweeps (`memory/sweep_g1.py`, `sweep_g2.py`). The final runs on bare metal are in `captured/` (#56). Per scan, the scanner catches a hiding page about as often as it is exposed, at any scan interval: about dwell / 100 ms for V2, and a few ms more for V3 (0.05 of scans at 1 ms dwell); a longer interval only delays the first catch.
- **Detection (`detection/`):** Tracee policy, aggregator, LLM triage, benign suite and the G5 harness. On the held-out capture the custom rule catches 15/15 hiding processes with 0/30 false alarms; Tracee's default signatures catch 0/15.
- **Figures:** all six, G1-G6, build on a fresh clone with `scripts/run_demo.sh`, from `results/` or the committed `captured/` data (#16). The report (#60) and the slides (#61) are in review as #66 and #68.
