# Final report (#60)

`main.tex` is the IEEE two-column report; `main.pdf` is its build. The format
follows `reference/FORMAT.md` (the instructor's sample sets the shape only).

## Where every number comes from

Nothing in the report is typed in from memory. Each number traces to one of:

| source | what it backs |
|---|---|
| `figures/G1`-`G6` (regenerated, below) | every figure |
| `captured/g1_scan.csv`, `g2_pareto.csv` | G1/G2: per-scan catch rates, slowdowns, faults/s, evasion |
| `captured/coupled_live.csv` | the real-kernel scans/s, slowdowns and catches |
| `captured/detection_g5.csv` | G5 counts and the G6b triage time |
| `results/aggregate_{mimicry,naive,g3}.csv` (from `scripts/run_demo.sh`) | G3 (simulation), G4, the AUCs, Table I, G6a |
| `docs/architecture.md` | the scenario weights, calibration rule, AUC reading, `cpu.max` cap sweep (re-derived through `sim.engine.run_policy`) |
| `docs/scx-qmap-demo.md` | Table II (sched_ext) |
| `detection/README.md` | Tracee setup, the relock rule, the earlier capture's flip counts, the equal-nice control and the earlier EEVDF run |

## Rebuild

From the repo root on a fresh clone:

```bash
scripts/setup.sh
scripts/run_demo.sh          # ~20-25 min; regenerates results/ and figures/
make -C report figures       # copies figures/G1..G6 into report/figures/
make -C report               # latexmk -> report/main.pdf
```

The committed `report/figures/` were produced this way on 2026-11-26 from
commit 5b10251 (`main` at 1c00012 plus `report/reference/`), on a fresh
tracked-files-only copy: `setup.sh` then the unmodified `run_demo.sh`, exit 0.
The optional autoencoder policy is skipped because `setup.sh` does not install
PyTorch, so the figures show 14 ML policies.

## Figure numbers

The paper numbers its figures in reading order, which differs from the repo's
graph names: Fig. 1 is G1, Fig. 2 is G2, Fig. 3 is G4, Fig. 4 is G3, Fig. 5 is G5
and Fig. 6 is G6.

## Committed binaries

`report/figures/*.png` and `report/main.pdf` are committed on purpose, an
exception to the "do not commit figures" rule in `CONTRIBUTING.md`, so the
report reads and rebuilds without running `run_demo.sh` or LaTeX first.
