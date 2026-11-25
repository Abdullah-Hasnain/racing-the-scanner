# Analysis (shared)

Turns the CSVs in `results/` into the figures G1-G6 in `figures/`.

```bash
python -m sim.run_experiment --policies all          # results/aggregate_mimicry.csv  -> G4, G6a
python -m sim.run_experiment --policies all --g3     # results/aggregate_g3.csv       -> G3
# detection harness writes results/detection_g5.csv  -> G5, G6b
python -m analysis.make_graphs                       # writes figures/
python -m pytest analysis/tests                      # figure tests (tiny CSVs, no sim run)
```

Each figure is one function and skips with a `[Gx] skip: ...` line when its CSV
is missing, so a partial `results/` still builds what it can. CSVs that need
root or a real kernel (`g1_scan.csv`, `g2_pareto.csv`, `coupled_live.csv`, `detection_g5.csv`) fall back to the
committed copies in `captured/` (`RTS_CAPTURED_DIR`) when `results/` has none;
a fresh `results/` file always wins.

| figure | CSV | shows |
|---|---|---|
| G1 `G1_catch_rate.png` | `g1_scan.csv` from the memory G1 sweep (#4, spec in #38) | per-scan catch rate (`catches / scans`, median over reps, IQR bars) vs scan interval on a log axis; one panel each for V2 and V3, one line per dwell time; V1 (dashed) and V4 (dotted) as reference lines |
| G2 `G2_pareto.png` | `g2_pareto.csv` from the memory G2 sweep (#5, spec in #38) | left: attacker slowdown vs V1 (log) against evasion rate at a 37 ms scan interval, one point per variant and dwell (medians over reps), with the Pareto front (no other setting is both cheaper and more evasive); right: the payload's own faults per second (`faults_per_s`) per setting; not /proc `minflt`, which never counts V2's SIGSEGV faults |
| G3 `G3_attack_conditions.png` | `aggregate_g3.csv`, `coupled_live.csv` | scanner slowdown vs no attack in each condition (none, hiding, starvation, coupled), so 1.0 = unharmed. Solid bars: simulation, p95 latency over its `none` value, mimicry attacker, for EEVDF, iforest, rf, SCHED_FIFO, cpu.weight, invariant. Hatched bars: real kernel (`detection/coupled_live.py`, root), scans/s under `none` over scans/s in the condition, median over reps, nice -20 attacker, for EEVDF, SCHED_FIFO, cpu.weight. Miss rate is not the shared axis because the sim's starvation condition has no exposure window, so its miss rate stays 0 while the scanner is delayed (#44). Either source alone still draws |
| G4 `G4_policy_comparison.png` | `aggregate_mimicry.csv` | p95 latency and miss rate for every policy, coloured by group |
| G5 `G5_detection.png` | `detection_g5.csv` | catch rate vs false-alarm rate for Tracee default, custom, and custom + AI, pooled over runs (sum caught / sum n_attackers, sum false_alarms / sum n_benign). `ai` rows split by `triage_backend`: `llm:<model>` is "custom + AI (<model>)", `heuristic` is "custom + heuristic", and `llm-fallback:*` rows are excluded (printed as `[G5] excluded N llm-fallback rows`) |
| G6 `G6_overhead.png` | `aggregate_mimicry.csv`, `detection_g5.csv` | G6a: real wall-clock ms the policy's decision code took, summed over a run; G6b: mean AI triage latency per process (ms) from the `llm:*` `ai` rows only (heuristic and llm-fallback rows are not AI overhead, and G6b is skipped with a printed reason if none exist) |

The sim times only `policy.multipliers`, not `policy.allocate`, so the reservation policies and the invariant show about 0 in G6a by construction. That is a sim limitation, not a measured zero cost.

If only one of the two G6 CSVs exists, G6 draws that part and prints which one it skipped.
The two overheads are different units on different systems (sim decision time vs real LLM
latency), so G6 keeps them in separate panels rather than one axis.

Keep figures out of git (they are regenerable and `.gitignore`d).
