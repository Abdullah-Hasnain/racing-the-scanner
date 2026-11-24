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
is missing, so a partial `results/` still builds what it can.

| figure | CSV | shows |
|---|---|---|
| G1, G2 | memory module | still stubbed |
| G3 `G3_attack_conditions.png` | `aggregate_g3.csv` | miss rate per condition (none, hiding, starvation, coupled) for baseline, iforest, rf, cgroup_weight, invariant; hatched bars are the mimicry attacker, bars show the median and the IQR |
| G4 `G4_policy_comparison.png` | `aggregate_mimicry.csv` | p95 latency and miss rate for every policy, coloured by group |
| G5 `G5_detection.png` | `detection_g5.csv` | catch rate vs false-alarm rate for Tracee default, custom, and custom + AI, pooled over runs (sum caught / sum n_attackers, sum false_alarms / sum n_benign). `ai` rows split by `triage_backend`: `llm:<model>` is "custom + AI (<model>)", `heuristic` is "custom + heuristic", and `llm-fallback:*` rows are excluded (printed as `[G5] excluded N llm-fallback rows`) |
| G6 `G6_overhead.png` | `aggregate_mimicry.csv`, `detection_g5.csv` | G6a: real wall-clock ms the policy's decision code took, summed over a run; G6b: mean AI triage latency per process (ms) from the `llm:*` `ai` rows only (heuristic and llm-fallback rows are not AI overhead, and G6b is skipped with a printed reason if none exist) |

The sim times only `policy.multipliers`, not `policy.allocate`, so the reservation policies and the invariant show about 0 in G6a by construction. That is a sim limitation, not a measured zero cost.

If only one of the two G6 CSVs exists, G6 draws that part and prints which one it skipped.
The two overheads are different units on different systems (sim decision time vs real LLM
latency), so G6 keeps them in separate panels rather than one axis.

Keep figures out of git (they are regenerable and `.gitignore`d).
