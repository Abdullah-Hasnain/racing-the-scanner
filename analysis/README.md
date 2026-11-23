# Analysis (shared)

Turns the CSVs in `results/` into the figures G1-G6 in `figures/`.

```bash
python -m sim.run_experiment --policies all    # writes results/aggregate_mimicry.csv
python analysis/make_graphs.py                 # writes figures/G4_policy_comparison.png
```

G4 (the scheduler-policy comparison) is wired now because the simulation already
produces its data. G1, G2, G3, G5, G6 light up as the memory and detection
harnesses start writing their result CSVs; each stub prints which module it
needs. Keep figures out of git (they are regenerable and `.gitignore`d).
