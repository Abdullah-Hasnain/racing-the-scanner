#!/usr/bin/env bash
# One-command demo: run the full scheduler-policy sweep and build the figure.
# This is the reproducible headline result (the simulation half).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== full policy sweep (baseline + 15 augmented + invariant) =="
python -m sim.run_experiment --policies all --runs 20

echo "== figures =="
python analysis/make_graphs.py

echo
echo "Done. See results/aggregate_mimicry.csv and figures/G4_policy_comparison.png"
echo "Expected: every ML policy is evaded under mimicry; only the invariant holds."
