#!/usr/bin/env bash
# One-command demo: run the full scheduler-policy sweep and build the figure.
# This is the reproducible headline result (the simulation half).
set -euo pipefail
cd "$(dirname "$0")/.."

# Use the project venv even when it isn't activated (a fresh terminal after
# scripts/setup.sh has no `python` on Ubuntu, and system python lacks the deps).
PY=.venv/bin/python
if [ ! -x "$PY" ]; then
  echo "No .venv found. Run scripts/setup.sh first." >&2
  exit 1
fi

echo "== full policy sweep (baseline + 15 ML + 4 reservations + invariant) =="
"$PY" -m sim.run_experiment --policies all --runs 20

echo "== figures =="
"$PY" analysis/make_graphs.py

echo
echo "Done. See results/aggregate_mimicry.csv and figures/G4_policy_comparison.png"
echo "Expected: every ML policy is evaded under mimicry, while every CPU reservation"
echo "(the invariant is one of them) keeps the monitor scheduled."
