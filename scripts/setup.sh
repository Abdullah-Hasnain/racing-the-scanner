#!/usr/bin/env bash
# One-command setup for macOS/Linux. Creates a venv, installs core deps,
# and runs the smoke test.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

echo "== smoke test =="
python -m sim.run_experiment --policies baseline invariant --runs 2 --smoke
echo "== unit tests =="
python -m pytest -q
echo
echo "Ready. Activate with: source .venv/bin/activate"
echo "Full sweep and figure: scripts/run_demo.sh"
