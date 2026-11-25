#!/usr/bin/env bash
# One-command demo: rebuild every figure G1-G6.
#
#   scripts/run_demo.sh          regenerate the CPU-only data (scheduler sweep, G3
#                                conditions) and draw every figure; the root-only
#                                data comes from the committed copies in captured/
#   scripts/run_demo.sh --live   also re-run the root captures on this machine
#                                (real-kernel G3 run, Tracee G5 capture); asks for
#                                your password through pkexec
#
# A CSV in results/ always wins over its copy in captured/ (see captured/README.md).
set -euo pipefail
cd "$(dirname "$0")/.."

LIVE=0
case "${1:-}" in
  "") ;;
  --live) LIVE=1 ;;
  *) echo "usage: scripts/run_demo.sh [--live]" >&2; exit 2 ;;
esac

# Use the project venv even when it isn't activated (a fresh terminal after
# scripts/setup.sh has no `python` on Ubuntu, and system python lacks the deps).
PY=.venv/bin/python
if [ ! -x "$PY" ]; then
  echo "No .venv found. Run scripts/setup.sh first." >&2
  exit 1
fi

echo "== full policy sweep (baseline + 15 ML + 4 reservations + invariant) =="
"$PY" -m sim.run_experiment --policies all --runs 20

echo "== attack conditions for G3 (none, hiding, starvation, coupled; naive and mimicry) =="
"$PY" -m sim.run_experiment --policies all --runs 20 --g3

# Both live scripts append to their CSV, and the figures pool every row in it, so an
# earlier run on this machine is moved aside rather than blended into this one.
move_aside() {
  if [ -f "results/$1" ]; then
    local old
    old="results/$1.$(date +%Y%m%d-%H%M%S).bak"
    mv "results/$1" "$old"
    echo "moved the previous $1 aside to $old"
  fi
}

if [ "$LIVE" = 1 ]; then
  echo "== live: building the payloads =="
  make -C memory

  echo "== live: coupled attack on the real kernel (root, ~15 min) =="
  move_aside coupled_live.csv
  pkexec "$PWD/$PY" "$PWD/detection/coupled_live.py" --repo "$PWD"

  echo "== live: G5 Tracee capture (root; needs Tracee v0.23.2, node, go, java, Ollama) =="
  move_aside detection_g5.csv
  pkexec "$PWD/$PY" "$PWD/detection/g5_capture.py" capture --repo "$PWD"
  run_dir=$(ls -td results/g5/*/ | head -1)
  "$PY" detection/g5_capture.py score "$run_dir"

  echo "(G1/G2 are not re-run here: memory/sweep_g1.py and sweep_g2.py take ~40 min as root; their final runs are in captured/, #56.)"
fi

echo "== figures =="
"$PY" -m analysis.make_graphs

echo
echo "Done. Figures are in figures/."
echo "Expected:"
echo "  G1: V1 is caught on every scan and V4 never; V2/V3 are caught about as often as"
echo "      they expose a page (about dwell / 100 ms), at any scan interval."
echo "  G2: hiding costs V2/V3 a ~1,600-2,200x slowdown and ~300K faults/s to evade"
echo "      70-98% of scans every 37 ms; V4 evades every scan at ~1x."
echo "  G3: EEVDF and the ML policies slow the scanner several times over under starvation"
echo "      and the coupled attack; every reservation stays at 1.0x, in the simulation and"
echo "      on the real kernel."
echo "  G4: every ML policy is evaded under mimicry (miss rate 1.0), while every CPU"
echo "      reservation (the invariant is one of them) keeps the monitor scheduled (0.0)."
echo "  G5: Tracee's default signatures miss the hiding payloads; the custom rule catches"
echo "      them with no false alarms on the benign runtimes."
echo "  G6: every reservation decides in a few ms a run, the ML policies in ~50-1,800 ms;"
echo "      AI triage takes ~400 ms per process."
