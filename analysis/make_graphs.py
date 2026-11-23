"""Build the figures G1-G6 from the CSVs in results/.

Right now G4 (the scheduler-policy comparison) is fully wired, because the
simulation already produces its data. G1, G2, G3, G5, G6 are stubbed with a
clear message naming the module whose results feed them; they light up as the
memory and detection harnesses start writing their CSVs.

Usage:
  python -m sim.run_experiment --policies all      # produce results/
  python analysis/make_graphs.py                   # writes figures/
"""

from __future__ import annotations

import os
from pathlib import Path

import matplotlib
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RESULTS = Path(os.environ.get("RTS_RESULTS_DIR", "./results"))
FIGURES = Path(os.environ.get("RTS_FIGURES_DIR", "./figures"))


def g4_policy_comparison() -> bool:
    """G4: monitor p95 latency and miss rate across every scheduling policy."""
    src = RESULTS / "aggregate_mimicry.csv"
    if not src.exists():
        print("[G4] skip: run `python -m sim.run_experiment --policies all` first")
        return False
    df = pd.read_csv(src).sort_values("p95_latency")

    colors = {"baseline": "#888", "invariant": "#2a7", "ml-unsupervised": "#47a", "ml-supervised": "#a55"}
    bar_colors = [colors.get(g, "#47a") for g in df["group"]]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    ax1.barh(df["policy"], df["p95_latency"], color=bar_colors)
    ax1.set_xlabel("p95 monitor scan latency (ticks, lower is better)")
    ax1.set_title("G4a: scheduler policy vs monitor latency under mimicry")
    ax1.invert_yaxis()

    ax2.barh(df["policy"], df["miss_rate"], color=bar_colors)
    ax2.set_xlabel("miss rate (fraction of scans that missed the window)")
    ax2.set_title("G4b: detection miss rate by policy")
    ax2.invert_yaxis()

    fig.tight_layout()
    FIGURES.mkdir(parents=True, exist_ok=True)
    out = FIGURES / "G4_policy_comparison.png"
    fig.savefig(out, dpi=130)
    plt.close(fig)
    print(f"[G4] wrote {out}")
    return True


def _stub(tag: str, needs: str) -> None:
    print(f"[{tag}] skip: needs results from {needs}")


def main() -> int:
    g4_policy_comparison()
    _stub("G1", "memory/scanner (catch rate vs scan interval)")
    _stub("G2", "memory payloads (slowdown vs evasion Pareto)")
    _stub("G3", "memory + sim (hiding only / starvation only / coupled)")
    _stub("G5", "detection (Tracee catch vs false-alarm, with/without AI)")
    _stub("G6", "detection + sim (AI and scheduler overhead)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
