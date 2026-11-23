"""Run the scheduler-policy comparison.

Examples
  python -m sim.run_experiment --policies baseline --runs 3 --smoke
  python -m sim.run_experiment --policies all
  python -m sim.run_experiment --policies baseline iforest rf invariant --runs 20

Writes per-run and aggregated CSVs into $RTS_RESULTS_DIR (default ./results),
and prints a ranked table. analysis/make_graphs.py turns the CSVs into G1-G6.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import pandas as pd

from sim.engine import SimConfig, run_policy
from sim.policies import all_policies, expand


def _torch_available() -> bool:
    try:
        import torch  # noqa: F401
        return True
    except Exception:
        return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Racing the Scanner: scheduler policy sweep")
    ap.add_argument("--policies", nargs="+", default=["all"],
                    help="policy names or 'all'. See sim/policies for the list.")
    ap.add_argument("--runs", type=int, default=int(os.environ.get("RTS_SIM_RUNS", 20)))
    ap.add_argument("--ticks", type=int, default=600)
    ap.add_argument("--seed", type=int, default=int(os.environ.get("RTS_SIM_SEED", 42)))
    ap.add_argument("--no-mimicry", action="store_true", help="attacker uses obvious hog timing")
    ap.add_argument("--smoke", action="store_true", help="tiny fast run to verify the setup")
    ap.add_argument("--out", default=os.environ.get("RTS_RESULTS_DIR", "./results"))
    args = ap.parse_args()

    if args.smoke:
        args.runs = min(args.runs, 3)
        args.ticks = 150

    names = expand(args.policies, include_torch=_torch_available())
    if not _torch_available():
        skipped = [n for n in expand(args.policies, include_torch=True) if n not in names]
        if skipped:
            print(f"[note] torch not installed; skipping: {', '.join(skipped)}")

    cfg = SimConfig(ticks=args.ticks, seed=args.seed, mimicry=not args.no_mimicry)

    per_run: list[dict] = []
    for name in names:
        try:
            rows = run_policy(name, cfg, runs=args.runs)
            per_run.extend(rows)
            agg = pd.DataFrame(rows)[["p95_latency", "miss_rate", "overhead_ms"]].median()
            print(f"  {name:<14} p95={agg.p95_latency:7.1f}  "
                  f"miss={agg.miss_rate:5.2f}  overhead={agg.overhead_ms:6.2f}ms")
        except Exception as exc:  # one bad policy must not kill the sweep
            print(f"  {name:<14} FAILED: {exc}")

    if not per_run:
        print("no results produced")
        return 1

    df = pd.DataFrame(per_run)
    num = df.select_dtypes("number").columns
    agg = (df.groupby(["policy", "group"], as_index=False)[num].median()
             .sort_values("p95_latency"))

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    tag = "mimicry" if not args.no_mimicry else "naive"
    df.to_csv(out / f"per_run_{tag}.csv", index=False)
    agg.to_csv(out / f"aggregate_{tag}.csv", index=False)

    print("\n=== ranked by p95 monitor latency (lower is better) ===")
    cols = ["policy", "group", "p50_latency", "p95_latency", "miss_rate",
            "detection_rate", "monitor_share", "overhead_ms"]
    with pd.option_context("display.width", 120, "display.max_rows", None):
        print(agg[cols].to_string(index=False))
    print(f"\nwrote {out}/aggregate_{tag}.csv and per_run_{tag}.csv")
    print(f"policies available: {len(all_policies())} "
          f"(baseline + {len(all_policies()) - 2} augmented + invariant)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
