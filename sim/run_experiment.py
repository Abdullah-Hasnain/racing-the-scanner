"""Run the scheduler-policy comparison.

Examples
  python -m sim.run_experiment --policies baseline --runs 3 --smoke
  python -m sim.run_experiment --policies all
  python -m sim.run_experiment --policies baseline iforest rf invariant --runs 20
  python -m sim.run_experiment --policies all --condition none     # no-attacker control
  python -m sim.run_experiment --policies all --g3                 # every condition x mode

Writes per-run and aggregated CSVs into $RTS_RESULTS_DIR (default ./results),
and prints a ranked table. analysis/make_graphs.py turns the CSVs into G1-G6.

File names: the coupled attack (the default) writes aggregate_{mimicry,naive}.csv;
another condition writes aggregate_<condition>_<mode>.csv; --g3 writes
aggregate_g3.csv with `condition` and `mimicry` columns.

Aggregates are medians across runs. p95_latency, miss_rate, roc_auc, and
roc_auc_benign also get <metric>_q25 and <metric>_q75 (the interquartile range),
printed as "median [q25, q75]". roc_auc is n/a (empty in the CSV) for policies
without a detector and where there is no attacker.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace
from pathlib import Path

import pandas as pd

from sim.engine import CONDITIONS, SimConfig, run_policy
from sim.metrics import aggregate
from sim.policies import all_policies, augmented_policies, expand, reservation_names


def _torch_available() -> bool:
    try:
        import torch  # noqa: F401
        return True
    except Exception:
        return False


def _mode(mimicry: bool) -> str:
    return "mimicry" if mimicry else "naive"


def _iqr(row: pd.Series, metric: str, spec: str) -> str:
    """'median [q25, q75]' from an aggregate row; n/a when the metric is undefined."""
    if pd.isna(row[metric]):
        return "n/a"
    return f"{row[metric]:{spec}} [{row[f'{metric}_q25']:{spec}}, {row[f'{metric}_q75']:{spec}}]"


def _sweep(names: list[str], cfg: SimConfig, runs: int) -> tuple[list[dict], list[str]]:
    """Run each policy; returns the per-run rows and the policies that raised."""
    per_run: list[dict] = []
    failed: list[str] = []
    for name in names:
        try:
            rows = run_policy(name, cfg, runs=runs)
            per_run.extend(rows)
            r = aggregate(pd.DataFrame(rows), ["policy"]).iloc[0]
            print(f"  {name:<14} p95={_iqr(r, 'p95_latency', '.1f'):<20} "
                  f"miss={_iqr(r, 'miss_rate', '.2f'):<19} "
                  f"auc={_iqr(r, 'roc_auc', '.2f'):<19} overhead={r.overhead_ms:6.2f}ms")
        except Exception as exc:  # one bad policy must not kill the sweep
            print(f"  {name:<14} FAILED: {exc}", file=sys.stderr)
            failed.append(f"{name} ({cfg.condition}, {_mode(cfg.mimicry)})")
    return per_run, failed


def _exit_status(failed: list[str], continue_on_error: bool) -> int:
    """Exit status for the sweep: 1 when a policy failed, unless --continue-on-error."""
    if not failed:
        return 0
    print(f"\n{len(failed)} policy runs failed and are missing from the CSVs: {', '.join(failed)}",
          file=sys.stderr)
    return 0 if continue_on_error else 1


def _g3(names: list[str], cfg: SimConfig, runs: int, out: Path, continue_on_error: bool) -> int:
    """Every attack condition in both attacker modes, for G3."""
    per_run: list[dict] = []
    failed: list[str] = []
    for condition in CONDITIONS:
        for mimicry in (False, True):
            print(f"\n== {condition}, {_mode(mimicry)} ==")
            rows, bad = _sweep(names, replace(cfg, condition=condition, mimicry=mimicry), runs)
            per_run.extend(rows)
            failed.extend(bad)
    if not per_run:
        print("no results produced")
        return 1

    df = pd.DataFrame(per_run)
    agg = aggregate(df, ["condition", "mimicry", "policy", "group"])
    df.to_csv(out / "per_run_g3.csv", index=False)
    agg.to_csv(out / "aggregate_g3.csv", index=False)

    wide = agg.assign(mode=agg["mimicry"].map(_mode))
    for metric, title in (("miss_rate", "miss rate (lower is better)"),
                          ("roc_auc_benign", "detection ROC-AUC, attacker vs benign apps")):
        table = (wide.pivot(index="policy", columns=["condition", "mode"], values=metric)
                     .reindex(index=list(dict.fromkeys(agg["policy"]))))
        print(f"\n=== median {title}, by condition and attacker mode ===")
        with pd.option_context("display.width", 160, "display.max_rows", None):
            print(table.round(2).to_string(na_rep="n/a"))
    print(f"\nwrote {out}/aggregate_g3.csv and per_run_g3.csv")
    return _exit_status(failed, continue_on_error)


def main() -> int:
    ap = argparse.ArgumentParser(description="Racing the Scanner: scheduler policy sweep")
    ap.add_argument("--policies", nargs="+", default=["all"],
                    help="policy names or 'all'. See sim/policies for the list.")
    ap.add_argument("--runs", type=int, default=int(os.environ.get("RTS_SIM_RUNS", 20)))
    ap.add_argument("--ticks", type=int, default=600)
    ap.add_argument("--seed", type=int, default=int(os.environ.get("RTS_SIM_SEED", 42)))
    ap.add_argument("--no-mimicry", action="store_true", help="attacker uses obvious hog timing")
    ap.add_argument("--condition", choices=CONDITIONS, default="coupled",
                    help="attack condition (see sim/engine.py); default: hiding + starvation")
    ap.add_argument("--g3", action="store_true",
                    help="sweep every condition in both modes (ignores --condition/--no-mimicry)")
    ap.add_argument("--smoke", action="store_true", help="tiny fast run to verify the setup")
    ap.add_argument("--continue-on-error", action="store_true",
                    help="exit 0 even if a policy fails (the CSVs then lack its rows)")
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

    cfg = SimConfig(ticks=args.ticks, seed=args.seed, mimicry=not args.no_mimicry,
                    condition=args.condition)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.g3:
        return _g3(names, cfg, args.runs, out, args.continue_on_error)

    per_run, failed = _sweep(names, cfg, args.runs)
    if not per_run:
        print("no results produced")
        return 1

    df = pd.DataFrame(per_run)
    agg = aggregate(df, ["policy", "group"]).sort_values("p95_latency", kind="stable")

    mode = _mode(cfg.mimicry)
    tag = mode if cfg.condition == "coupled" else f"{cfg.condition}_{mode}"
    df.to_csv(out / f"per_run_{tag}.csv", index=False)
    agg.to_csv(out / f"aggregate_{tag}.csv", index=False)

    print("\n=== ranked by p95 monitor latency (lower is better); median [q25, q75] over runs ===")
    table = pd.DataFrame({
        "policy": agg["policy"],
        "group": agg["group"],
        "p95_latency": [_iqr(r, "p95_latency", ".1f") for _, r in agg.iterrows()],
        "miss_rate": [_iqr(r, "miss_rate", ".2f") for _, r in agg.iterrows()],
        "auc_vs_legit": [_iqr(r, "roc_auc", ".2f") for _, r in agg.iterrows()],
        "auc_vs_benign": [_iqr(r, "roc_auc_benign", ".2f") for _, r in agg.iterrows()],
        "monitor_share": agg["monitor_share"],
        "benign_share": agg["benign_share"],
        "overhead_ms": agg["overhead_ms"].round(1),
    })
    with pd.option_context("display.width", 160, "display.max_rows", None):
        print(table.to_string(index=False))
    print(f"\nwrote {out}/aggregate_{tag}.csv and per_run_{tag}.csv")
    print(f"policies available: {len(all_policies())} (baseline + {len(augmented_policies())} "
          f"augmented + {len(reservation_names())} reservation + invariant)")
    return _exit_status(failed, args.continue_on_error)


if __name__ == "__main__":
    raise SystemExit(main())
