"""Build the figures G1-G6 from the CSVs in results/.

G3-G6 are wired; each skips with a clear message when its CSV is missing. G1
and G2 are stubbed with a message naming the memory module whose results feed
them.

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


GROUP_COLORS = {
    "baseline": "#888",
    "invariant": "#2a7",
    "ml-unsupervised": "#47a",
    "ml-supervised": "#a55",
    "reservation": "#d90",
}
G3_CONDITIONS = ["none", "hiding", "starvation", "coupled"]
G3_POLICIES = ["baseline", "iforest", "rf", "cgroup_weight", "invariant"]
DETECTOR_LABELS = {"default_sigs": "Tracee default", "custom": "Tracee custom", "ai": "Tracee custom + AI"}
DECISION_TICKS = 600  # ticks per sim run; overhead_ms is summed over them


def _save(fig, name: str) -> Path:
    FIGURES.mkdir(parents=True, exist_ok=True)
    out = FIGURES / name
    fig.savefig(out, dpi=130)
    plt.close(fig)
    return out


def g4_policy_comparison() -> bool:
    """G4: monitor p95 latency and miss rate across every scheduling policy."""
    src = RESULTS / "aggregate_mimicry.csv"
    if not src.exists():
        print("[G4] skip: run `python -m sim.run_experiment --policies all` first")
        return False
    df = pd.read_csv(src).sort_values("p95_latency")

    bar_colors = [GROUP_COLORS.get(g, "#47a") for g in df["group"]]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    ax1.barh(df["policy"], df["p95_latency"], color=bar_colors)
    ax1.set_xlabel("p95 monitor scan latency (ticks, lower is better)")
    ax1.set_title("G4a: scheduler policy vs monitor latency under mimicry")
    ax1.invert_yaxis()

    ax2.barh(df["policy"], df["miss_rate"], color=bar_colors)
    ax2.set_xlabel("miss rate (fraction of scans that missed the window)")
    ax2.set_title("G4b: detection miss rate by policy")
    ax2.invert_yaxis()

    fig.legend(handles=_group_legend(df["group"]), loc="lower center", ncol=5, fontsize=8, frameon=False)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    out = _save(fig, "G4_policy_comparison.png")
    print(f"[G4] wrote {out}")
    return True


def _group_legend(groups) -> list:
    from matplotlib.patches import Patch

    return [Patch(color=GROUP_COLORS[g], label=g) for g in GROUP_COLORS if g in set(groups)]


def g3_attack_conditions() -> bool:
    """G3: miss rate per attack condition, naive vs mimicry, for a policy subset."""
    src = RESULTS / "aggregate_g3.csv"
    if not src.exists():
        print("[G3] skip: run `python -m sim.run_experiment --policies all --g3` first")
        return False
    df = pd.read_csv(src)
    df = df[df["policy"].isin(G3_POLICIES)]
    policies = [p for p in G3_POLICIES if p in set(df["policy"])]

    fig, axes = plt.subplots(1, len(G3_CONDITIONS), figsize=(14, 4.5), sharey=True)
    width = 0.4
    for ax, cond in zip(axes, G3_CONDITIONS, strict=True):
        sub = df[df["condition"] == cond]
        for k, (mimicry, hatch) in enumerate([(False, ""), (True, "//")]):
            rows = sub[sub["mimicry"] == mimicry].set_index("policy").reindex(policies)
            x = [i + (k - 0.5) * width for i in range(len(policies))]
            err = None
            if {"miss_rate_q25", "miss_rate_q75"} <= set(rows.columns):
                err = [
                    (rows["miss_rate"] - rows["miss_rate_q25"]).clip(lower=0).fillna(0),
                    (rows["miss_rate_q75"] - rows["miss_rate"]).clip(lower=0).fillna(0),
                ]
            ax.bar(
                x, rows["miss_rate"].fillna(0), width, yerr=err, hatch=hatch,
                color=[GROUP_COLORS.get(g, "#47a") for g in rows["group"].fillna("")],
                edgecolor="white", error_kw={"lw": 1, "capsize": 2},
            )
        ax.set_title(cond)
        ax.set_xticks(range(len(policies)), policies, rotation=40, ha="right")
        ax.set_ylim(0, 1.05)
    axes[0].set_ylabel("miss rate (median, IQR bars)")
    from matplotlib.patches import Patch

    handles = _group_legend(df["group"]) + [
        Patch(facecolor="#ccc", edgecolor="white", label="naive attacker"),
        Patch(facecolor="#ccc", edgecolor="white", hatch="//", label="mimicry attacker"),
    ]
    fig.suptitle("G3: miss rate by attack condition (mimicry only matters where the attacker hogs)", fontsize=11)
    fig.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, 0.94), ncol=len(handles), fontsize=8, frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.86))
    out = _save(fig, "G3_attack_conditions.png")
    print(f"[G3] wrote {out}")
    return True


def pool_detection(df: pd.DataFrame) -> pd.DataFrame:
    """Pool runs per detector: sum caught / sum n_attackers, sum false_alarms / sum n_benign."""
    g = df.groupby("detector", as_index=False)[["caught", "n_attackers", "false_alarms", "n_benign"]].sum()
    g["catch_rate"] = g["caught"] / g["n_attackers"]
    g["fp_rate"] = g["false_alarms"] / g["n_benign"]
    return g


def g5_detection() -> bool:
    """G5: Tracee catch rate vs false-alarm rate, default vs custom vs custom + AI."""
    src = RESULTS / "detection_g5.csv"
    if not src.exists():
        print("[G5] skip: needs detection_g5.csv from the detection harness")
        return False
    pooled = pool_detection(pd.read_csv(src))
    fig, ax = plt.subplots(figsize=(6.5, 5))
    for i, r in enumerate(pooled.itertuples()):
        ax.scatter(r.fp_rate, r.catch_rate, s=90, color=f"C{i}", zorder=3,
                   label=f"{DETECTOR_LABELS.get(r.detector, r.detector)} "
                         f"({r.caught}/{r.n_attackers} caught, {r.false_alarms}/{r.n_benign} false alarms)")
    ax.set_xlim(-0.03, 1.03)
    ax.set_ylim(-0.03, 1.03)
    ax.set_xlabel("false-alarm rate (false alarms / benign processes, pooled over runs)")
    ax.set_ylabel("catch rate (caught / attackers, pooled over runs)")
    ax.set_title("G5: Tracee detection (top-left is best)")
    ax.grid(alpha=0.3)
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    out = _save(fig, "G5_detection.png")
    print(f"[G5] wrote {out}")
    return True


def g6_overhead() -> bool:
    """G6: scheduler decision overhead (sim) and AI triage latency (detection)."""
    sched_src = RESULTS / "aggregate_mimicry.csv"
    det_src = RESULTS / "detection_g5.csv"
    sched = pd.read_csv(sched_src) if sched_src.exists() else None
    triage = None
    if det_src.exists():
        d = pd.read_csv(det_src)
        d = d[d["detector"] == "ai"]
        if len(d):
            triage = d.groupby("triage_backend")["triage_ms_mean"].mean()
    if sched is None:
        print("[G6] skip scheduler part: aggregate_mimicry.csv missing")
    if triage is None:
        print("[G6] skip triage part: no `ai` rows in detection_g5.csv")
    if sched is None and triage is None:
        return False

    legend_handles: list = []
    n = (sched is not None) + (triage is not None)
    widths = [3 if sched is not None else 0, 1 if triage is not None else 0]
    fig, axes = plt.subplots(1, n, figsize=(6.5 * n, 5.5), gridspec_kw={"width_ratios": [w for w in widths if w]})
    axes = [axes] if n == 1 else list(axes)
    if sched is not None:
        ax = axes.pop(0)
        sched = sched.sort_values("overhead_ms")
        ax.barh(sched["policy"], sched["overhead_ms"], color=[GROUP_COLORS.get(g, "#47a") for g in sched["group"]])
        ax.invert_yaxis()
        ax.set_xlabel(f"scheduler decision time per {DECISION_TICKS}-tick run (ms, sim)")
        ax.set_title("G6a: scheduler overhead")
        sec = ax.secondary_xaxis("top", functions=(lambda x: x / DECISION_TICKS * 1000, lambda x: x * DECISION_TICKS / 1000))
        sec.set_xlabel("per decision (microseconds)")
        legend_handles = _group_legend(sched["group"])
    if triage is not None:
        ax = axes.pop(0)
        ax.bar(triage.index.astype(str), triage.values, color="C2")
        ax.set_ylabel("triage latency per process (ms, mean)")
        ax.set_title("G6b: AI triage overhead")
    if sched is not None:
        fig.legend(handles=legend_handles, loc="lower center", ncol=5, fontsize=8, frameon=False)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    out = _save(fig, "G6_overhead.png")
    print(f"[G6] wrote {out}")
    return True


def _stub(tag: str, needs: str) -> None:
    print(f"[{tag}] skip: needs results from {needs}")


def main() -> int:
    g4_policy_comparison()
    _stub("G1", "memory/scanner (catch rate vs scan interval)")
    _stub("G2", "memory payloads (slowdown vs evasion Pareto)")
    g3_attack_conditions()
    g5_detection()
    g6_overhead()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
