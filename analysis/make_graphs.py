"""Build the figures G1-G6 from the CSVs in results/.

G3-G6 are wired; each skips with a clear message when its CSV is missing. G1
and G2 are stubbed with a message naming the memory module whose results feed
them.

Usage (see analysis/README.md):
  python -m sim.run_experiment --policies all          # results/aggregate_mimicry.csv
  python -m sim.run_experiment --policies all --g3     # results/aggregate_g3.csv
  python -m analysis.make_graphs                       # writes figures/
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import NamedTuple

import matplotlib
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

RESULTS = Path(os.environ.get("RTS_RESULTS_DIR", "./results"))
FIGURES = Path(os.environ.get("RTS_FIGURES_DIR", "./figures"))


FALLBACK_BLUE = "#47a"
GROUP_COLORS = {
    "baseline": "#888",
    "invariant": "#2a7",
    "ml-unsupervised": FALLBACK_BLUE,
    "ml-supervised": "#a55",
    "reservation": "#d90",
}
G3_CONDITIONS = ["none", "hiding", "starvation", "coupled"]
G3_POLICIES = ["baseline", "iforest", "rf", "cgroup_weight", "invariant"]


class DetectorStyle(NamedTuple):
    label: str
    color: str
    marker: str
    size: int


# One row per G5 series. Detectors often land on the same point, so each has its own
# colour, shape and size, and G5 draws the largest first. `ai` is the LLM-triaged
# series (its label gets the model name); `heuristic` is `ai` rows run with --no-llm.
DETECTORS = {
    "default_sigs": DetectorStyle("Tracee default", "#2ca02c", "s", 260),
    "custom": DetectorStyle("Tracee custom", "#ff7f0e", "o", 150),
    "ai": DetectorStyle("custom + AI", "#1f77b4", "^", 70),
    "heuristic": DetectorStyle("custom + heuristic", "#9467bd", "v", 110),
}
DEFAULT_STYLE = DetectorStyle("", "#888888", "D", 110)


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

    bar_colors = [GROUP_COLORS.get(g, FALLBACK_BLUE) for g in df["group"]]

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
    present = set(groups)
    return [Patch(color=GROUP_COLORS[g], label=g) for g in GROUP_COLORS if g in present]


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
                color=[GROUP_COLORS.get(g, FALLBACK_BLUE) for g in rows["group"].fillna("")],
                edgecolor="white", error_kw={"lw": 1, "capsize": 2},
            )
        ax.set_title(cond)
        ax.set_xticks(range(len(policies)), policies, rotation=40, ha="right")
        ax.set_ylim(0, 1.05)
    axes[0].set_ylabel("miss rate (median, IQR bars)")
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


LIVE_POLICIES = {"eevdf": "baseline", "cgroup_weight": "reservation", "sched_fifo": "reservation"}


def live_g3_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Per condition and policy: median, min and max over reps of scans/s and catches/s."""
    df = df.assign(catches_per_s=df["catches"] / df["seconds"])
    g = df.groupby(["condition", "policy"])[["scans_per_s", "catches_per_s"]]
    out = g.median()
    for agg in ("min", "max"):
        out = out.join(g.agg(agg).add_suffix(f"_{agg}"))
    return out.reset_index()


def g3_real_kernel() -> bool:
    """G3, real kernel: scanner scans/s and catches/s per attack condition and CPU policy."""
    src = RESULTS / "coupled_live.csv"
    if not src.exists():
        print("[G3-live] skip: needs coupled_live.csv from detection/coupled_live.py (root)")
        return False
    s = live_g3_summary(pd.read_csv(src))
    conds = [c for c in G3_CONDITIONS if c in set(s["condition"])]
    policies = [p for p in LIVE_POLICIES if p in set(s["policy"])]
    colors = [GROUP_COLORS[LIVE_POLICIES[p]] for p in policies]
    # Scans share one axis; catches do not, since a never-hiding attacker (none,
    # starvation) is caught on every scan and would flatten the hiding panels.
    fig, axes = plt.subplots(2, len(conds), figsize=(3.2 * len(conds), 6.5), squeeze=False)
    for ax in axes[0][1:]:
        ax.sharey(axes[0][0])
    for row, (metric, label) in enumerate([("scans_per_s", "scans per second"),
                                           ("catches_per_s", "catches per second")]):
        for ax, cond in zip(axes[row], conds, strict=True):
            r = s[s["condition"] == cond].set_index("policy").reindex(policies)
            err = [(r[metric] - r[f"{metric}_min"]).fillna(0), (r[f"{metric}_max"] - r[metric]).fillna(0)]
            ax.bar(range(len(policies)), r[metric].fillna(0), yerr=err, color=colors,
                   edgecolor="white", error_kw={"lw": 1, "capsize": 3})
            ax.set_xticks(range(len(policies)), policies if row else [], rotation=30, ha="right")
            if row == 0:
                ax.set_title(cond)
        axes[row][0].set_ylabel(f"{label}\n(median, min-max bars)")
    fig.legend(handles=_group_legend([LIVE_POLICIES[p] for p in policies]), loc="upper center",
               bbox_to_anchor=(0.5, 0.93), ncol=2, fontsize=8, frameon=False)
    fig.suptitle("G3 (real kernel): the scanner under a nice -20 attacker on one core", fontsize=11)
    fig.tight_layout(rect=(0, 0, 1, 0.89))
    out = _save(fig, "G3_real_kernel.png")
    print(f"[G3-live] wrote {out}")
    return True


def _series(row: pd.Series) -> tuple[str, str]:
    """(style key, legend label) for a G5 row, or ("", "") for an excluded one."""
    if row["detector"] != "ai":
        key = row["detector"]
        return key, DETECTORS.get(key, DEFAULT_STYLE).label or key
    backend = str(row["triage_backend"])
    if backend == "heuristic":
        return "heuristic", DETECTORS["heuristic"].label
    if backend.startswith("llm:"):
        return "ai", f"{DETECTORS['ai'].label} ({backend[4:]})"
    return "", ""  # llm-fallback:* mixes LLM and heuristic answers


def pool_detection(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Pool runs per series: sum caught / sum n_attackers, sum false_alarms / sum n_benign.

    `ai` rows split by triage backend and `llm-fallback:*` rows are dropped; returns
    the pooled points and the number of dropped rows.
    """
    df = df.copy()
    pairs = [_series(r) for _, r in df.iterrows()]
    df["style"] = [k for k, _ in pairs]
    df["label"] = [lab for _, lab in pairs]
    excluded = int((df["style"] == "").sum())
    df = df[df["style"] != ""]
    g = df.groupby(["style", "label"], as_index=False)[["caught", "n_attackers", "false_alarms", "n_benign"]].sum()
    g["catch_rate"] = g["caught"] / g["n_attackers"]
    g["fp_rate"] = g["false_alarms"] / g["n_benign"]
    return g, excluded


def g5_detection() -> bool:
    """G5: Tracee catch rate vs false-alarm rate: default, custom, custom + AI or heuristic."""
    src = RESULTS / "detection_g5.csv"
    if not src.exists():
        print("[G5] skip: needs detection_g5.csv from the detection harness")
        return False
    pooled, excluded = pool_detection(pd.read_csv(src))
    if excluded:
        print(f"[G5] excluded {excluded} llm-fallback rows")
    if pooled.empty:
        print("[G5] skip: no usable rows in detection_g5.csv")
        return False
    fig, ax = plt.subplots(figsize=(7, 5))
    pooled = pooled.assign(_size=pooled["style"].map(lambda d: DETECTORS.get(d, DEFAULT_STYLE).size))
    for r in pooled.sort_values("_size", ascending=False).itertuples():
        _, color, marker, size = DETECTORS.get(r.style, DEFAULT_STYLE)
        ax.scatter(r.fp_rate, r.catch_rate, s=size, color=color, marker=marker, zorder=3,
                   edgecolors="white", linewidths=0.8,
                   label=f"{r.label} ({r.caught}/{r.n_attackers} caught, "
                         f"{r.false_alarms}/{r.n_benign} false alarms)")
    ax.set_xlim(-0.03, 1.03)
    ax.set_ylim(-0.03, 1.03)
    ax.set_xlabel("false-alarm rate (false alarms / benign processes, pooled over runs)")
    ax.set_ylabel("catch rate (caught / attackers, pooled over runs)")
    ax.set_title("G5: Tracee detection (top-left is best)")
    ax.grid(alpha=0.3)
    ax.legend(loc="lower right", fontsize=8)
    if excluded:
        fig.text(0.01, 0.01, f"{excluded} llm-fallback rows excluded (mixed LLM and heuristic answers)",
                 fontsize=7, color="#555")
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    out = _save(fig, "G5_detection.png")
    print(f"[G5] wrote {out}")
    return True


def g6_overhead() -> bool:
    """G6: scheduler policy compute time (sim) and AI triage latency (detection)."""
    sched_src = RESULTS / "aggregate_mimicry.csv"
    det_src = RESULTS / "detection_g5.csv"
    sched = pd.read_csv(sched_src) if sched_src.exists() else None
    triage = None
    if det_src.exists():
        d = pd.read_csv(det_src)
        d = d[(d["detector"] == "ai") & d["triage_backend"].astype(str).str.startswith("llm:")]
        if len(d):
            triage = d.groupby("triage_backend")["triage_ms_mean"].mean()
    if sched is None:
        print("[G6] skip scheduler part: aggregate_mimicry.csv missing")
    if triage is None:
        print("[G6] skip triage part: no `llm:*` ai rows in detection_g5.csv "
              "(heuristic latency is not AI overhead, llm-fallback latency includes timeouts)")
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
        ax.barh(sched["policy"], sched["overhead_ms"], color=[GROUP_COLORS.get(g, FALLBACK_BLUE) for g in sched["group"]])
        ax.invert_yaxis()
        ax.set_xlabel("policy decision code, real wall-clock per run (ms)")
        ax.set_title("G6a: scheduler policy compute time")
        legend_handles = _group_legend(sched["group"])
    if triage is not None:
        ax = axes.pop(0)
        ax.bar(triage.index.astype(str), triage.values, color="C2")
        ax.set_ylabel("triage latency per process (ms, mean)")
        ax.set_title("G6b: AI triage overhead")
    if sched is not None:
        fig.legend(handles=legend_handles, loc="lower center", ncol=5, fontsize=8, frameon=False)
        fig.text(0.01, 0.01, "sim times only policy.multipliers, not policy.allocate: "
                 "reservation policies and the invariant show ~0 by construction",
                 fontsize=7, color="#555")
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
    g3_real_kernel()
    g5_detection()
    g6_overhead()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
