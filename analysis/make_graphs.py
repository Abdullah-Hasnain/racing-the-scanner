"""Build the figures G1-G6 from the CSVs in results/.

CSVs that need root or a real kernel (coupled_live.csv, detection_g5.csv) fall
back to their committed copies in captured/ when results/ has none. G3-G6 are
wired; each skips with a clear message when its CSV is missing. G1
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
# Committed copies of the CSVs that need root or a real kernel to produce (#44).
CAPTURED = Path(os.environ.get("RTS_CAPTURED_DIR", "./captured"))


FALLBACK_BLUE = "#47a"
GROUP_COLORS = {
    "baseline": "#888",
    "invariant": "#2a7",
    "ml-unsupervised": FALLBACK_BLUE,
    "ml-supervised": "#a55",
    "reservation": "#d90",
}
G3_CONDITIONS = ["none", "hiding", "starvation", "coupled"]
G3_POLICIES = ["baseline", "iforest", "rf", "sched_fifo", "cgroup_weight", "invariant"]
G3_LABELS = {"baseline": "EEVDF", "sched_fifo": "SCHED_FIFO", "cgroup_weight": "cpu.weight"}


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


def _src(name: str) -> Path | None:
    """A fresh results/ CSV wins over its committed copy in captured/."""
    for d in (RESULTS, CAPTURED):
        if (d / name).exists():
            return d / name
    return None


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


SIM_TO_LIVE = {"baseline": "eevdf", "sched_fifo": "sched_fifo", "cgroup_weight": "cgroup_weight"}


def g3_slowdown(sim: pd.DataFrame | None, live: pd.DataFrame | None) -> pd.DataFrame:
    """Scanner slowdown vs the no-attack condition, per condition, policy and source.

    Simulation: p95 latency over its `none` value, mimicry attacker. Real kernel:
    the scan-period ratio, scans/s under `none` over scans/s in the condition
    (median over reps), for the claimed-priority attacker. 1.0 means unharmed.
    Policies are named as in the simulation (EEVDF is `baseline`).
    """
    parts = []
    if sim is not None:
        s = sim[(sim["mimicry"] == True) & sim["policy"].isin(G3_POLICIES)]  # noqa: E712
        s = s.set_index(["policy", "condition"])["p95_latency"].unstack()
        parts.append(s.div(s["none"], axis=0).stack().rename("slowdown").reset_index().assign(source="sim"))
    if live is not None:
        if "attacker_nice" in live:
            live = live[live["attacker_nice"] == live["attacker_nice"].min()]
        r = live.groupby(["policy", "condition"])["scans_per_s"].median().unstack()
        r = (1 / r).mul(r["none"], axis=0).rename(index={v: k for k, v in SIM_TO_LIVE.items()})
        parts.append(r.stack().rename("slowdown").reset_index().assign(source="real"))
    if not parts:
        return pd.DataFrame(columns=["policy", "condition", "slowdown", "source"])
    return pd.concat(parts, ignore_index=True)


def g3_attack_conditions() -> bool:
    """G3: scanner slowdown per attack condition, simulation (solid) next to the real kernel (hatched)."""
    sim_src, live_src = _src("aggregate_g3.csv"), _src("coupled_live.csv")
    if sim_src is None and live_src is None:
        print("[G3] skip: run `python -m sim.run_experiment --policies all --g3` "
              "(and detection/coupled_live.py as root for the real-kernel bars)")
        return False
    sim = pd.read_csv(sim_src) if sim_src else None
    t = g3_slowdown(sim, pd.read_csv(live_src) if live_src else None)
    groups = dict(zip(sim["policy"], sim["group"], strict=False)) if sim is not None else {}
    groups.setdefault("baseline", "baseline")
    policies = [p for p in G3_POLICIES if p in set(t["policy"])]

    fig, axes = plt.subplots(1, len(G3_CONDITIONS), figsize=(15, 4.8), sharey=True)
    for ax, cond in zip(axes, G3_CONDITIONS, strict=True):
        for i, pol in enumerate(policies):
            color = GROUP_COLORS.get(groups.get(pol, "reservation"), FALLBACK_BLUE)
            for source, dx, hatch in [("sim", -0.2, ""), ("real", 0.2, "//")]:
                v = t[(t["policy"] == pol) & (t["condition"] == cond) & (t["source"] == source)]["slowdown"]
                if len(v):
                    ax.bar(i + dx, v.iloc[0], 0.4, color=color, hatch=hatch, edgecolor="white")
        ax.axhline(1.0, color="black", lw=0.6)
        ax.set_title(cond)
        ax.set_xticks(range(len(policies)), [G3_LABELS.get(p, p) for p in policies], rotation=40, ha="right")
    axes[0].set_ylabel("scanner slowdown vs no attack (x)")
    handles = _group_legend(groups[p] for p in policies if p in groups) + [
        Patch(facecolor="#ccc", edgecolor="white", label="simulation: p95 latency ratio (mimicry attacker)"),
        Patch(facecolor="#ccc", edgecolor="white", hatch="//",
              label="real kernel: scan period ratio (nice -20 attacker, one core)"),
    ]
    fig.suptitle("G3: how much each attack slows the scanner (1.0 = unharmed)", fontsize=11)
    fig.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, 0.94), ncol=4, fontsize=8, frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.84))
    out = _save(fig, "G3_attack_conditions.png")
    print(f"[G3] wrote {out}")
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
    src = _src("detection_g5.csv")
    if src is None:
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
    det_src = _src("detection_g5.csv")
    sched = pd.read_csv(sched_src) if sched_src.exists() else None
    triage = None
    if det_src is not None:
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
    g5_detection()
    g6_overhead()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
