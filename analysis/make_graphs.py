"""Build the figures G1-G6 from the CSVs in results/.

CSVs that need root or a real kernel (g1_scan.csv, g2_pareto.csv, coupled_live.csv,
detection_g5.csv) fall back to their committed copies in captured/ when results/
has none. Every figure skips with a clear message when its CSV is missing.

Usage (see analysis/README.md):
  python -m sim.run_experiment --policies all          # results/aggregate_mimicry.csv
  python -m sim.run_experiment --policies all --g3     # results/aggregate_g3.csv
  python -m analysis.make_graphs                       # writes figures/
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import NamedTuple

import matplotlib
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402


def _default_dir(env: str, name: str) -> Path:
    """$env if set, else <repo>/name, so the figures land in the same place from any cwd."""
    return Path(os.environ.get(env) or Path(__file__).resolve().parent.parent / name)


RESULTS = _default_dir("RTS_RESULTS_DIR", "results")
FIGURES = _default_dir("RTS_FIGURES_DIR", "figures")
# Committed copies of the CSVs that need root or a real kernel to produce (#44).
CAPTURED = _default_dir("RTS_CAPTURED_DIR", "captured")


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


def _drop_zero(df: pd.DataFrame, cols: list[str], fig: str) -> pd.DataFrame:
    """Drop rows whose denominator is 0, saying so, rather than plot a silent NaN."""
    bad = (df[cols] <= 0).any(axis=1)
    if bad.any():
        print(f"[{fig}] dropped {int(bad.sum())} rows with {' or '.join(cols)} = 0", file=sys.stderr)
    return df[~bad]


def _finite(t: pd.DataFrame, fig: str) -> pd.DataFrame:
    """Drop the inf/NaN ratios a zero baseline gives, saying so."""
    bad = ~t["slowdown"].abs().lt(float("inf"))
    if bad.any():
        print(f"[{fig}] dropped {int(bad.sum())} slowdowns with a zero or missing baseline", file=sys.stderr)
    return t[~bad]


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
        parts.append(_finite(s.div(s["none"], axis=0).stack().rename("slowdown").reset_index(), "G3")
                     .assign(source="sim"))
    if live is not None:
        if "attacker_nice" in live:
            live = live[live["attacker_nice"] == live["attacker_nice"].min()]
        r = live.groupby(["policy", "condition"])["scans_per_s"].median().unstack()
        r = (1 / r).mul(r["none"], axis=0).rename(index={v: k for k, v in SIM_TO_LIVE.items()})
        parts.append(_finite(r.stack().rename("slowdown").reset_index(), "G3").assign(source="real"))
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
    if sim_src is None:
        print("[G3] warning: aggregate_g3.csv missing, drawing the real-kernel bars only; "
              "run `python -m sim.run_experiment --policies all --runs 20 --g3`", file=sys.stderr)
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
    handles = _group_legend(groups.get(p, "reservation") for p in policies) + [
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


VARIANT_COLORS = {"v1": "#888", "v2": "#47a", "v3": "#a55", "v4": "#2a7"}


def wilson_interval(catches: int, scans: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for catches / scans; stays inside [0, 1] at low n."""
    if scans == 0:
        return 0.0, 1.0
    p = catches / scans
    denom = 1 + z * z / scans
    centre = (p + z * z / (2 * scans)) / denom
    half = z * ((p * (1 - p) / scans + z * z / (4 * scans * scans)) ** 0.5) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def g1_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Catch rate per variant, dwell and interval, pooling every scan of the cell's reps
    (sum(catches) / sum(scans)), with a 95% Wilson interval. At long intervals a run gets
    only a handful of scans, so a median of per-run rates jumps between 0, 1/7 and 1/4."""
    df = df.assign(dwell_ms=df["dwell_ms"].fillna(0))  # V1/V4 have no dwell
    out = df.groupby(["variant", "dwell_ms", "interval_s"])[["catches", "scans"]].sum().reset_index()
    out = _drop_zero(out, ["scans"], "G1")
    out["catch_rate"] = out["catches"] / out["scans"]
    bounds = [wilson_interval(c, n) for c, n in zip(out["catches"], out["scans"], strict=True)]
    out["lo"], out["hi"] = [b[0] for b in bounds], [b[1] for b in bounds]
    return out


def g1_catch_rate() -> bool:
    """G1: per-scan catch rate vs scan interval, one panel per hiding variant, one line per dwell."""
    src = _src("g1_scan.csv")
    if src is None:
        print("[G1] skip: needs g1_scan.csv from the memory G1 sweep (#4)")
        return False
    s = g1_summary(pd.read_csv(src))
    hiders = [v for v in ("v2", "v3") if v in set(s["variant"])]
    fig, axes = plt.subplots(1, max(len(hiders), 1), figsize=(6 * max(len(hiders), 1), 4.5),
                             sharey=True, squeeze=False)
    for ax, v in zip(axes[0], hiders, strict=False):
        rows = s[s["variant"] == v]
        for dwell, d in rows.groupby("dwell_ms"):
            ax.errorbar(d["interval_s"], d["catch_rate"],
                        yerr=[(d["catch_rate"] - d["lo"]).clip(lower=0), (d["hi"] - d["catch_rate"]).clip(lower=0)],
                        marker="o", capsize=2, label=f"dwell {dwell:g} ms")
        for ref, style in (("v1", "--"), ("v4", ":")):
            r = s[s["variant"] == ref].groupby("interval_s")["catch_rate"].median()
            if len(r):
                ax.plot(r.index, r.values, style, color=VARIANT_COLORS[ref], label=f"{ref.upper()} (reference)")
        ax.set_xscale("log")
        ax.set_title(v.upper())
        ax.set_xlabel("scan interval (s, log)")
        ax.set_ylim(-0.03, 1.03)
        ax.legend(fontsize=8)
    axes[0][0].set_ylabel("catch rate (all scans pooled, 95% Wilson bars)")
    n = s.groupby("interval_s")["scans"].median()
    fig.text(0.01, 0.01, "scans per cell (median over variants): "
             + ", ".join(f"{i:g} s: {int(k)}" for i, k in n.items())
             + ". Fewer scans at long intervals give wider bars, not a trend.", fontsize=7)
    fig.suptitle("G1: how often the RAM scanner catches the hidden marker", fontsize=11)
    fig.tight_layout(rect=(0, 0.04, 1, 0.94))  # room for the footnote and the title
    out = _save(fig, "G1_catch_rate.png")
    print(f"[G1] wrote {out}")
    return True


def g2_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Median slowdown, evasion and faults/s per variant and dwell, with the Pareto front.

    Faults are the payload's own count (`faults_per_s`), not /proc minflt: V2's
    SIGSEGV faults never reach min_flt, so minflt would show V2 at zero.

    A setting is on the front when no other setting is at least as cheap for the
    attacker (slowdown vs V1) and at least as evasive, and strictly better in one.
    """
    df = df.assign(dwell_ms=df["dwell_ms"].fillna(0))
    s = df.groupby(["variant", "dwell_ms"])[["slowdown_vs_v1", "evasion_rate", "faults_per_s"]].median()
    s = s.reset_index()
    slow, ev = s["slowdown_vs_v1"].to_numpy(), s["evasion_rate"].to_numpy()
    s["pareto"] = [
        not any((slow[j] <= slow[i]) and (ev[j] >= ev[i]) and (slow[j] < slow[i] or ev[j] > ev[i])
                for j in range(len(s)))
        for i in range(len(s))
    ]
    return s


def g2_pareto() -> bool:
    """G2: the attacker's cost (slowdown vs V1) against what it buys (evasion), plus page faults."""
    src = _src("g2_pareto.csv")
    if src is None:
        print("[G2] skip: needs g2_pareto.csv from the memory G2 sweep (#5)")
        return False
    s = g2_summary(pd.read_csv(src))
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.8), gridspec_kw={"width_ratios": [3, 2]})
    for v, d in s.groupby("variant"):
        ax1.scatter(d["slowdown_vs_v1"], d["evasion_rate"], color=VARIANT_COLORS.get(v, FALLBACK_BLUE),
                    s=60, label=v.upper(), zorder=3)
        left = v == "v2"  # V2 and V3 sit side by side, so label them on opposite sides
        for _, r in d.iterrows():
            if r["dwell_ms"]:
                ax1.annotate(f"{r['dwell_ms']:g} ms", (r["slowdown_vs_v1"], r["evasion_rate"]),
                             textcoords="offset points", xytext=(-7 if left else 7, -3),
                             ha="right" if left else "left", fontsize=7)
    # Ring the front's points rather than joining them: when V1 and V4 are the whole
    # front they share x = 1, and a step line between them hides under their markers.
    front = s[s["pareto"]]
    ax1.scatter(front["slowdown_vs_v1"], front["evasion_rate"], s=220, facecolors="none",
                edgecolors="black", linewidths=1.0, zorder=4,
                label="Pareto front (no setting both cheaper and more evasive)")
    ax1.set_xscale("log")
    ax1.set_xlabel("attacker slowdown vs V1 (x, log)")
    ax1.set_ylabel("evasion rate (1 - catch rate, scanner every 37 ms)")
    ax1.set_ylim(-0.03, 1.03)
    ax1.legend(fontsize=8)
    labels = [f"{v.upper()} {d:g}ms" if d else v.upper() for v, d in zip(s["variant"], s["dwell_ms"], strict=True)]
    ax2.bar(range(len(s)), s["faults_per_s"], color=[VARIANT_COLORS.get(v, FALLBACK_BLUE) for v in s["variant"]])
    ax2.set_xticks(range(len(s)), labels, rotation=45, ha="right", fontsize=8)
    ax2.set_ylabel("payload faults per second (median)")
    ax2.set_yscale("symlog")
    ax2.set_ylim(0, max(1.0, s["faults_per_s"].max()) * 4)  # headroom above the tallest bar
    fig.suptitle("G2: what hiding costs the attacker", fontsize=11)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    out = _save(fig, "G2_pareto.png")
    print(f"[G2] wrote {out}")
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
    g = _drop_zero(g, ["n_attackers", "n_benign"], "G5")
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
        # log, so the reservations' few ms show next to the ML policies' hundreds
        ax.set_xscale("log" if (sched["overhead_ms"] > 0).all() else "symlog")
        ax.set_xlabel("policy compute time (decide + allocate), real wall-clock per run (ms, log)")
        ax.set_title("G6a: scheduler policy compute time")
        legend_handles = _group_legend(sched["group"])
    if triage is not None:
        ax = axes.pop(0)
        ax.bar(triage.index.astype(str).str.removeprefix("llm:"), triage.values, color="C2")
        ax.set_ylabel("triage latency per process (ms, mean)")
        ax.set_title("G6b: AI triage overhead")
    if sched is not None:
        fig.legend(handles=legend_handles, loc="lower center", ncol=5, fontsize=8, frameon=False)
    fig.tight_layout(rect=(0, 0.05 if sched is not None else 0, 1, 1))
    out = _save(fig, "G6_overhead.png")
    print(f"[G6] wrote {out}")
    return True


def main() -> int:
    g4_policy_comparison()
    g1_catch_rate()
    g2_pareto()
    g3_attack_conditions()
    g5_detection()
    g6_overhead()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
