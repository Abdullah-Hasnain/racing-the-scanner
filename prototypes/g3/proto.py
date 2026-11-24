"""Throwaway G3 layout prototypes for #44 Part A. Not for the repo."""
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

RES = Path(sys.argv[1]); OUT = Path(sys.argv[2])
CONDS = ["none", "hiding", "starvation", "coupled"]
SIM_POL = ["baseline", "iforest", "rf", "sched_fifo", "cgroup_weight", "invariant"]
LIVE = {"eevdf": "baseline", "cgroup_weight": "cgroup_weight", "sched_fifo": "sched_fifo"}
LABEL = {"baseline": "EEVDF", "iforest": "iforest (ML)", "rf": "rf (ML)", "sched_fifo": "SCHED_FIFO",
         "cgroup_weight": "cpu.weight", "invariant": "invariant"}
COL = {"baseline": "#888", "iforest": "#4a7fc1", "rf": "#a55", "sched_fifo": "#2a7",
       "cgroup_weight": "#2a7", "invariant": "#2a7"}

sim = pd.read_csv(RES / "aggregate_g3.csv")
sim = sim[sim["mimicry"] == True]  # noqa: E712  the attacker the headline is about
live = pd.read_csv(RES / "coupled_live.csv")
live = live[live["attacker_nice"] == -20]
live = live.assign(catches_per_s=live["catches"] / live["seconds"])
lm = live.groupby(["condition", "policy"])[["scans_per_s", "catches_per_s"]].median().reset_index()

def sim_val(cond, pol, col="miss_rate"):
    r = sim[(sim.condition == cond) & (sim.policy == pol)]
    return float(r[col].iloc[0]) if len(r) else float("nan")

def live_val(cond, pol, col):
    r = lm[(lm.condition == cond) & (lm.policy == pol)]
    return float(r[col].iloc[0]) if len(r) else float("nan")

# A: two rows, native units
fig, ax = plt.subplots(2, 4, figsize=(15, 7), sharey="row")
for j, c in enumerate(CONDS):
    ax[0][j].bar(range(len(SIM_POL)), [sim_val(c, p) for p in SIM_POL], color=[COL[p] for p in SIM_POL])
    ax[0][j].set_xticks(range(len(SIM_POL)), [LABEL[p] for p in SIM_POL], rotation=40, ha="right", fontsize=8)
    ax[0][j].set_title(c); ax[0][j].set_ylim(0, 1.05)
    pols = list(LIVE)
    base = {p: live_val("none", p, "scans_per_s") for p in pols}
    ax[1][j].bar(range(3), [1 - live_val(c, p, "scans_per_s") / base[p] for p in pols], color=[COL[LIVE[p]] for p in pols])
    ax[1][j].set_xticks(range(3), [LABEL[LIVE[p]] for p in pols], rotation=40, ha="right", fontsize=8)
    ax[1][j].set_ylim(0, 1.05)
ax[0][0].set_ylabel("simulation\nmonitor miss rate")
ax[1][0].set_ylabel("real kernel\nscans lost vs no attack")
fig.suptitle("Prototype A: simulation on top, real kernel below (each in its own unit)")
fig.tight_layout(); fig.savefig(OUT / "protoA.png", dpi=110)

# B: one shared metric, slowdown vs no attack
fig, ax = plt.subplots(1, 4, figsize=(15, 4.6), sharey=True)
order = [("baseline", "eevdf"), ("iforest", None), ("rf", None), ("sched_fifo", "sched_fifo"), ("cgroup_weight", "cgroup_weight"), ("invariant", None)]
for j, c in enumerate(CONDS):
    for i, (sp, lp) in enumerate(order):
        sv = sim_val(c, sp, "p95_latency") / sim_val("none", sp, "p95_latency")
        ax[j].bar(i - 0.2, sv, 0.4, color=COL[sp])
        if lp:
            rv = live_val("none", lp, "scans_per_s") / live_val(c, lp, "scans_per_s")
            ax[j].bar(i + 0.2, rv, 0.4, color=COL[sp], hatch="//", edgecolor="white")
    ax[j].set_xticks(range(len(order)), [LABEL[sp] for sp, _ in order], rotation=40, ha="right", fontsize=8)
    ax[j].set_title(c); ax[j].axhline(1, color="k", lw=0.6)
ax[0].set_ylabel("scanner slowdown vs no attack (x)")
from matplotlib.patches import Patch
fig.legend(handles=[Patch(facecolor="#bbb", label="simulation: p95 latency ratio (mimicry attacker)"),
                    Patch(facecolor="#bbb", hatch="//", edgecolor="white", label="real kernel: scan period ratio (nice -20 attacker)")],
           loc="upper center", ncol=2, fontsize=8, frameon=False, bbox_to_anchor=(0.5, 0.93))
fig.suptitle("Prototype B: one axis for both, slowdown vs no attack (1.0 = unharmed)")
fig.tight_layout(rect=(0, 0, 1, 0.88)); fig.savefig(OUT / "protoB.png", dpi=110)
print("wrote", OUT / "protoA.png", OUT / "protoB.png")
