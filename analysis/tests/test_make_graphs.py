"""Each figure writes its PNG from a tiny CSV and skips cleanly without one."""

from __future__ import annotations

import pandas as pd
import pytest

from analysis import make_graphs as mg


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    res, fig = tmp_path / "results", tmp_path / "figures"
    res.mkdir()
    monkeypatch.setattr(mg, "RESULTS", res)
    monkeypatch.setattr(mg, "FIGURES", fig)
    monkeypatch.setattr(mg, "CAPTURED", tmp_path / "captured")
    return res, fig


def _png(path):
    return path.exists() and path.read_bytes()[:4] == b"\x89PNG"


def _mimicry_csv(res):
    pd.DataFrame(
        {
            "policy": ["baseline", "iforest", "rf", "cgroup_weight", "invariant"],
            "group": ["baseline", "ml-unsupervised", "ml-supervised", "reservation", "invariant"],
            "miss_rate": [0.9, 0.8, 0.7, 0.0, 0.0],
            "p95_latency": [50, 40, 30, 8, 6],
            "overhead_ms": [1.0, 20.0, 15.0, 0.5, 0.5],
        }
    ).to_csv(res / "aggregate_mimicry.csv", index=False)


def _g5_csv(res, ai_backend="llm:m1"):
    rows = []
    for run in range(2):
        for det, caught, fa, ms in [("default_sigs", 1, 0, 0.0), ("custom", 3, 2, 0.0), ("ai", 3, 0, 850.0)]:
            rows.append(
                dict(run_id=run, mode="mimic", detector=det, attacker="v1", benign="suite",
                     n_attackers=4, n_benign=10, caught=caught, false_alarms=fa,
                     catch_rate=caught / 4, fp_rate=fa / 10,
                     triage_backend=ai_backend if det == "ai" else "llm:m1",
                     triage_ms_mean=ms)
            )
    pd.DataFrame(rows).to_csv(res / "detection_g5.csv", index=False)


def test_g4_writes_with_reservation_group(dirs):
    res, fig = dirs
    _mimicry_csv(res)
    assert mg.g4_policy_comparison()
    assert _png(fig / "G4_policy_comparison.png")


def test_g4_reservation_has_its_own_colour():
    assert mg.GROUP_COLORS["reservation"] not in (
        mg.GROUP_COLORS["ml-unsupervised"], mg.GROUP_COLORS["ml-supervised"],
        mg.GROUP_COLORS["baseline"], mg.GROUP_COLORS["invariant"])


def _g3_csv(res):
    rows = []
    for cond in ["none", "hiding", "starvation", "coupled"]:
        for mim in [False, True]:
            for pol, grp, slow in [("baseline", "baseline", 7.0), ("iforest", "ml-unsupervised", 5.0),
                                   ("rf", "ml-supervised", 6.0), ("sched_fifo", "reservation", 1.0),
                                   ("cgroup_weight", "reservation", 1.0), ("invariant", "invariant", 1.0)]:
                hurt = mim and cond in ("starvation", "coupled")
                rows.append(dict(condition=cond, mimicry=mim, policy=pol, group=grp,
                                 miss_rate=0.5, p95_latency=4.0 * (slow if hurt else 1.0)))
    pd.DataFrame(rows).to_csv(res / "aggregate_g3.csv", index=False)


def test_g3_writes_and_skips(dirs):
    res, fig = dirs
    assert mg.g3_attack_conditions() is False
    _g3_csv(res)
    assert mg.g3_attack_conditions() is True
    assert _png(fig / "G3_attack_conditions.png")


def test_g5_writes_and_skips(dirs):
    res, fig = dirs
    assert mg.g5_detection() is False
    _g5_csv(res)
    assert mg.g5_detection() is True
    assert _png(fig / "G5_detection.png")


def test_g5_pools_over_runs(dirs):
    res, _ = dirs
    _g5_csv(res)
    pooled, excluded = mg.pool_detection(pd.read_csv(res / "detection_g5.csv"))
    pooled = pooled.set_index("style")
    assert excluded == 0
    assert pooled.loc["custom", "catch_rate"] == pytest.approx(6 / 8)
    assert pooled.loc["custom", "fp_rate"] == pytest.approx(4 / 20)
    assert pooled.loc["ai", "label"] == "custom + AI (m1)"


def test_g5_labels_heuristic_and_drops_llm_fallback(dirs):
    res, _ = dirs
    _g5_csv(res, ai_backend="heuristic")
    pooled, excluded = mg.pool_detection(pd.read_csv(res / "detection_g5.csv"))
    assert excluded == 0
    assert set(pooled["style"]) == {"default_sigs", "custom", "heuristic"}
    _g5_csv(res, ai_backend="llm-fallback:m1")
    pooled, excluded = mg.pool_detection(pd.read_csv(res / "detection_g5.csv"))
    assert excluded == 2
    assert "ai" not in set(pooled["style"])


def test_g6_triage_ignores_non_llm_rows(dirs):
    res, _ = dirs
    _g5_csv(res, ai_backend="heuristic")
    assert mg.g6_overhead() is False  # heuristic latency is not AI overhead


def test_g6_all_parts_missing_skips(dirs):
    assert mg.g6_overhead() is False


def test_g6_sched_only_and_triage_only_and_both(dirs):
    res, fig = dirs
    _mimicry_csv(res)
    assert mg.g6_overhead() is True
    assert _png(fig / "G6_overhead.png")
    (fig / "G6_overhead.png").unlink()
    (res / "aggregate_mimicry.csv").unlink()
    _g5_csv(res)
    assert mg.g6_overhead() is True
    assert _png(fig / "G6_overhead.png")
    _mimicry_csv(res)
    assert mg.g6_overhead() is True


def test_g6_omits_stale_zero_by_construction_footnote(dirs, monkeypatch):
    res, fig = dirs
    _mimicry_csv(res)
    texts = []
    orig_save = mg._save

    def capture_save(figure, name):
        texts.extend(t.get_text() for t in figure.texts)
        return orig_save(figure, name)

    monkeypatch.setattr(mg, "_save", capture_save)
    assert mg.g6_overhead() is True
    assert _png(fig / "G6_overhead.png")
    assert not any("by construction" in t.lower() or "not policy.allocate" in t.lower() for t in texts)


def _live_csv(res):
    rows = []
    for rep, (scans, catches) in enumerate([(200, 30), (240, 40), (220, 35)]):
        for cond in ["none", "starvation", "hiding", "coupled"]:
            for pol in ["eevdf", "cgroup_weight", "sched_fifo"]:
                starved = pol == "eevdf" and cond in ("starvation", "coupled")
                n = scans if starved else 540
                rows.append(dict(rep=rep, condition=cond, policy=pol, seconds=20.0, scans=n,
                                 catches=n if cond in ("none", "starvation") else catches,
                                 scans_per_s=n / 20))
    pd.DataFrame(rows).to_csv(res / "coupled_live.csv", index=False)


def test_g3_slowdown_is_relative_to_no_attack_in_both_sources(dirs):
    res, _ = dirs
    _g3_csv(res)
    _live_csv(res)
    t = mg.g3_slowdown(pd.read_csv(res / "aggregate_g3.csv"), pd.read_csv(res / "coupled_live.csv"))
    t = t.set_index(["source", "policy", "condition"])["slowdown"]
    assert t[("sim", "baseline", "starvation")] == 7.0  # mimicry attacker only
    assert t[("sim", "cgroup_weight", "coupled")] == 1.0
    assert t[("real", "baseline", "none")] == 1.0  # eevdf is named baseline, as in the sim
    assert t[("real", "baseline", "coupled")] == 27.0 / 11.0  # median 540/20 over median 220/20
    assert t[("real", "sched_fifo", "coupled")] == 1.0
    assert ("real", "iforest", "coupled") not in t


def test_g3_slowdown_keeps_only_the_claimed_priority_attacker(dirs):
    live = pd.DataFrame(dict(policy="eevdf", condition=["none", "coupled", "none", "coupled"],
                             attacker_nice=[-20, -20, 0, 0], scans_per_s=[27.0, 9.0, 27.0, 27.0]))
    t = mg.g3_slowdown(None, live).set_index(["policy", "condition"])["slowdown"]
    assert t[("baseline", "coupled")] == 3.0


def test_g3_draws_real_kernel_alone_and_reads_captured(dirs, tmp_path):
    _, fig = dirs
    cap = tmp_path / "captured"
    cap.mkdir()
    _live_csv(cap)
    assert mg.g3_attack_conditions() is True
    assert _png(fig / "G3_attack_conditions.png")


def test_results_csv_wins_over_captured(dirs, tmp_path):
    res, _ = dirs
    cap = tmp_path / "captured"
    cap.mkdir()
    (cap / "detection_g5.csv").write_text("x\n")
    assert mg._src("detection_g5.csv") == cap / "detection_g5.csv"
    (res / "detection_g5.csv").write_text("x\n")
    assert mg._src("detection_g5.csv") == res / "detection_g5.csv"
    assert mg._src("missing.csv") is None


def _g1_csv(path):
    rows = []
    for rep in range(3):
        for interval in [0.05, 0.15, 0.5, 1.5, 5.0]:
            for variant, dwells in [("v1", [0]), ("v2", [1, 5, 10, 25]), ("v3", [1, 5, 10, 25]), ("v4", [0])]:
                for dwell in dwells:
                    rate = {"v1": 1.0, "v4": 0.0}.get(variant, min(1.0, dwell / 100 + 0.01 * rep))
                    rows.append(dict(run_id=f"r{rep}", rep=rep, variant=variant, dwell_ms=dwell,
                                     interval_s=interval, pattern="seq", duration_s=10, scans=100,
                                     catches=round(rate * 100), catch_rate=rate, miss_rate=1 - rate,
                                     p50_scan_ms=1, p95_scan_ms=2, p99_scan_ms=3, max_entropy=5.6))
    pd.DataFrame(rows).to_csv(path / "g1_scan.csv", index=False)


def _g2_csv(path):
    rows = []
    for rep in range(3):
        # V2's SIGSEGV faults never reach /proc minflt, so its minflt stays near 0
        for variant, dwell, slow, evade, faults in [("v1", 0, 1.0, 0.0, 0), ("v2", 1, 40.0, 0.95, 5000),
                                                    ("v2", 25, 8.0, 0.6, 900), ("v3", 10, 20.0, 0.9, 3000),
                                                    ("v4", 0, 1.1, 1.0, 2)]:
            rows.append(dict(run_id=f"r{rep}", rep=rep, variant=variant, dwell_ms=dwell, pattern="seq",
                             duration_s=5, accesses=1000, accesses_per_s=200, slowdown_vs_v1=slow + rep,
                             faults=faults, faults_per_s=faults / 5, minflt=3, evasion_rate=evade,
                             catch_rate=1 - evade, p95_scan_ms=2))
    pd.DataFrame(rows).to_csv(path / "g2_pareto.csv", index=False)


def test_g1_summary_is_median_catch_rate_per_variant_dwell_interval(dirs):
    res, _ = dirs
    _g1_csv(res)
    s = mg.g1_summary(pd.read_csv(res / "g1_scan.csv")).set_index(["variant", "dwell_ms", "interval_s"])
    assert s.loc[("v2", 10, 0.5), "catch_rate"] == pytest.approx(0.11)  # median of 0.10, 0.11, 0.12
    assert s.loc[("v2", 10, 0.5), "q25"] == pytest.approx(0.105)
    assert s.loc[("v1", 0, 5.0), "catch_rate"] == 1.0


def test_g1_writes_and_skips(dirs):
    res, fig = dirs
    assert mg.g1_catch_rate() is False
    _g1_csv(res)
    assert mg.g1_catch_rate() is True
    assert _png(fig / "G1_catch_rate.png")


def test_g2_pareto_front_keeps_only_undominated_points(dirs):
    res, _ = dirs
    _g2_csv(res)
    s = mg.g2_summary(pd.read_csv(res / "g2_pareto.csv"))
    front = s[s["pareto"]].set_index(["variant", "dwell_ms"])
    # v4 evades everything at ~1x cost, so it dominates every V2/V3 setting
    assert list(front.index) == [("v1", 0), ("v4", 0)]
    assert s.set_index(["variant", "dwell_ms"]).loc[("v2", 1), "slowdown_vs_v1"] == 41.0  # median over reps
    assert s.set_index(["variant", "dwell_ms"]).loc[("v2", 1), "faults_per_s"] == 1000.0  # not minflt


def test_g2_writes_and_skips_and_reads_captured(dirs, tmp_path):
    _, fig = dirs
    assert mg.g2_pareto() is False
    cap = tmp_path / "captured"
    cap.mkdir()
    _g2_csv(cap)
    assert mg.g2_pareto() is True
    assert _png(fig / "G2_pareto.png")


def test_g1_and_g2_keep_v1_v4_rows_with_an_empty_dwell(dirs):
    res, _ = dirs
    _g1_csv(res)
    _g2_csv(res)
    g1 = pd.read_csv(res / "g1_scan.csv")
    g1.loc[g1["variant"].isin(["v1", "v4"]), "dwell_ms"] = None
    g2 = pd.read_csv(res / "g2_pareto.csv")
    g2.loc[g2["variant"].isin(["v1", "v4"]), "dwell_ms"] = None
    assert {"v1", "v4"} <= set(mg.g1_summary(g1)["variant"])
    assert {"v1", "v4"} <= set(mg.g2_summary(g2)["variant"])
