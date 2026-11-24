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


def _g5_csv(res):
    rows = []
    for run in range(2):
        for det, caught, fa, ms in [("default_sigs", 1, 0, 0.0), ("custom", 3, 2, 0.0), ("ai", 3, 0, 850.0)]:
            rows.append(
                dict(run_id=run, mode="mimic", detector=det, attacker="v1", benign="suite",
                     n_attackers=4, n_benign=10, caught=caught, false_alarms=fa,
                     catch_rate=caught / 4, fp_rate=fa / 10, triage_backend="stub",
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


def test_g3_writes_and_skips(dirs):
    res, fig = dirs
    assert mg.g3_attack_conditions() is False
    rows = []
    for cond in ["none", "hiding", "starvation", "coupled"]:
        for mim in [False, True]:
            for pol, grp in [("baseline", "baseline"), ("iforest", "ml-unsupervised"),
                             ("rf", "ml-supervised"), ("cgroup_weight", "reservation"),
                             ("invariant", "invariant")]:
                rows.append(dict(condition=cond, mimicry=mim, policy=pol, group=grp,
                                 miss_rate=0.5, miss_rate_q25=0.4, miss_rate_q75=0.6,
                                 p95_latency=10))
    pd.DataFrame(rows).to_csv(res / "aggregate_g3.csv", index=False)
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
    pooled = mg.pool_detection(pd.read_csv(res / "detection_g5.csv")).set_index("detector")
    assert pooled.loc["custom", "catch_rate"] == pytest.approx(6 / 8)
    assert pooled.loc["custom", "fp_rate"] == pytest.approx(4 / 20)


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
