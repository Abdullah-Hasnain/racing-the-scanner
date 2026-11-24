"""The standard Linux reservation mechanisms (#9).

They judge no one, so naive and mimicry runs are identical and their AUC is n/a.
Each is checked against what its mechanism implies, including its cost to the
benign apps.
"""

from __future__ import annotations

import importlib.util

import numpy as np
import pytest

from sim.engine import CONDITIONS, SimConfig, run_once
from sim.policies import all_policies, build_policy, reservation_names
from sim.policies.base import InvariantPolicy
from sim.policies.reservation import CgroupCpuMaxPolicy
from sim.process import attacker_profile, benign_profile, monitor_profile

HAS_TORCH = importlib.util.find_spec("torch") is not None
WINDOW = SimConfig().exposure_window
SCHEDULING = ("p50_latency", "p95_latency", "p99_latency", "miss_rate", "detection_rate",
              "monitor_share", "benign_share", "n_scans")


def _run(name: str, **cfg) -> dict:
    return run_once(build_policy(name), SimConfig(ticks=300, seed=3, **cfg)).summary()


def _procs() -> list:
    rng = np.random.default_rng(0)
    return [monitor_profile(0), *[benign_profile(100 + i, rng) for i in range(4)],
            attacker_profile(999, mimicry=True)]


@pytest.mark.parametrize("name", ["sched_fifo", "cgroup_weight", "sched_deadline"])
def test_reservation_keeps_the_monitor_safe_under_mimicry(name):
    res = _run(name)
    assert res["miss_rate"] == 0.0
    assert res["p95_latency"] <= WINDOW - 2


def test_sched_fifo_gives_the_lowest_latency_and_nearly_starves_the_benign_apps():
    fifo = _run("sched_fifo")
    others = {n: _run(n) for n in ("baseline", "elliptic", "logreg", "cgroup_cpumax",
                                   "cgroup_weight", "sched_deadline", "invariant")}
    assert fifo["p95_latency"] <= 2
    assert fifo["p95_latency"] < min(r["p95_latency"] for r in others.values())
    # The cost: the benign apps share the ~5% left over with the hog.
    assert fifo["benign_share"] < 0.01
    assert fifo["benign_share"] < min(r["benign_share"] for r in others.values()) / 10


def test_cgroup_cpumax_protects_the_monitor_with_one_tick_to_spare():
    # Every non-monitor process is capped at 20%. The hog is held at its cap, and
    # the monitor gets 1/5 of the remaining 80% by weight: 16%, so 6.25 ticks per
    # scan. Safe, but coarser than a direct 20% reservation (5 ticks).
    res = _run("cgroup_cpumax")
    assert res["monitor_share"] == pytest.approx(0.16, abs=1e-4)
    assert res["p95_latency"] == WINDOW - 1
    assert res["miss_rate"] == 0.0


def test_cgroup_cpumax_holds_every_capped_process_at_the_cap():
    procs, cfg = _procs(), SimConfig()
    weights = np.array([p.claimed_priority * p.demand for p in procs])
    out = CgroupCpuMaxPolicy().allocate(weights / weights.sum(), procs, cfg)
    assert out.sum() == pytest.approx(1.0)
    assert (out[1:] <= cfg.cpumax_cap + 1e-12).all()   # benign apps and the hog
    assert out[-1] == pytest.approx(cfg.cpumax_cap)    # the hog is held at the cap
    assert out[0] == pytest.approx(out[1])             # monitor and a benign app split the rest by weight


@pytest.mark.parametrize("condition", CONDITIONS)
@pytest.mark.parametrize("name", reservation_names())
def test_reservation_is_detection_free(name, condition):
    naive = _run(name, condition=condition, mimicry=False)
    mimic = _run(name, condition=condition, mimicry=True)
    assert {k: naive[k] for k in SCHEDULING} == {k: mimic[k] for k in SCHEDULING}
    for res in (naive, mimic):
        assert np.isnan(res["roc_auc"]) and np.isnan(res["roc_auc_benign"])


@pytest.mark.parametrize("condition", CONDITIONS)
@pytest.mark.parametrize("mimicry", [False, True])
@pytest.mark.parametrize("name", ["cgroup_weight", "sched_deadline"])
def test_twenty_percent_reservations_equal_the_invariant(name, condition, mimicry):
    # Not a different result: with an always-runnable monitor, a 20:80 cgroup
    # weight split and a fluid 0.2 SCHED_DEADLINE budget are the invariant.
    res = _run(name, condition=condition, mimicry=mimicry)
    inv = _run("invariant", condition=condition, mimicry=mimicry)
    assert {k: res[k] for k in SCHEDULING} == {k: inv[k] for k in SCHEDULING}


def test_invariant_allocation_is_unchanged_from_main():
    # engine._allocate as it was before the allocation hook (#9), verbatim.
    def main_allocate(shares, floor):
        if shares[0] >= floor:
            return shares
        others = shares.copy()
        others[0] = 0.0
        tot = others.sum()
        others = others / tot * (1.0 - floor) if tot > 0 else others
        others[0] = floor
        return others

    procs, cfg, rng = _procs(), SimConfig(), np.random.default_rng(0)
    for _ in range(500):
        w = rng.uniform(0.01, 5.0, size=len(procs))
        shares = w / w.sum()
        np.testing.assert_array_equal(InvariantPolicy().allocate(shares, procs, cfg),
                                      main_allocate(shares, cfg.floor_share))


@pytest.mark.parametrize("name", all_policies())
def test_benign_share_is_reported_for_every_policy(name):
    policy = build_policy(name)
    if policy.requires_torch and not HAS_TORCH:
        pytest.skip("torch not installed")
    res = run_once(policy, SimConfig(ticks=100, train_samples=120, seed=1)).summary()
    assert 0.0 < res["benign_share"] < 1.0
    assert res["benign_share"] + res["monitor_share"] <= 1.0 + 1e-9
