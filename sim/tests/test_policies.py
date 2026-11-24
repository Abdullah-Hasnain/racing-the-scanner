"""Validation of the augmented policies (#6): each one trains and runs in the
harness, and each is calibrated as docs/architecture.md describes: it demotes the
naive hog and leaves the monitor alone. Mimicry is deliberately absent; how the
policies fare against it is the experiment, not a test.
"""

from __future__ import annotations

import importlib.util

import numpy as np
import pytest

from sim.engine import SimConfig, _build_training, run_once
from sim.policies import augmented_policies, build_policy
from sim.policies.ml import KnnOutlier
from sim.process import attacker_profile, monitor_profile

HAS_TORCH = importlib.util.find_spec("torch") is not None


def _build(name: str):
    policy = build_policy(name)
    if policy.requires_torch and not HAS_TORCH:
        pytest.skip("torch not installed")
    return policy


@pytest.mark.parametrize("name", augmented_policies())
def test_policy_trains_and_runs_in_the_harness(name):
    res = run_once(_build(name), SimConfig(ticks=200, train_samples=120, seed=1)).summary()
    assert res["n_scans"] > 0
    assert 0.0 < res["monitor_share"] < 1.0
    assert res["overhead_ms"] > 0.0


@pytest.mark.parametrize("name", augmented_policies())
def test_policy_demotes_naive_hog_and_spares_monitor(name):
    policy = _build(name)
    cfg = SimConfig(seed=7)  # default scenario: the one the hyperparameters are calibrated for
    rng = np.random.default_rng(cfg.seed)
    legit_X, sup_X, sup_y = _build_training(cfg, rng)
    if policy.kind == "supervised":
        policy.fit(sup_X, sup_y)
    else:
        policy.fit(legit_X)

    monitor, hog = monitor_profile(0), attacker_profile(999, mimicry=False)
    mult = np.array([
        policy.multipliers([monitor, hog], np.array([monitor.observe(rng), hog.observe(rng)]))
        for _ in range(200)
    ])
    assert (mult[:, 1] < 1.0).mean() >= 0.95  # naive hog demoted
    assert (mult[:, 0] < 1.0).mean() <= 0.10  # monitor not demoted


def test_knn_threshold_excludes_self_match():
    # With k=1 a self-included training distance is 0, which would flag nearly
    # every unseen point; excluding self keeps the fresh false-positive rate near
    # the contamination budget.
    rng = np.random.default_rng(0)
    det = KnnOutlier(k=1, contamination=0.05)
    det.fit(rng.normal(size=(2000, 6)))
    assert det.outlier_mask(rng.normal(size=(4000, 6))).mean() < 0.15
