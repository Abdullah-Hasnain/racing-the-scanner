"""Smoke tests: the harness runs, the registry is complete, and the invariant
protects the monitor where the baseline does not. These run in CI on every PR.
"""

from __future__ import annotations

import numpy as np

from sim.engine import SimConfig, run_once
from sim.policies import all_policies, augmented_policies, build_policy


def _small() -> SimConfig:
    return SimConfig(ticks=200, train_samples=120, seed=1)


def test_registry_has_control_and_invariant_and_15_augmented():
    names = all_policies()
    assert names[0] == "baseline"
    assert names[-1] == "invariant"
    # the professor's requirement: ~15 augmented schedulers
    assert len(augmented_policies()) >= 14


def test_every_policy_builds():
    for name in all_policies():
        p = build_policy(name)
        assert p.name == name


def test_baseline_produces_scans():
    res = run_once(build_policy("baseline"), _small()).summary()
    for key in ("p50_latency", "p95_latency", "miss_rate", "monitor_share"):
        assert key in res
    assert res["n_scans"] > 0


def test_invariant_beats_baseline_under_mimicry():
    cfg = _small()
    base = run_once(build_policy("baseline"), cfg).summary()
    inv = run_once(build_policy("invariant"), cfg).summary()
    # the whole point: a hard floor keeps the monitor scheduled; the control does not
    assert inv["monitor_share"] > base["monitor_share"]
    assert inv["p95_latency"] <= base["p95_latency"]


def test_unsupervised_detector_scores_an_array():
    # a trained detector returns one decision per row
    from sklearn.ensemble import IsolationForest

    from sim.policies.ml import PredictOutlier

    det = PredictOutlier(lambda: IsolationForest(contamination=0.06, random_state=0))
    det.fit(np.random.default_rng(0).normal(size=(200, 6)))
    mask = det.outlier_mask(np.random.default_rng(1).normal(size=(10, 6)))
    assert mask.shape == (10,)
    assert mask.dtype == bool
