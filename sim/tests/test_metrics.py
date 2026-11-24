"""Detection ROC-AUC and the spread across runs (#8).

Every detector separates the naive hog almost perfectly. The mimic copies the
center of benign behavior, so against the benign apps it imitates the family
scores it at or below chance; the few classifiers that rank it higher do so at
probabilities that never reach a decision. The AUC is computed on the windows
the scheduler judged, which are held out from training by session.
"""

from __future__ import annotations

import functools
import importlib.util

import numpy as np
import pandas as pd
import pytest

import sim.engine as engine
from sim.engine import SimConfig, _build_training, run_once, run_policy
from sim.metrics import SPREAD, aggregate, detection_auc
from sim.policies import augmented_policies, build_policy
from sim.policies.ml import PredictOutlier, unsupervised_policies
from sim.process import attacker_profile, benign_profile, monitor_profile

HAS_TORCH = importlib.util.find_spec("torch") is not None
SEED = 42  # the first sweep seed: these runs are rows of the documented 20-run spread

# Caps for the mimic, set from the 20-run sweep (docs/architecture.md, "Detection
# ROC-AUC"):
#   NAIVE_FLOOR        every run of every policy: >= 0.9996
#   FAMILY_MEDIAN_CAP  chance; the family median of roc_auc_benign was 0.14-0.41
#   POLICY_CAP         above all 280 mimicry runs (max 0.945, naive_bayes); single
#                      runs of logreg, mlp, and naive_bayes rank the mimic high
#   DEMOTED_CAP        share of ticks the mimic is demoted: never by a supervised
#                      policy; by an unsupervised one only at its false-positive
#                      rate (median <= 0.03, worst run 0.205, hbos). The naive hog
#                      is demoted on >= 0.99.
NAIVE_FLOOR = 0.99
FAMILY_MEDIAN_CAP = 0.5
POLICY_CAP = 0.95
DEMOTED_CAP = {"supervised": 0.0, "unsupervised": 0.25}


def _build(name: str):
    policy = build_policy(name)
    if policy.requires_torch and not HAS_TORCH:
        pytest.skip("torch not installed")
    return policy


@functools.cache  # the family test reuses the per-policy mimicry runs
def _run(name: str, **cfg) -> tuple[dict, float]:
    """One run's summary, and the fraction of ticks the scheduler demoted the attacker."""
    policy = _build(name)
    demoted: list[bool] = []
    decide = policy.multipliers

    def recording(processes, obs):
        m = decide(processes, obs)
        demoted.extend(m[i] < 1 for i, p in enumerate(processes) if p.role == "attacker")
        return m

    policy.multipliers = recording
    res = run_once(policy, SimConfig(seed=SEED, **cfg)).summary()
    return res, float(np.mean(demoted)) if demoted else float("nan")


@pytest.mark.parametrize("name", augmented_policies())
def test_every_detector_separates_the_naive_hog(name):
    res, _ = _run(name, mimicry=False)
    assert res["roc_auc"] >= NAIVE_FLOOR
    assert res["roc_auc_benign"] >= NAIVE_FLOOR


@pytest.mark.parametrize("name", augmented_policies())
def test_no_detector_comes_near_separating_the_mimic(name):
    res, demoted = _run(name)
    assert res["roc_auc"] <= POLICY_CAP
    assert res["roc_auc_benign"] <= POLICY_CAP
    # Whatever the ranking, the decision treats the mimic as legitimate.
    assert demoted <= DEMOTED_CAP[build_policy(name).kind]


def test_mimic_is_at_or_below_chance_against_benign_apps_for_the_family():
    names = [n for n in augmented_policies() if HAS_TORCH or not build_policy(n).requires_torch]
    aucs = [_run(n)[0]["roc_auc_benign"] for n in names]
    assert np.median(aucs) <= FAMILY_MEDIAN_CAP


@pytest.mark.parametrize("name", ["baseline", "invariant"])
def test_auc_is_undefined_without_a_detector(name):
    res, _ = _run(name, ticks=100)
    assert np.isnan(res["roc_auc"]) and np.isnan(res["roc_auc_benign"])


def test_auc_is_undefined_without_an_attacker():
    res, _ = _run("elliptic", ticks=100, condition="none")
    assert np.isnan(res["roc_auc"]) and np.isnan(res["roc_auc_benign"])


def test_auc_reports_below_chance_raw():
    # A detector that scores the attacker as more normal than everyone else gets
    # AUC 0, not a flipped 1.
    roles = np.array(["attacker", "benign", "monitor"] * 10)
    scores = np.where(roles == "attacker", 0.0, 1.0)
    assert detection_auc(scores, roles, versus=("benign", "monitor")) == 0.0


@pytest.mark.parametrize("name", [p.name for p in unsupervised_policies()])
def test_outlier_score_is_the_decision_statistic(name):
    # outlier_mask thresholds outlier_score, and for the sklearn detectors that
    # agrees with the model's own predict(): the AUC rates what the scheduler does.
    policy = _build(name)
    rng = np.random.default_rng(SEED)
    legit_X, _, _ = _build_training(SimConfig(seed=SEED), rng)
    policy.fit(legit_X)
    det = policy.model
    procs = [monitor_profile(0), benign_profile(500, rng), attacker_profile(999, mimicry=False)]
    X = np.array([p.observe(rng) for _ in range(200) for p in procs])
    np.testing.assert_array_equal(det.outlier_mask(X), det.outlier_score(X) > det.thr)
    if isinstance(det, PredictOutlier):
        np.testing.assert_array_equal(det.outlier_mask(X), det.model.predict(det.scaler.transform(X)) == -1)


@pytest.mark.parametrize("name", ["elliptic", "logreg"])
def test_auc_windows_are_held_out_by_session(name, monkeypatch):
    made: list = []

    def recording_benign(pid, rng):
        made.append(benign_profile(pid, rng))
        return made[-1]

    monkeypatch.setattr(engine, "benign_profile", recording_benign)
    policy = build_policy(name)
    seen: dict = {"judged": []}
    fit, multipliers, scores = policy.fit, policy.multipliers, policy.scores

    def spy_fit(X, labels=None):
        seen["train"] = X.copy()
        return fit(X, labels)

    def spy_multipliers(processes, obs):
        seen["judged"].append(obs.copy())
        return multipliers(processes, obs)

    def spy_scores(processes, obs):
        seen["procs"], seen["scored"] = list(processes), obs.copy()
        return scores(processes, obs)

    monkeypatch.setattr(policy, "fit", spy_fit)
    monkeypatch.setattr(policy, "multipliers", spy_multipliers)
    monkeypatch.setattr(policy, "scores", spy_scores)
    cfg = SimConfig(ticks=100, seed=SEED)
    run_once(policy, cfg)

    # Benign apps: the first n_benign are training processes, the next n_benign
    # run (and are scored); they are different processes with different timing.
    train_apps, run_apps = made[:cfg.n_benign], made[cfg.n_benign:]
    assert len(run_apps) == cfg.n_benign
    scored_apps = {id(p) for p in seen["procs"] if p.role == "benign"}
    assert scored_apps == {id(p) for p in run_apps}
    assert not any(np.allclose(a.timing, b.timing) for a in run_apps for b in train_apps)

    # Every window the scheduler judged is scored, in tick order: nothing dropped,
    # shuffled, or added. None of them appears in the training data.
    np.testing.assert_array_equal(seen["scored"], np.concatenate(seen["judged"]))
    train_rows = {tuple(r) for r in seen["train"]}
    assert not any(tuple(r) in train_rows for r in seen["scored"])


def test_aggregate_reports_median_and_iqr():
    df = pd.DataFrame({
        "policy": ["a"] * 5 + ["b"] * 5,
        "p95_latency": [1, 2, 3, 4, 5, 9, 9, 9, 9, 9],
        "miss_rate": [0.0] * 10,
        "roc_auc": [0.1, 0.2, 0.3, 0.4, 0.5] + [np.nan] * 5,
        "roc_auc_benign": [0.5] * 5 + [np.nan] * 5,
    })
    agg = aggregate(df, ["policy"]).set_index("policy")
    assert list(agg.columns[:3]) == ["p95_latency", "p95_latency_q25", "p95_latency_q75"]
    assert agg.loc["a", ["p95_latency", "p95_latency_q25", "p95_latency_q75"]].tolist() == [3, 2, 4]
    assert agg.loc["a", "roc_auc"] == pytest.approx(0.3)
    assert agg.loc["b", ["roc_auc", "roc_auc_q25", "roc_auc_q75"]].isna().all()


def test_sweep_aggregate_columns_are_sane():
    rows = [r for n in ("baseline", "elliptic") for r in run_policy(n, SimConfig(ticks=100, seed=SEED), runs=4)]
    agg = aggregate(pd.DataFrame(rows), ["policy", "group"]).set_index("policy")
    for m in SPREAD:
        assert {m, f"{m}_q25", f"{m}_q75"} <= set(agg.columns)
        ok = agg[m].notna()
        assert (agg.loc[ok, f"{m}_q25"] <= agg.loc[ok, m]).all()
        assert (agg.loc[ok, m] <= agg.loc[ok, f"{m}_q75"]).all()
    assert agg.loc["baseline", ["roc_auc", "roc_auc_benign"]].isna().all()
    assert agg.loc["elliptic", ["roc_auc", "roc_auc_benign"]].between(0.0, 1.0).all()
