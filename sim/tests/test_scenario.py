"""Scenario balance and attack conditions (#7).

The scenario must let detection matter: with no attacker the monitor meets the
exposure window, a detected naive hog leaves it safe, and only an undetected
(mimicry) hog starves it. The monitor boost is detection-dependent, not a
reservation: a flagged monitor loses it, and an undemoted hog swamps it.
"""

from __future__ import annotations

import importlib.util

import numpy as np
import pytest

from sim.engine import CONDITIONS, SimConfig, _build_training, run_once
from sim.policies import augmented_policies, build_policy
from sim.process import attacker_profile, monitor_profile

HAS_TORCH = importlib.util.find_spec("torch") is not None
WINDOW = SimConfig().exposure_window


def _build(name: str):
    policy = build_policy(name)
    if policy.requires_torch and not HAS_TORCH:
        pytest.skip("torch not installed")
    return policy


def _run(name: str, **cfg) -> dict:
    return run_once(_build(name), SimConfig(ticks=300, seed=3, **cfg)).summary()


def test_training_is_blind_to_attack_mode_and_condition():
    # Every condition and mode is scored by the same detector, trained on legit
    # behavior and the naive hog only; the mimic never leaks into training.
    def training(**cfg):
        return _build_training(SimConfig(seed=5, **cfg), np.random.default_rng(5))

    ref = training()
    for condition in CONDITIONS:
        for mimicry in (False, True):
            for a, b in zip(training(condition=condition, mimicry=mimicry), ref, strict=True):
                np.testing.assert_array_equal(a, b)


def test_unknown_condition_is_rejected():
    with pytest.raises(ValueError, match="unknown condition"):
        run_once(build_policy("baseline"), SimConfig(condition="bogus"))


def test_no_attacker_baseline_meets_window_with_margin():
    res = _run("baseline", condition="none")
    assert res["p95_latency"] <= WINDOW - 2
    assert res["miss_rate"] == 0.0


def test_only_the_coupled_attack_beats_the_undefended_scanner():
    hiding = _run("baseline", condition="hiding")
    starvation = _run("baseline", condition="starvation")
    coupled = _run("baseline", condition="coupled")
    assert hiding["miss_rate"] == 0.0                # hidden, but the scanner is on time
    assert starvation["p95_latency"] > WINDOW        # starved...
    assert starvation["miss_rate"] == 0.0            # ...but never hidden, so still caught
    assert coupled["miss_rate"] >= 0.95


@pytest.mark.parametrize("condition", CONDITIONS)
@pytest.mark.parametrize("mimicry", [False, True])
def test_invariant_holds_in_every_condition(condition, mimicry):
    res = _run("invariant", condition=condition, mimicry=mimicry)
    assert res["p95_latency"] <= WINDOW - 2
    assert res["miss_rate"] == 0.0


@pytest.mark.parametrize("name", augmented_policies())
def test_detecting_policy_protects_monitor_from_naive_hog(name):
    res = _run(name, mimicry=False)
    assert res["p95_latency"] <= WINDOW - 2  # with margin, not on the edge
    assert res["miss_rate"] <= 0.02


@pytest.mark.parametrize("name", augmented_policies())
def test_flagged_monitor_loses_its_boost(name):
    # The boost depends on the monitor's own timing passing as normal. The same
    # monitor process showing hog-like timing is demoted instead: the false-
    # positive cost a reservation would never pay.
    policy = _build(name)
    rng = np.random.default_rng(11)
    legit_X, sup_X, sup_y = _build_training(SimConfig(seed=11), rng)
    if policy.kind == "supervised":
        policy.fit(sup_X, sup_y)
    else:
        policy.fit(legit_X)

    monitor = monitor_profile(0)
    hog_like = attacker_profile(999, mimicry=False).timing
    normal, flagged = policy.multipliers([monitor, monitor], np.array([monitor.timing, hog_like]))
    assert normal == policy.boost
    assert flagged == policy.penalty


@pytest.mark.parametrize("name", augmented_policies())
def test_mimic_swamps_the_boosted_monitor(name):
    base = _run("baseline")
    res = _run(name)
    assert res["monitor_share"] > base["monitor_share"]  # the boost is applied...
    assert res["miss_rate"] >= 0.95                      # ...and the monitor still misses
