"""Process model.

A process is defined by (a) a role, (b) a timing profile that the scheduler's
behavioral detector can observe, and (c) a *claimed priority* that it presents
to the scheduler. The key idea of the whole project lives in the gap between
(b) and (c): the attacker shapes its observable timing (b) to look benign while
still claiming a high priority (c) so it keeps hogging CPU. A behavior-based
detector only sees (b), which is exactly why mimicry works.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

# The feature vector the scheduler's detector observes, in a fixed order.
FEATURE_NAMES = (
    "burst_mean",   # mean CPU burst length
    "burst_std",    # variance of burst length
    "sleep_mean",   # mean sleep between bursts
    "sleep_std",    # variance of sleep
    "wake_rate",    # wakeups per unit time
    "ctxsw_rate",   # voluntary context switches per unit time
)
N_FEATURES = len(FEATURE_NAMES)


@dataclass
class Process:
    """One schedulable process.

    timing: the mean of each feature in FEATURE_NAMES (what it 'really' does).
    noise:  per-feature std used when sampling an observed window.
    claimed_priority: the weight it asks the scheduler for (nice-like). A plain
        scheduler honors it; a smart one may override it; an invariant ignores it
        for the protected monitor.
    """

    pid: int
    role: str  # "monitor" | "benign" | "attacker" | "victim"
    timing: np.ndarray
    noise: np.ndarray
    claimed_priority: float = 1.0
    demand: float = 1.0  # how much CPU it wants (1.0 = a full share if granted)
    label: int = field(default=0)  # 0 benign/monitor, 1 hog (for supervised policies)

    def observe(self, rng: np.random.Generator) -> np.ndarray:
        """Sample one observed feature window (timing + noise)."""
        return self.timing + rng.normal(0.0, self.noise)


# ---- profile builders -------------------------------------------------------

def _vec(burst_mean, burst_std, sleep_mean, sleep_std, wake_rate, ctxsw_rate):
    return np.array(
        [burst_mean, burst_std, sleep_mean, sleep_std, wake_rate, ctxsw_rate],
        dtype=float,
    )


def monitor_profile(pid: int) -> Process:
    """A latency-sensitive security monitor: short periodic bursts, regular sleeps.

    demand 0.5 (a benign app's weight) lets the monitor meet the exposure window
    under the benign load alone (#7). At 0.25 it starved with no attacker at all,
    so no scheduler could protect it whatever its detector did. Demand is not an
    observed feature, so the detector calibration from #6 is unaffected.
    """
    return Process(
        pid=pid,
        role="monitor",
        timing=_vec(2.0, 0.3, 8.0, 0.5, 5.0, 4.0),
        noise=_vec(0.2, 0.05, 0.4, 0.1, 0.3, 0.3),
        claimed_priority=1.0,
        demand=0.5,
        label=0,
    )


def benign_profile(pid: int, rng: np.random.Generator) -> Process:
    """An ordinary interactive/throughput app. Several of these form the backdrop."""
    jitter = rng.normal(0.0, 0.3, size=N_FEATURES)
    return Process(
        pid=pid,
        role="benign",
        timing=_vec(3.0, 0.6, 6.0, 0.8, 4.0, 3.0) + jitter,
        noise=_vec(0.3, 0.08, 0.5, 0.12, 0.3, 0.3),
        claimed_priority=1.0,
        demand=0.5,
        label=0,
    )


def attacker_profile(pid: int, mimicry: bool, starve: bool = True) -> Process:
    """The attacker process.

    starve=True, the CPU hog:
      naive  : long bursts, little sleep -> obviously anomalous timing.
      mimicry: timing shaped to sit inside the benign distribution, yet it still
               claims a high priority and high demand, so it keeps starving others.
    starve=False, the hiding payload alone: benign timing and a benign app's
      share. With nothing to disguise, `mimicry` has no effect.
    """
    if not starve:
        return Process(
            pid=pid,
            role="attacker",
            timing=_vec(3.0, 0.6, 6.0, 0.8, 4.0, 3.0),
            noise=_vec(0.3, 0.08, 0.5, 0.12, 0.3, 0.3),
            claimed_priority=1.0,
            demand=0.5,
            label=0,
        )
    if mimicry:
        timing = _vec(3.0, 0.6, 6.0, 0.8, 4.0, 3.0)   # looks benign
    else:
        timing = _vec(9.0, 2.0, 1.0, 0.3, 1.0, 1.0)   # looks like a hog
    return Process(
        pid=pid,
        role="attacker",
        timing=timing,
        noise=_vec(0.3, 0.08, 0.5, 0.12, 0.3, 0.3),
        claimed_priority=5.0,  # asks for a big share regardless of how it looks
        demand=3.0,
        label=1,
    )
