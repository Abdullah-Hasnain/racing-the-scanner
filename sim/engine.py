"""The scheduling simulation.

One run places a monitor, several benign apps, and one attacker on a simulated
CPU. Each tick the active policy sets priority multipliers from observed
behavior, the scheduler allocates CPU shares (honoring the invariant floor if
the policy enforces one), and the monitor accumulates CPU until it completes a
scan. We record the interval between scans (its scheduling latency) and whether
each scan landed inside the attacker's exposure window.

This is a model, not the kernel. It is the controlled instrument for the policy
comparison; a subset of policies is validated on real sched_ext (see ROADMAP).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import numpy as np
from threadpoolctl import threadpool_limits

from sim.policies import build_policy
from sim.policies.base import Policy
from sim.process import (
    attacker_profile,
    benign_profile,
    monitor_profile,
)

NORMAL, HOG, MONITOR = 0, 1, 2


@dataclass
class SimConfig:
    n_benign: int = 4
    ticks: int = 600
    scan_cost: float = 1.0        # CPU the monitor must accumulate per scan
    exposure_window: int = 8      # a scan "catches" the payload if latency <= this
    floor_share: float = 0.20     # invariant minimum monitor share
    mimicry: bool = True          # attacker imitates benign timing
    train_samples: int = 300
    seed: int = 42


@dataclass
class SimResult:
    policy: str
    group: str
    mimicry: bool
    scan_latencies: list[float]
    monitor_share_mean: float
    overhead_ms: float
    extra: dict = field(default_factory=dict)

    def summary(self) -> dict:
        lat = np.array(self.scan_latencies if self.scan_latencies else [np.nan])
        window = self.extra.get("exposure_window", 8)
        return {
            "policy": self.policy,
            "group": self.group,
            "mimicry": self.mimicry,
            "p50_latency": float(np.nanpercentile(lat, 50)),
            "p95_latency": float(np.nanpercentile(lat, 95)),
            "p99_latency": float(np.nanpercentile(lat, 99)),
            "miss_rate": float(np.nanmean(lat > window)),
            "detection_rate": float(np.nanmean(lat <= window)),
            "monitor_share": round(self.monitor_share_mean, 4),
            "overhead_ms": round(self.overhead_ms, 3),
            "n_scans": int(np.sum(~np.isnan(lat))),
        }


def _build_training(cfg: SimConfig, rng: np.random.Generator):
    """Training data drawn from LEGITIMATE behavior only (plus a naive hog for labels).

    The real attacker (mimicry) is never in the training set, so results are not
    tautological: the detectors are trained blind to the attack they must stop.
    """
    monitor = monitor_profile(0)
    benign = [benign_profile(100 + i, rng) for i in range(cfg.n_benign)]
    naive_hog = attacker_profile(999, mimicry=False)

    legit_rows = []
    sup_rows, sup_labels = [], []
    for _ in range(cfg.train_samples):
        for p in benign:
            legit_rows.append(p.observe(rng))
            sup_rows.append(p.observe(rng))
            sup_labels.append(NORMAL)
        legit_rows.append(monitor.observe(rng))
        sup_rows.append(monitor.observe(rng))
        sup_labels.append(MONITOR)
        sup_rows.append(naive_hog.observe(rng))  # labelled hog; NOT in legit set
        sup_labels.append(HOG)

    return (
        np.asarray(legit_rows),
        np.asarray(sup_rows),
        np.asarray(sup_labels),
    )


def _allocate(shares: np.ndarray, enforces_floor: bool, floor: float) -> np.ndarray:
    if not enforces_floor or shares[0] >= floor:
        return shares
    others = shares.copy()
    others[0] = 0.0
    tot = others.sum()
    others = others / tot * (1.0 - floor) if tot > 0 else others
    others[0] = floor
    return others


def run_once(policy: Policy, cfg: SimConfig) -> SimResult:
    # One BLAS/OpenMP thread: a scheduling decision runs on one core, and OpenMP
    # models (histgb) otherwise spend most of each 6-row predict waking threads,
    # which would inflate overhead_ms with thread-spawn cost instead of model cost.
    with threadpool_limits(limits=1):
        return _run_once(policy, cfg)


def _run_once(policy: Policy, cfg: SimConfig) -> SimResult:
    rng = np.random.default_rng(cfg.seed)
    legit_X, sup_X, sup_y = _build_training(cfg, rng)

    kind = getattr(policy, "kind", "unsupervised")
    if kind == "supervised":
        policy.fit(sup_X, sup_y)
    else:
        policy.fit(legit_X)

    monitor = monitor_profile(0)
    benign = [benign_profile(100 + i, rng) for i in range(cfg.n_benign)]
    attacker = attacker_profile(999, cfg.mimicry)
    procs = [monitor, *benign, attacker]
    base_eff = np.array([p.claimed_priority * p.demand for p in procs])

    acc = 0.0
    last_scan = 0
    latencies: list[float] = []
    mon_shares: list[float] = []
    overhead = 0.0

    for t in range(cfg.ticks):
        obs = np.array([p.observe(rng) for p in procs])
        t0 = time.perf_counter()
        mult = policy.multipliers(procs, obs)
        overhead += time.perf_counter() - t0

        eff = np.clip(base_eff * mult, 1e-9, None)
        share = eff / eff.sum()
        share = _allocate(share, policy.enforces_floor, cfg.floor_share)
        mon_shares.append(float(share[0]))

        acc += share[0]
        while acc >= cfg.scan_cost:
            latencies.append(float(t - last_scan))
            last_scan = t
            acc -= cfg.scan_cost

    return SimResult(
        policy=policy.name,
        group=policy.group,
        mimicry=cfg.mimicry,
        scan_latencies=latencies,
        monitor_share_mean=float(np.mean(mon_shares)),
        overhead_ms=overhead * 1000.0,
        extra={"exposure_window": cfg.exposure_window},
    )


def run_policy(name: str, cfg: SimConfig, runs: int = 1) -> list[dict]:
    """Run one policy `runs` times (different seeds) and return per-run summaries."""
    out = []
    for r in range(runs):
        c = SimConfig(**{**cfg.__dict__, "seed": cfg.seed + r})
        res = run_once(build_policy(name), c)
        out.append(res.summary())
    return out
