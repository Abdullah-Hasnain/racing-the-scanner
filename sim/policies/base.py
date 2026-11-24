"""Policy interface and the two non-ML reference policies.

A *policy* acts on the scheduler in two places each tick:

1. `multipliers`: from observed behavior, a priority multiplier per process.
   The scheduler weighs each process as

       weight = claimed_priority * demand * multiplier

   and turns the weights into proportional CPU shares.
2. `allocate`: an optional rewrite of those shares (default: unchanged). This is
   where a reservation lives: it moves CPU between processes without judging
   anyone's behavior.

- Baseline (S0): multiplier is always 1 and shares are left alone. The scheduler
  honors whatever priority a process claims, with no awareness of the monitor.
  This is the control.
- Invariant (S3): multiplier is 1 too, but `allocate` guarantees the monitor a
  minimum CPU share (cfg.floor_share) regardless of weights. Nothing a process
  does to its behavior can take that floor away.

The ~15 ML policies live in ml.py and override `multipliers`; the standard Linux
reservation mechanisms live in reservation.py and override `allocate`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

import numpy as np

from sim.process import Process

if TYPE_CHECKING:
    from sim.engine import SimConfig


def monitor_mask(processes: list[Process]) -> np.ndarray:
    return np.array([p.role == "monitor" for p in processes])


class Policy(ABC):
    name: str = "policy"
    group: str = "base"
    requires_torch: bool = False

    def fit(self, legit_features: np.ndarray, labels: np.ndarray | None = None) -> None:
        """Train on observed behavior. Called once before the run.

        legit_features: rows of observed windows from legitimate processes
            (benign apps and the monitor). Never trained on the attacker.
        labels: optional class labels for supervised policies
            (0 normal, 1 hog, 2 monitor).
        """
        return None

    @abstractmethod
    def multipliers(self, processes: list[Process], obs: np.ndarray) -> np.ndarray:
        """Return one priority multiplier per process, same order as `processes`.

        obs[i] is the observed feature window for processes[i] this tick.
        """
        ...

    def allocate(self, shares: np.ndarray, processes: list[Process], cfg: SimConfig) -> np.ndarray:
        """Final CPU shares this tick, from the proportional ones (which sum to 1)."""
        return shares

    def scores(self, processes: list[Process], obs: np.ndarray) -> np.ndarray | None:
        """Continuous suspicion per row of obs (higher = more hog-like), for ROC-AUC.

        None means the policy has no detector (baseline, invariant, the
        reservation group), so its detection AUC is undefined.
        """
        return None


class BaselinePolicy(Policy):
    """S0: stock-scheduler control. No awareness, no protection."""

    name = "baseline"
    group = "baseline"

    def multipliers(self, processes: list[Process], obs: np.ndarray) -> np.ndarray:
        return np.ones(len(processes), dtype=float)


class InvariantPolicy(Policy):
    """S3: hard CPU-reservation floor for the monitor, enforced by the scheduler.

    The policy itself judges no one (multiplier 1 for all); the guarantee is
    structural, which is why mimicry cannot defeat it. The monitor gets
    max(its proportional share, cfg.floor_share); everyone else is scaled down
    proportionally to make room.
    """

    name = "invariant"
    group = "invariant"

    def multipliers(self, processes: list[Process], obs: np.ndarray) -> np.ndarray:
        return np.ones(len(processes), dtype=float)

    def allocate(self, shares: np.ndarray, processes: list[Process], cfg: SimConfig) -> np.ndarray:
        mon = monitor_mask(processes)
        floor = cfg.floor_share
        if shares[mon].sum() >= floor:
            return shares
        others = shares.copy()
        others[mon] = 0.0
        tot = others.sum()
        others = others / tot * (1.0 - floor) if tot > 0 else others
        others[mon] = floor
        return others
