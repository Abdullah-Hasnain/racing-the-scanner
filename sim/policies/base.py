"""Policy interface and the two non-ML reference policies.

A *policy* turns observed per-process behavior into a priority multiplier.
The scheduler then computes each process's CPU weight as

    weight = claimed_priority * multiplier

- Baseline (S0): multiplier is always 1. The scheduler honors whatever priority
  a process claims, with no awareness of the monitor. This is the control.
- Invariant (S3): multiplier is 1 too, but the policy sets enforces_floor=True so
  the scheduler guarantees the monitor a minimum CPU share regardless of weights.
  Nothing a process does to its behavior can take that floor away.

The ~15 ML policies live in ml.py and override `multipliers`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

import numpy as np

from sim.process import Process


class Policy(ABC):
    name: str = "policy"
    group: str = "base"
    enforces_floor: bool = False
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

    def scores(self, processes: list[Process], obs: np.ndarray) -> np.ndarray | None:
        """Continuous suspicion per row of obs (higher = more hog-like), for ROC-AUC.

        None means the policy has no detector (baseline, invariant), so its
        detection AUC is undefined.
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
    structural, which is why mimicry cannot defeat it.
    """

    name = "invariant"
    group = "invariant"
    enforces_floor = True

    def multipliers(self, processes: list[Process], obs: np.ndarray) -> np.ndarray:
        return np.ones(len(processes), dtype=float)
