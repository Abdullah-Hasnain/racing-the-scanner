"""The standard Linux CPU-reservation mechanisms: the "reservation" group (#9).

They answer "why not just use real-time priority or cgroups?". Each one protects
the KNOWN monitor (or bounds everyone else) without classifying any process:
every multiplier is 1, there is no detector and no `scores`, so mimicry cannot
affect them and their detection AUC is n/a.

Like the rest of the sim, these are fluid models (CPU shares per tick). In this
scenario the monitor is always runnable (it scans back to back), and the models
rely on that; each docstring says what changes when the monitor idles.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import numpy as np

from sim.policies.base import Policy, monitor_mask
from sim.process import Process

if TYPE_CHECKING:
    from sim.engine import SimConfig


def _monitor_takes(shares: np.ndarray, processes: list[Process], s: float) -> np.ndarray:
    """The monitor gets share s; everyone else splits 1 - s by weight."""
    mon = monitor_mask(processes)
    out = shares.copy()
    out[mon] = 0.0
    tot = out.sum()
    out = out / tot * (1.0 - s) if tot > 0 else out
    out[mon] = s
    return out


class ReservationPolicy(Policy):
    group = "reservation"

    def multipliers(self, processes: list[Process], obs: np.ndarray) -> np.ndarray:
        return np.ones(len(processes), dtype=float)


class SchedFifoPolicy(ReservationPolicy):
    """SCHED_FIFO: the monitor runs at real-time priority.

    It preempts every normal task, so it takes the CPU first, up to the kernel's
    RT limit (cfg.rt_limit = 95%: RT throttling, or the fair-server reservation
    on newer kernels, keeps about 5% of each second for normal tasks). Normal
    tasks, the hog included, share what is left by weight. That is the cost: an
    always-runnable RT task nearly starves the rest of the system. A monitor that
    idled would take only what it uses.
    """

    name = "sched_fifo"

    def allocate(self, shares: np.ndarray, processes: list[Process], cfg: SimConfig) -> np.ndarray:
        return _monitor_takes(shares, processes, cfg.rt_limit)


class CgroupCpuMaxPolicy(ReservationPolicy):
    """cgroup v2 cpu.max: the same bandwidth cap on every non-monitor process.

    Each one (the attacker included, but not singled out) may use at most
    cfg.cpumax_cap of the CPU, like tenants on a multi-tenant host. Capping only
    the attacker would need an oracle. The CPU is shared by weight; a process
    that would exceed its cap is held at it and the excess goes to the others.
    The monitor is protected only indirectly, by what the caps leave over, and
    cpu.max is not work-conserving: capped processes cannot use idle CPU.
    """

    name = "cgroup_cpumax"

    def allocate(self, shares: np.ndarray, processes: list[Process], cfg: SimConfig) -> np.ndarray:
        cap = cfg.cpumax_cap
        capped = ~monitor_mask(processes)
        out = np.zeros_like(shares)
        free = np.ones(len(shares), dtype=bool)  # not yet held at the cap
        left = 1.0
        while free.any():
            fair = np.where(free, shares, 0.0)
            fair = fair / fair.sum() * left
            over = free & capped & (fair > cap)
            if not over.any():
                out[free] = fair[free]
                break
            out[over] = cap
            left -= cap * over.sum()
            free &= ~over
        return out


class CgroupWeightPolicy(ReservationPolicy):
    """cgroup v2 cpu.weight: the monitor in its own cgroup, everyone else in a sibling.

    Weights 25:100 split the CPU 20:80 (cfg.floor_share) while both groups are
    busy, so the hog's claimed priority only competes inside its own group.
    Because the monitor is always runnable, this is numerically the invariant:
    the monitor's proportional share never exceeds 20% under a policy that
    judges no one. It is work-conserving: an idle monitor's share would go to
    the others.
    """

    name = "cgroup_weight"

    def allocate(self, shares: np.ndarray, processes: list[Process], cfg: SimConfig) -> np.ndarray:
        return _monitor_takes(shares, processes, cfg.floor_share)


class SchedDeadlinePolicy(ReservationPolicy):
    """SCHED_DEADLINE with runtime/period = cfg.floor_share (0.2).

    The monitor gets its runtime each period with priority over normal tasks,
    then is throttled until the next period. As a fluid model with an
    always-runnable monitor, that is exactly cgroup_weight's 20:80 split, and so
    numerically the invariant. This row is kept for completeness, labelled as
    identical; it is not a different result.
    """

    name = "sched_deadline"

    def allocate(self, shares: np.ndarray, processes: list[Process], cfg: SimConfig) -> np.ndarray:
        return _monitor_takes(shares, processes, cfg.floor_share)


def reservation_policies() -> list[ReservationPolicy]:
    return [SchedFifoPolicy(), CgroupCpuMaxPolicy(), CgroupWeightPolicy(), SchedDeadlinePolicy()]
