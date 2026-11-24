"""The coupled attack on the real kernel (#15).

The simulation shows that under a coupled attack (hide and hog the CPU) a CPU
reservation keeps the monitor scheduled where detection-based scheduling fails.
This runs the reservation half of that claim on real Linux: V2 hides, CPU hogs
compete for the same core, and the live RAM scanner scans V2 under three CPU
policies:

- eevdf: the stock scheduler, every process at equal weight
- cgroup_weight: the scanner alone in a cgroup with cpu.weight 10000, the rest 100
- sched_fifo: the scanner at SCHED_FIFO priority 10

Everything is pinned to one core so the hogs really compete, and the hogs claim
a high priority (nice -20 by default), as the simulation's attacker does. At
equal nice the scanner (well under 1% of a core) is never starved: EEVDF already
gives a light, mostly sleeping task its share. Each cell records
how many scans the scanner completed, how many caught V2's marker, and V2's own
fault count (the hogs slow V2 too). The ML policies exist only in the simulation,
so they are not part of this run.

Needs root: reading another process's memory under ptrace_scope=1, creating
cgroups, and SCHED_FIFO. From the repo root:

  pkexec "$PWD/.venv/bin/python" "$PWD/detection/coupled_live.py" --repo "$PWD"
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

POLICIES = ("eevdf", "cgroup_weight", "sched_fifo")
CONDITIONS = ("hiding", "coupled")
CGROUP = Path("/sys/fs/cgroup/rts-coupled")
MONITOR_WEIGHT, OTHERS_WEIGHT = 10000, 100
FIFO_PRIORITY = 10
HOG = "while True: pass"

_SCAN = re.compile(r"^scan\s+\d+\s+found=(\d)\s+scan_ms=\s*([\d.]+)")
_V2_DONE = re.compile(r"faults=(\d+)")


@dataclass(frozen=True)
class ScanSummary:
    scans: int
    catches: int  # scans that found V2's marker
    scans_per_s: float
    p50_scan_ms: float | None
    p95_scan_ms: float | None


def _rank(sorted_ms: list[float], q: float) -> float:
    """Nearest-rank percentile."""
    return sorted_ms[max(0, math.ceil(q * len(sorted_ms)) - 1)]


def summarize(lines: Iterable[str], seconds: float) -> ScanSummary:
    """Reduce the scanner's per-scan lines to counts and scan-time percentiles."""
    found, ms = [], []
    for line in lines:
        if m := _SCAN.match(line.strip()):
            found.append(m.group(1) == "1")
            ms.append(float(m.group(2)))
    ms.sort()
    return ScanSummary(
        scans=len(found),
        catches=sum(found),
        scans_per_s=len(found) / seconds,
        p50_scan_ms=_rank(ms, 0.5) if ms else None,
        p95_scan_ms=_rank(ms, 0.95) if ms else None,
    )


def _pin(cpu: int, fifo: bool, nice: int = 0):
    def setup() -> None:
        os.sched_setaffinity(0, {cpu})
        if nice:
            os.setpriority(os.PRIO_PROCESS, 0, nice)
        if fifo:
            os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(FIFO_PRIORITY))
    return setup


def _cgroups() -> tuple[Path, Path]:
    monitor, others = CGROUP / "monitor", CGROUP / "others"
    for d in (CGROUP, monitor, others):
        d.mkdir(exist_ok=True)
    (CGROUP / "cgroup.subtree_control").write_text("+cpu")
    (monitor / "cpu.weight").write_text(str(MONITOR_WEIGHT))
    (others / "cpu.weight").write_text(str(OTHERS_WEIGHT))
    return monitor, others


def _join(cgroup: Path, pid: int) -> None:
    (cgroup / "cgroup.procs").write_text(str(pid))


def run_cell(args: argparse.Namespace, policy: str, condition: str) -> dict:
    """One run on one core. The scanner is already scanning when the attack
    starts: the hogs (coupled only) begin after its first scan, and only scans
    from then on count."""
    monitor, others = _cgroups()
    v2 = subprocess.Popen(
        [args.v2_bin, "--duration", "0"],  # until SIGINT
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        preexec_fn=_pin(args.cpu, False),
    )
    _join(others, v2.pid)
    time.sleep(1)  # let V2 lock its buffer before the first scan
    scanner = subprocess.Popen(
        [sys.executable, str(Path(args.repo) / "memory/scanner/scanner.py"), "--pid", str(v2.pid),
         "--interval", str(args.interval), "--duration", str(args.seconds + 1)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
        preexec_fn=_pin(args.cpu, fifo=policy == "sched_fifo"),
    )
    _join(monitor if policy == "cgroup_weight" else others, scanner.pid)
    lines = iter(scanner.stdout.readline, "")
    for line in lines:
        if _SCAN.match(line.strip()):
            break
    hogs = [
        subprocess.Popen([sys.executable, "-c", HOG], preexec_fn=_pin(args.cpu, False, args.hog_nice))
        for _ in range(args.hogs if condition == "coupled" else 0)
    ]
    for h in hogs:
        _join(others, h.pid)
    t0 = time.monotonic()
    after = list(lines)
    scanner.wait()
    elapsed = time.monotonic() - t0
    for h in hogs:
        h.kill()
        h.wait()
    v2.send_signal(signal.SIGINT)
    v2_out, _ = v2.communicate()
    faults = _V2_DONE.search(v2_out or "")
    return {
        "policy": policy, "condition": condition, "hogs": len(hogs), "hog_nice": args.hog_nice,
        "seconds": round(elapsed, 2), "interval_s": args.interval,
        **asdict(summarize(after, elapsed)),
        "v2_faults": int(faults.group(1)) if faults else None,
    }


def _write(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        if new:
            w.writeheader()
        w.writerows(rows)
    uid = int(os.environ.get("PKEXEC_UID", os.environ.get("SUDO_UID", "-1")))
    if uid >= 0:  # hand the results back to the user who ran pkexec
        os.chown(path, uid, uid)
        os.chown(path.parent, uid, uid)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Coupled attack on the real kernel (#15)")
    ap.add_argument("--repo", default=".", help="repo root (pkexec starts in /root)")
    ap.add_argument("--v2-bin", help="V2 binary (default: <repo>/memory/bin/v2)")
    ap.add_argument("--cpu", type=int, default=os.cpu_count() - 1, help="core to pin to")
    ap.add_argument("--hogs", type=int, default=4)
    ap.add_argument("--hog-nice", type=int, default=-20, help="the hogs' claimed priority")
    ap.add_argument("--seconds", type=float, default=20.0, help="scanner run per cell")
    ap.add_argument("--interval", type=float, default=0.05, help="scanner sleep between scans")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--policies", nargs="+", default=list(POLICIES), choices=POLICIES)
    ap.add_argument("--conditions", nargs="+", default=list(CONDITIONS), choices=CONDITIONS)
    ap.add_argument("--out", help="CSV (default: <repo>/results/coupled_live.csv)")
    args = ap.parse_args(argv)
    args.v2_bin = args.v2_bin or str(Path(args.repo) / "memory/bin/v2")
    if os.geteuid() != 0:
        sys.exit(f"needs root; run: pkexec {sys.executable} {Path(__file__).resolve()} "
                 f"--repo {Path(args.repo).resolve()}")
    if not Path(args.v2_bin).exists():
        sys.exit(f"no V2 binary at {args.v2_bin}; run `make -C memory` first")

    rows = []
    run_id = time.strftime("%Y%m%d-%H%M%S")
    for rep in range(args.reps):
        for condition in args.conditions:
            for policy in args.policies:
                row = {"run_id": run_id, "rep": rep, **run_cell(args, policy, condition)}
                print(row, flush=True)
                rows.append(row)
    _write(rows, Path(args.out or Path(args.repo) / "results/coupled_live.csv"))
    for d in (CGROUP / "monitor", CGROUP / "others", CGROUP):
        d.rmdir()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
