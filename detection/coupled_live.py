"""The coupled attack on the real kernel (#15).

V2 and CPU hogs (the attacker, at a claimed high priority) share one core with
the live RAM scanner, under three CPU policies for the scanner. Each cell counts
the scans completed and the scans that caught V2's marker. Setup, results and
caveats are in detection/README.md, "Coupled attack on the real kernel".

Needs root (reading another process's memory under ptrace_scope=1, cgroups,
SCHED_FIFO). From the repo root:

  pkexec "$PWD/.venv/bin/python" "$PWD/detection/coupled_live.py" --repo "$PWD"
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

import numpy as np


@dataclass(frozen=True)
class Policy:
    fifo: bool  # the scanner runs at SCHED_FIFO
    own_cgroup: bool  # the scanner sits alone in a heavily weighted cgroup


POLICIES = {
    "eevdf": Policy(fifo=False, own_cgroup=False),  # stock scheduler, no reservation
    "cgroup_weight": Policy(fifo=False, own_cgroup=True),
    "sched_fifo": Policy(fifo=True, own_cgroup=False),
}
CONDITIONS = {"hiding": 0, "coupled": 4}  # condition -> default number of hogs
CGROUP = Path("/sys/fs/cgroup/rts-coupled")
MONITOR_WEIGHT, ATTACKER_WEIGHT = 10000, 100
FIFO_PRIORITY = 10
HOG = "while True: pass"

_SCAN = re.compile(r"^scan\s+\d+\s+found=(\d)\s+scan_ms=\s*([\d.]+)")
_V2_FAULTS = re.compile(r"faults=(\d+)")


@dataclass(frozen=True)
class ScanSummary:
    scans: int
    catches: int  # scans that found V2's marker
    scans_per_s: float
    p50_scan_ms: float | None
    p95_scan_ms: float | None


def summarize(lines: Iterable[str], seconds: float) -> ScanSummary:
    """Reduce the scanner's per-scan lines to counts and scan-time percentiles
    (linear interpolation, as sim/engine.py reports latency)."""
    found, ms = [], []
    for line in lines:
        if m := _SCAN.match(line.strip()):
            found.append(m.group(1) == "1")
            ms.append(float(m.group(2)))
    return ScanSummary(
        scans=len(found),
        catches=sum(found),
        scans_per_s=len(found) / seconds,
        p50_scan_ms=float(np.percentile(ms, 50)) if ms else None,
        p95_scan_ms=float(np.percentile(ms, 95)) if ms else None,
    )


def _child_setup(cpu: int, nice: int = 0, fifo: bool = False):
    """Pin a child to one core and give it a nice value or SCHED_FIFO."""
    def setup() -> None:
        os.sched_setaffinity(0, {cpu})
        if nice:
            os.setpriority(os.PRIO_PROCESS, 0, nice)
        if fifo:
            os.sched_setscheduler(0, os.SCHED_FIFO, os.sched_param(FIFO_PRIORITY))
    return setup


def _make_cgroups() -> tuple[Path, Path]:
    monitor, attacker = CGROUP / "monitor", CGROUP / "attacker"
    for d in (CGROUP, monitor, attacker):
        d.mkdir(exist_ok=True)
    (CGROUP / "cgroup.subtree_control").write_text("+cpu")
    (monitor / "cpu.weight").write_text(str(MONITOR_WEIGHT))
    (attacker / "cpu.weight").write_text(str(ATTACKER_WEIGHT))
    return monitor, attacker


def _remove_cgroups() -> None:
    for d in (CGROUP / "monitor", CGROUP / "attacker", CGROUP):
        if d.exists():
            d.rmdir()


def _join(cgroup: Path, pid: int) -> None:
    (cgroup / "cgroup.procs").write_text(str(pid))


def run_cell(args: argparse.Namespace, policy: str, condition: str) -> dict:
    """One run on one core. The scanner is already scanning when the attack
    starts: the hogs begin after its first scan, and only scans in the next
    `args.seconds` count, timed as their lines arrive."""
    pol = POLICIES[policy]
    monitor, attacker = _make_cgroups()
    procs: list[subprocess.Popen] = []
    try:
        # V2 is the attacker too, so it gets the attacker's priority.
        v2 = subprocess.Popen(
            [args.v2_bin, "--duration", "0"],  # until SIGINT
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            preexec_fn=_child_setup(args.cpu, nice=args.hog_nice),
        )
        procs.append(v2)
        _join(attacker, v2.pid)
        time.sleep(1)  # let V2 lock its buffer before the first scan
        scanner = subprocess.Popen(
            [sys.executable, str(Path(args.repo) / "memory/scanner/scanner.py"),
             "--pid", str(v2.pid), "--interval", str(args.interval),
             "--duration", str(args.seconds + 5)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            preexec_fn=_child_setup(args.cpu, fifo=pol.fifo),
        )
        procs.append(scanner)
        _join(monitor if pol.own_cgroup else attacker, scanner.pid)
        lines = iter(scanner.stdout.readline, "")
        for line in lines:
            if _SCAN.match(line.strip()):
                break
        for _ in range(args.hogs if condition == "coupled" else 0):
            hog = subprocess.Popen(
                [sys.executable, "-c", HOG], preexec_fn=_child_setup(args.cpu, nice=args.hog_nice)
            )
            procs.append(hog)
            _join(attacker, hog.pid)
        t_end = time.monotonic() + args.seconds
        window = []
        for line in lines:
            if time.monotonic() > t_end:
                break
            window.append(line)
    finally:
        for p in reversed(procs[1:]):  # scanner and hogs
            p.kill()
            p.wait()
    v2.send_signal(signal.SIGINT)
    v2_out, _ = v2.communicate()
    _remove_cgroups()
    faults = _V2_FAULTS.search(v2_out or "")
    return {
        "policy": policy, "condition": condition, "cpu": args.cpu,
        "hogs": len(procs) - 2, "attacker_nice": args.hog_nice,
        "seconds": args.seconds, "interval_s": args.interval,
        **asdict(summarize(window, args.seconds)),
        "v2_faults": int(faults.group(1)) if faults else None,
    }


def _write(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0])
    if path.exists():
        with path.open() as f:
            if next(csv.reader(f), None) != fields:
                sys.exit(f"{path} has different columns; pass a new --out")
    new = not path.exists()
    with path.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
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
    ap.add_argument("--cpu", type=int, default=2, help="core to pin everything to")
    ap.add_argument("--hogs", type=int, default=CONDITIONS["coupled"])
    ap.add_argument("--hog-nice", type=int, default=-20, help="the attacker's claimed priority")
    ap.add_argument("--seconds", type=float, default=20.0, help="counted scan window per cell")
    # 37 ms does not divide V2's 100 ms period, so scans sweep its whole cycle.
    ap.add_argument("--interval", type=float, default=0.037, help="scanner sleep between scans")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--policies", nargs="+", default=list(POLICIES), choices=list(POLICIES))
    ap.add_argument("--conditions", nargs="+", default=list(CONDITIONS), choices=list(CONDITIONS))
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
    try:
        for rep in range(args.reps):
            for condition in args.conditions:
                for policy in args.policies:
                    row = {"run_id": run_id, "rep": rep, **run_cell(args, policy, condition)}
                    print(row, flush=True)
                    rows.append(row)
    finally:
        _remove_cgroups()
        if rows:
            _write(rows, Path(args.out or Path(args.repo) / "results/coupled_live.csv"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
