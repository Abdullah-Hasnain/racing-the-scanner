"""The coupled attack on the real kernel (#15).

An attacker (V1 or V2, plus CPU hogs in the starving conditions, all at a
claimed high priority) shares one core with the live RAM scanner, under three
CPU policies for the scanner. The four conditions mirror the simulation's G3:
none (V1, never hides), starvation (V1 + hogs), hiding (V2), coupled (V2 + hogs).
Each cell counts the scans completed and the scans that caught the marker. Setup, results and
caveats are in detection/README.md, "Coupled attack on the real kernel".

Needs root (reading another process's memory under ptrace_scope=1, cgroups,
SCHED_FIFO). From the repo root:

  pkexec "$PWD/.venv/bin/python" "$PWD/detection/coupled_live.py" --repo "$PWD"
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import os
import pwd
import re
import signal
import subprocess
import sys
import time
from collections import deque
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
@dataclass(frozen=True)
class Condition:
    attacker: str  # "v1" never hides its marker, "v2" hides it between accesses
    hogs: bool  # CPU hogs join the attacker


CONDITIONS = {
    "none": Condition("v1", hogs=False),
    "starvation": Condition("v1", hogs=True),
    "hiding": Condition("v2", hogs=False),
    "coupled": Condition("v2", hogs=True),
}
ATTACKER_ARGS = {"v1": [], "v2": ["--duration", "0"]}  # both run until signalled
CGROUP = Path("/sys/fs/cgroup/rts-coupled")
MONITOR_WEIGHT, ATTACKER_WEIGHT = 10000, 100
FIFO_PRIORITY = 10
HOG = "while True: pass"

PR_SET_PDEATHSIG = 1
FIELDS = [
    "run_id", "rep", "policy", "condition", "attacker", "cpu", "hogs", "attacker_nice",
    "seconds", "interval_s", "scans", "catches", "scans_per_s", "p50_scan_ms",
    "p95_scan_ms", "v2_faults",
]

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
    """Pin a child to one core and give it a nice value or SCHED_FIFO. The child
    is also killed if the harness dies, even by SIGKILL, so no nice -20 hog or
    V2 is left spinning on the measured core."""
    def setup() -> None:
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
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
    """Best effort: a cgroup that is still populated stays, with a warning,
    rather than replacing whatever error is already on its way out."""
    for d in (CGROUP / "monitor", CGROUP / "attacker", CGROUP):
        try:
            if d.exists():
                d.rmdir()
        except OSError as exc:
            print(f"warning: could not remove {d}: {exc}", file=sys.stderr)


def _join(cgroup: Path, pid: int) -> None:
    (cgroup / "cgroup.procs").write_text(str(pid))


def scanner_command(repo: str, pid: int, interval: float, duration: float) -> list[str]:
    """The live scanner without its entropy pass (it makes each scan ~40x slower,
    #47), which is closest to the pre-#45 scanner the README table first used,
    and without its CSV (as root it would leave root-owned files in results/;
    the scan lines on stdout are what we read)."""
    return [sys.executable, str(Path(repo) / "memory/scanner/scanner.py"),
            "--pid", str(pid), "--interval", str(interval), "--duration", str(duration),
            "--no-entropy", "--no-csv"]


def _stop_target(target: subprocess.Popen) -> str:
    """SIGINT, so V2 prints its fault count, then SIGKILL if it hangs. V1 just
    dies on SIGINT. Returns what the target printed."""
    if target.poll() is None:
        target.send_signal(signal.SIGINT)
    try:
        out, _ = target.communicate(timeout=3)
    except subprocess.TimeoutExpired:  # a hung V2
        target.kill()
        out, _ = target.communicate()
    return out or ""


class CellFailed(RuntimeError):
    """The scanner or the attacker stopped early, so the cell measured nothing."""


def run_cell(args: argparse.Namespace, policy: str, condition: str) -> dict:
    """One run on one core. The scanner is already scanning when the attack
    starts: the hogs begin after its first scan, and only scans in the next
    `args.seconds` count, timed as their lines arrive. Raises CellFailed if the
    scanner never scans, or the scanner or attacker stops before the window
    ends, so a failure can't read as starvation. Every child is stopped on the
    way out, whatever happens."""
    pol, cond = POLICIES[policy], CONDITIONS[condition]
    monitor, attacker = _make_cgroups()
    target: subprocess.Popen | None = None
    helpers: list[subprocess.Popen] = []  # scanner and hogs
    other: deque[str] = deque(maxlen=20)  # the scanner's non-scan lines, for errors
    target_out = ""

    def failed(why: str) -> CellFailed:
        tail = "".join(other).strip() or "(no other output)"
        return CellFailed(f"{policy}/{condition}: {why}; scanner said:\n{tail}")

    try:
        # The hiding process is the attacker too, so it gets the attacker's priority.
        target = subprocess.Popen(
            [getattr(args, f"{cond.attacker}_bin"), *ATTACKER_ARGS[cond.attacker]],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            preexec_fn=_child_setup(args.cpu, nice=args.attacker_nice),
        )
        _join(attacker, target.pid)
        time.sleep(1)  # let V2 lock its buffer before the first scan
        scanner = subprocess.Popen(
            scanner_command(args.repo, target.pid, args.interval, args.seconds + 5),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
            preexec_fn=_child_setup(args.cpu, fifo=pol.fifo),
        )
        helpers.append(scanner)
        _join(monitor if pol.own_cgroup else attacker, scanner.pid)
        lines = iter(scanner.stdout.readline, "")
        for line in lines:
            if _SCAN.match(line.strip()):
                break
            other.append(line)
        else:
            raise failed("the scanner exited before its first scan")
        for _ in range(args.hogs if cond.hogs else 0):
            hog = subprocess.Popen(
                [sys.executable, "-c", HOG],
                preexec_fn=_child_setup(args.cpu, nice=args.attacker_nice),
            )
            helpers.append(hog)
            _join(attacker, hog.pid)
        t_end = time.monotonic() + args.seconds
        window = []
        for line in lines:
            if time.monotonic() > t_end:
                break
            if _SCAN.match(line.strip()):
                window.append(line)
            else:
                other.append(line)
        if time.monotonic() <= t_end:
            raise failed("the scanner stopped before the window ended")
        if target.poll() is not None:
            raise failed(f"the attacker exited early (code {target.returncode})")
    finally:
        for p in reversed(helpers):
            p.kill()
            p.wait()
        if target is not None:
            target_out = _stop_target(target)
        _remove_cgroups()
    faults = _V2_FAULTS.search(target_out)
    return {
        "policy": policy, "condition": condition, "attacker": cond.attacker, "cpu": args.cpu,
        "hogs": len(helpers) - 1, "attacker_nice": args.attacker_nice,
        "seconds": args.seconds, "interval_s": args.interval,
        **asdict(summarize(window, args.seconds)),
        "v2_faults": int(faults.group(1)) if faults else None,  # V2 only
    }


def check_out(path: Path) -> None:
    """Refuse an existing CSV with other columns before any cell runs, so a
    mismatch can't throw away a finished sweep."""
    if path.exists():
        with path.open() as f:
            if next(csv.reader(f), None) != FIELDS:
                sys.exit(f"{path} has different columns; pass a new --out")


def _write(row: dict, path: Path) -> None:
    """Append one row, as soon as its cell finishes, so an interrupted sweep
    keeps every cell it completed."""
    assert list(row) == FIELDS, list(row)
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with path.open("a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)
    uid = int(os.environ.get("PKEXEC_UID", os.environ.get("SUDO_UID", "-1")))
    if uid >= 0:  # hand the results back to the user who ran pkexec
        gid = pwd.getpwuid(uid).pw_gid
        os.chown(path, uid, gid)
        os.chown(path.parent, uid, gid)


def _exit_on_signal(signum, frame):
    raise SystemExit(128 + signum)  # unwinds, so run_cell stops every child


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Coupled attack on the real kernel (#15)")
    ap.add_argument("--repo", default=".", help="repo root (pkexec starts in /root)")
    ap.add_argument("--v1-bin", help="V1 binary (default: <repo>/memory/bin/v1)")
    ap.add_argument("--v2-bin", help="V2 binary (default: <repo>/memory/bin/v2)")
    ap.add_argument("--cpu", type=int, default=2, help="core to pin everything to")
    ap.add_argument("--hogs", type=int, default=4, help="hogs in starvation and coupled")
    ap.add_argument("--attacker-nice", "--hog-nice", type=int, default=-20,
                    help="the attacker's claimed priority (V1/V2 and the hogs); 0 = equal nice")
    ap.add_argument("--seconds", type=float, default=20.0, help="counted scan window per cell")
    # 37 ms does not divide V2's 100 ms period, so scans sweep its whole cycle.
    ap.add_argument("--interval", type=float, default=0.037, help="scanner sleep between scans")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--policies", nargs="+", default=list(POLICIES), choices=list(POLICIES))
    ap.add_argument("--conditions", nargs="+", default=list(CONDITIONS), choices=list(CONDITIONS))
    ap.add_argument("--out", help="CSV (default: <repo>/results/coupled_live.csv)")
    args = ap.parse_args(argv)
    args.v1_bin = args.v1_bin or str(Path(args.repo) / "memory/bin/v1")
    args.v2_bin = args.v2_bin or str(Path(args.repo) / "memory/bin/v2")
    if os.geteuid() != 0:
        sys.exit(f"needs root; run: pkexec {sys.executable} {Path(__file__).resolve()} "
                 f"--repo {Path(args.repo).resolve()}")
    for b in {CONDITIONS[c].attacker for c in args.conditions}:
        if not Path(getattr(args, f"{b}_bin")).exists():
            sys.exit(f"no {b.upper()} binary at {getattr(args, f'{b}_bin')}; run `make -C memory` first")

    out = Path(args.out or Path(args.repo) / "results/coupled_live.csv")
    check_out(out)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _exit_on_signal)
    others = set(range(os.cpu_count() or 1)) - {args.cpu}
    if others:  # keep the harness off the measured core, so it timestamps lines on time
        os.sched_setaffinity(0, others)
    run_id = time.strftime("%Y%m%d-%H%M%S")
    for rep in range(args.reps):
        for condition in args.conditions:
            for policy in args.policies:
                row = {"run_id": run_id, "rep": rep, **run_cell(args, policy, condition)}
                print(row, flush=True)
                _write(row, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
