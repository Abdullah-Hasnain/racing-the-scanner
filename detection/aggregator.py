"""D3 (part 1): per-PID Tracee log aggregator.

Reads Aqua Tracee JSON events (one JSON object per line) from a file or stdin and
rolls them up into one feature record per PID per time window (default 1 s). The
record is what the local-LLM triage layer (triage_llm.py) reviews to decide
whether a burst of mprotect/madvise/userfaultfd/memfd_secret activity is a real
hiding attempt or ordinary JIT/GC behavior.

This runs with no dependencies and works offline on a saved Tracee log, so it is
developable without a live Tracee install.

Usage:
  tracee ... --output json | python aggregator.py --window 1.0
  python aggregator.py --input tracee_events.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field

WATCHED = ("mprotect", "madvise", "userfaultfd", "memfd_secret")


@dataclass
class PidWindow:
    pid: int
    comm: str = ""
    syscalls: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    prot_none_to_rw: int = 0   # hallmark of V2-style hiding
    rw_to_rx: int = 0          # hallmark of JIT (benign)
    sigsegv: int = 0
    threads: int = 0
    alerts: int = 0

    def as_features(self) -> dict:
        return {
            "pid": self.pid,
            "comm": self.comm,
            **{f"n_{k}": self.syscalls.get(k, 0) for k in WATCHED},
            "prot_none_to_rw": self.prot_none_to_rw,
            "rw_to_rx": self.rw_to_rx,
            "sigsegv": self.sigsegv,
            "threads": self.threads,
            "tracee_alerts": self.alerts,
        }


def _prot_flags(event: dict) -> tuple[str, str]:
    """Best-effort extraction of (old, new) mprotect protection. Tracee field
    names vary by version, so this is intentionally defensive."""
    args = {a.get("name"): a.get("value") for a in event.get("args", [])}
    return str(args.get("prev_prot", "")), str(args.get("prot", ""))


def aggregate(lines) -> dict[int, PidWindow]:
    windows: dict[int, PidWindow] = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        pid = int(ev.get("processId", ev.get("pid", -1)))
        if pid < 0:
            continue
        w = windows.setdefault(pid, PidWindow(pid=pid))
        w.comm = ev.get("processName", w.comm)
        name = ev.get("eventName", "")
        if name in WATCHED:
            w.syscalls[name] += 1
        if name == "mprotect":
            old, new = _prot_flags(ev)
            if "NONE" in old and ("READ" in new or "WRITE" in new):
                w.prot_none_to_rw += 1
            if ("WRITE" in old or "READ" in old) and "EXEC" in new:
                w.rw_to_rx += 1
        if name in ("sigsegv", "signal") and "SEGV" in json.dumps(ev):
            w.sigsegv += 1
        if ev.get("metadata", {}).get("Properties", {}).get("signatureName"):
            w.alerts += 1
    return windows


def main() -> int:
    ap = argparse.ArgumentParser(description="Tracee per-PID aggregator (D3)")
    ap.add_argument("--input", help="Tracee JSON file; omit to read stdin")
    ap.add_argument("--window", type=float, default=1.0, help="(reserved) window seconds")
    args = ap.parse_args()

    src = open(args.input) if args.input else sys.stdin
    windows = aggregate(src)
    for w in windows.values():
        print(json.dumps(w.as_features()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
