"""D3 (part 1): per-PID Tracee log aggregator.

Reads Aqua Tracee JSON events (one JSON object per line) from a file or stdin and
rolls them up into one feature record per process over the whole capture. The
record is what the local-LLM triage layer (triage_llm.py) reviews to decide
whether a burst of mprotect/madvise/userfaultfd/memfd_secret activity is a real
hiding attempt or ordinary JIT/GC behavior.

This runs with no dependencies and works offline on a saved Tracee log, so it is
developable without a live Tracee install.

Usage:
  tracee ... --output json | python aggregator.py
  python aggregator.py --input tracee_events.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntFlag, StrEnum

WATCHED = ("mprotect", "madvise", "userfaultfd", "memfd_secret", "rt_sigreturn")
SIGSEGV = 11


class Prot(IntFlag):
    """The access bits of a memory protection. No bits set is PROT_NONE."""

    R = 1
    W = 2
    X = 4


class Flip(StrEnum):
    """A protection change worth counting, valued by its feature name."""

    NONE_RW = "none_rw_flips"  # to or from PROT_NONE: V2-style lock and unlock
    RW_RX = "rw_rx_flips"      # write access swapped for exec, or back: a JIT


_ACCESS = Prot.R | Prot.W | Prot.X
_PROT_NAMES = {"PROT_READ": Prot.R, "PROT_WRITE": Prot.W, "PROT_EXEC": Prot.X}


def _parse_prot(value: int | str) -> Prot:
    """Tracee's prot or prev_prot, raw or parsed, as access bits.

    Raw prev_prot is the region's vm_flags, which carries bits above R/W/X
    (VM_MAYREAD and friends); they are dropped. With parse-arguments on, Tracee
    names only the PROT_* bits, so a PROT_NONE region renders as "".
    """
    if isinstance(value, str):
        return Prot(sum(_PROT_NAMES.get(tok, 0) for tok in value.split("|")))
    return Prot(value & _ACCESS)


def _flip(prev: Prot, new: Prot) -> Flip | None:
    """The flip a protection change from prev to new is.

    Any change to or from PROT_NONE is a NONE_RW flip, whatever the other side,
    so a hider gains nothing by unlocking with exec or read-only access.
    """
    if (not prev) != (not new):
        return Flip.NONE_RW
    if {prev & (Prot.W | Prot.X), new & (Prot.W | Prot.X)} == {Prot.W, Prot.X}:
        return Flip.RW_RX
    return None


def _int(value: int | str) -> int:
    return int(value, 16) if isinstance(value, str) else int(value)


@dataclass
class ProcessFeatures:
    pid: int
    comm: str = ""
    syscalls: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    flips: dict[Flip, int] = field(default_factory=lambda: defaultdict(int))
    segv_handlers: int = 0  # rt_sigaction calls that install a SIGSEGV handler
    relock_trips: int = 0  # regions unlocked from PROT_NONE, then locked again
    unlocked: set[tuple[int, int]] = field(default_factory=set)  # (addr, len) now open
    alerts: int = 0

    def mprotect(self, event: dict) -> None:
        """Count a security_file_mprotect event's flip and any relock round trip.

        Only this LSM event has prev_prot; the raw mprotect syscall event does not.
        A round trip is keyed by the exact (addr, len) the unlock used.
        """
        args = {a.get("name"): a.get("value") for a in event.get("args", [])}
        if "prot" not in args or "prev_prot" not in args:
            return
        prev, new = _parse_prot(args["prev_prot"]), _parse_prot(args["prot"])
        if not (flip := _flip(prev, new)):
            return
        self.flips[flip] += 1
        if flip is not Flip.NONE_RW or "addr" not in args:
            return
        region = (_int(args["addr"]), _int(args.get("len", 0)))
        if not prev:
            self.unlocked.add(region)
        elif region in self.unlocked:
            self.unlocked.remove(region)
            self.relock_trips += 1

    def as_features(self) -> dict:
        return {
            "pid": self.pid,
            "comm": self.comm,
            **{f"n_{k}": self.syscalls.get(k, 0) for k in WATCHED},
            **{f.value: self.flips.get(f, 0) for f in Flip},
            "relock_trips": self.relock_trips,
            "segv_handlers": self.segv_handlers,
            "tracee_alerts": self.alerts,
        }


def _installs_segv_handler(event: dict) -> bool:
    """True when an rt_sigaction call sets (not just queries) the SIGSEGV handler.

    Tracee has no SIGSEGV-delivery event; see "Signal features" in README.md.
    Tracee prints signum as an int and pointers as hex strings ("0x0" is null).
    """
    args = {a.get("name"): a.get("value") for a in event.get("args", [])}
    act = args.get("act") or 0
    return args.get("signum") == SIGSEGV and _int(act) != 0


def aggregate(lines) -> dict[int, ProcessFeatures]:
    procs: dict[int, ProcessFeatures] = {}
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
        w = procs.setdefault(pid, ProcessFeatures(pid=pid))
        w.comm = ev.get("processName", w.comm)
        name = ev.get("eventName", "")
        if name in WATCHED:
            w.syscalls[name] += 1
        if name == "security_file_mprotect":
            w.mprotect(ev)
        if name == "rt_sigaction" and _installs_segv_handler(ev):
            w.segv_handlers += 1
        if ev.get("metadata", {}).get("Properties", {}).get("signatureName"):
            w.alerts += 1
    return procs


def main() -> int:
    ap = argparse.ArgumentParser(description="Tracee per-PID aggregator (D3)")
    ap.add_argument("--input", help="Tracee JSON file; omit to read stdin")
    args = ap.parse_args()

    src = open(args.input) if args.input else sys.stdin
    for w in aggregate(src).values():
        print(json.dumps(w.as_features()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
