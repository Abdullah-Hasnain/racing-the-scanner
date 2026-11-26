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
import contextlib
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntFlag, StrEnum

WATCHED = ("mprotect", "madvise", "userfaultfd", "memfd_secret")
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
    names only the PROT_* bits, so a PROT_NONE region renders as "". A numeric
    string ("0x70") is read as the raw value.
    """
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError:
            prot = Prot(0)
            for tok in value.split("|"):
                prot |= _PROT_NAMES.get(tok.strip(), Prot(0))
            return prot
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
    """An int Tracee printed raw or as a string: hex with 0x (pointers, "0x0"),
    or decimal as hand-written fixtures may quote it ("4096")."""
    return int(value, 0) if isinstance(value, str) else int(value)


def _args(event: dict) -> dict:
    return {a.get("name"): a.get("value") for a in event.get("args", [])}


@dataclass
class ProcessFeatures:
    pid: int
    comm: str = ""
    syscalls: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    flips: dict[Flip, int] = field(default_factory=lambda: defaultdict(int))
    segv_handlers: int = 0  # rt_sigaction calls that install a SIGSEGV handler
    relock_trips: int = 0  # regions unlocked from PROT_NONE, then locked again
    # working state, not a feature: (addr, len) regions unlocked and not yet relocked
    unlocked: set[tuple[int, int]] = field(default_factory=set, repr=False)
    # working state: comm came from the main thread, so worker names no longer override it
    named_by_main: bool = field(default=False, repr=False)
    alerts: int = 0

    def mprotect(self, event: dict) -> None:
        """Count a security_file_mprotect event's flip and any relock round trip.

        Only this LSM event has prev_prot; the raw mprotect syscall event does not.
        A round trip is keyed by the exact (addr, len) the unlock used.
        """
        args = _args(event)
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
    args = _args(event)
    act = args.get("act") or 0
    return args.get("signum") == SIGSEGV and _int(act) != 0


def aggregate(lines) -> dict[int, ProcessFeatures]:
    procs: dict[int, ProcessFeatures] = {}
    skipped = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:  # e.g. a last line cut short when Tracee was killed
            skipped += 1
            continue
        pid = int(ev.get("processId", ev.get("pid", -1)))
        if pid < 0:
            continue
        w = procs.setdefault(pid, ProcessFeatures(pid=pid))
        # Name the process after its main thread: workers carry their own names
        # ("V8Worker", "C1 CompilerThre"), and exec renames the main thread, so
        # its latest name wins. A process seen only through workers keeps theirs.
        main_thread = int(ev.get("threadId", pid)) == pid
        if main_thread or not w.named_by_main:
            w.comm = ev.get("processName", w.comm)
            w.named_by_main = w.named_by_main or main_thread
        name = ev.get("eventName", "")
        if name in WATCHED:
            w.syscalls[name] += 1
        if name == "security_file_mprotect":
            w.mprotect(ev)
        if name == "rt_sigaction" and _installs_segv_handler(ev):
            w.segv_handlers += 1
        if ((ev.get("metadata") or {}).get("Properties") or {}).get("signatureName"):
            w.alerts += 1
    if skipped:
        print(f"aggregator: skipped {skipped} lines that are not JSON", file=sys.stderr)
    return procs


def main() -> int:
    ap = argparse.ArgumentParser(description="Tracee per-PID aggregator (D3)")
    ap.add_argument("--input", help="Tracee JSON file; omit to read stdin")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") if args.input else contextlib.nullcontext(sys.stdin) as src:
        procs = aggregate(src)
    for w in procs.values():
        print(json.dumps(w.as_features()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
