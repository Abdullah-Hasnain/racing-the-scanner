"""The benign false-alarm suite driver (Member 3).

Runs the legitimate memory-heavy workloads whose syscall patterns overlap with
the attacker, so we can measure how often Tracee false-alarms on them and how
much the AI triage cuts that.

Real workloads (preferred, when the runtimes are installed):
  - Node.js (V8 JIT): flips pages RW<->RX constantly.
  - Go or Java (GC): PROT_NONE guard pages, MADV_DONTNEED.
  - jemalloc / SQLite: MADV_DONTNEED on free.

If a runtime is missing, this prints the exact command to run it. It also ships
a pure-Python stand-in (--stub) that exercises mmap + mprotect flips so the
Tracee -> aggregator -> triage pipeline can be developed end to end without any
external runtime.
"""

from __future__ import annotations

import argparse
import ctypes
import mmap
import shutil
import time

WORKLOADS = {
    "node": ["node", "-e", "setInterval(()=>{const f=new Function('return 1');f()},1)"],
    "go-gc": ["go", "run", "./benign/gcstress.go"],   # add gcstress.go as an issue
    "sqlite": ["sqlite3", ":memory:", "VACUUM;"],
}


def run_stub(seconds: float) -> None:
    """Exercise mprotect RW<->RX flips like a JIT, with no external runtime."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    size = mmap.PAGESIZE * 16
    buf = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
    page = addr & ~(mmap.PAGESIZE - 1)
    PROT_RW = mmap.PROT_READ | mmap.PROT_WRITE
    PROT_RX = mmap.PROT_READ | mmap.PROT_EXEC
    print("[benign-stub] flipping a page RW<->RX like a JIT. Ctrl-C to stop.")
    end = time.time() + seconds
    while time.time() < end:
        libc.mprotect(ctypes.c_void_p(page), mmap.PAGESIZE, PROT_RX)
        libc.mprotect(ctypes.c_void_p(page), mmap.PAGESIZE, PROT_RW)
        time.sleep(0.001)
    buf.close()


def main() -> int:
    ap = argparse.ArgumentParser(description="Benign false-alarm suite")
    ap.add_argument("--workload", choices=list(WORKLOADS), help="real runtime to launch")
    ap.add_argument("--stub", action="store_true", help="run the dependency-free JIT stand-in")
    ap.add_argument("--seconds", type=float, default=30.0)
    args = ap.parse_args()

    if args.stub or not args.workload:
        run_stub(args.seconds)
        return 0

    cmd = WORKLOADS[args.workload]
    if shutil.which(cmd[0]) is None:
        print(f"[benign] '{cmd[0]}' not installed. Install it, or run with --stub.")
        print("         command would be:", " ".join(cmd))
        return 1
    import subprocess
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
