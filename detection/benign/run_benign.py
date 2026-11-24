"""The benign false-alarm suite driver (Member 3).

Runs the legitimate memory-heavy workloads whose syscall patterns overlap with
the attacker, so we can measure how often Tracee false-alarms on them and how
much the AI triage cuts that. Every workload runs for --seconds (default 30)
and then exits 0.

    python3 detection/benign/run_benign.py --workload NAME [--seconds N]
    python3 detection/benign/run_benign.py --stub [--seconds N]

Workloads (expected memory syscalls in parentheses):
  node     Node.js V8 JIT: compiles and runs many fresh functions
           (mprotect RW<->RX flips on code pages, mmap/munmap).
  go-gc    Go GC allocator loop, benign/gcstress.go (PROT_NONE arena
           reservations, madvise MADV_DONTNEED / MADV_FREE on scavenge).
  java-gc  JVM GC allocator loop, benign/GcStress.java, run as `java GcStress.java`
           (mmap/munmap, mprotect guard pages, madvise on heap uncommit).
  malloc   benign/malloc_churn.c, built on demand with gcc: allocate, touch and
           free 32 MB, then malloc_trim (madvise MADV_DONTNEED), the way
           jemalloc and SQLite free memory.
  sqlite   Python's stdlib sqlite3 on a temp-file DB: insert/delete batches plus
           VACUUM, with mmap I/O enabled (mmap/munmap/mremap, file I/O).
           Needs no extra install.

If a runtime is missing, this prints the Ubuntu install command and exits 1.
--stub is a pure-Python stand-in (mmap + mprotect RW<->RX flips) so the
Tracee -> aggregator -> triage pipeline can be developed with no external
runtime.
"""

from __future__ import annotations

import argparse
import ctypes
import mmap
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

NODE_JS = (
    "const end=Date.now()+%s*1000;"
    "(function t(){if(Date.now()>=end)return;"
    "for(let i=0;i<200;i++){const f=new Function('a','return a*'+i+'+1');"
    "for(let j=0;j<500;j++)f(j)}"
    "setTimeout(t,1)})()"
)

# workload -> (required binary, Ubuntu install command)
REQUIRES = {
    "node": ("node", "sudo apt install nodejs"),
    "go-gc": ("go", "sudo apt install golang-go"),
    "java-gc": ("java", "sudo apt install default-jre-headless"),
    "malloc": ("gcc", "sudo apt install build-essential"),
    "sqlite": (None, ""),
}


def run_malloc(seconds: float) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "malloc_churn")
        cc = subprocess.call(["gcc", "-O1", "-o", exe, str(HERE / "malloc_churn.c")])
        if cc != 0:
            return cc
        return subprocess.call([exe, str(seconds)])


def run_sqlite(seconds: float) -> int:
    end = time.time() + seconds
    rounds = 0
    with tempfile.TemporaryDirectory() as tmp:
        db = sqlite3.connect(os.path.join(tmp, "churn.db"))
        db.execute("PRAGMA mmap_size=67108864")
        db.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, pad BLOB)")
        while time.time() < end:
            with db:
                db.executemany(
                    "INSERT INTO t(pad) VALUES (?)", ((os.urandom(2048),) for _ in range(5000))
                )
                db.execute("DELETE FROM t WHERE id % 2 = 0")
            db.execute("VACUUM")
            rounds += 1
        db.close()
    print(f"[benign-sqlite] {rounds} rounds")
    return 0


WORKLOADS = {
    "node": lambda s: subprocess.call(["node", "-e", NODE_JS % s]),
    "go-gc": lambda s: subprocess.call(
        ["go", "run", str(HERE / "gcstress.go"), "-seconds", str(s)]
    ),
    "java-gc": lambda s: subprocess.call(["java", str(HERE / "GcStress.java"), str(s)]),
    "malloc": run_malloc,
    "sqlite": run_sqlite,
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
    print("[benign-stub] flipping a page RW<->RX like a JIT.")
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

    binary, install = REQUIRES[args.workload]
    if binary and shutil.which(binary) is None:
        print(f"[benign] '{binary}' not installed. Install it with:")
        print(f"         {install}")
        print("         or run with --stub.")
        return 1
    return WORKLOADS[args.workload](args.seconds)


if __name__ == "__main__":
    raise SystemExit(main())
