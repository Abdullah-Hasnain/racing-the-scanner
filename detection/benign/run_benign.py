"""The benign false-alarm suite driver (Member 3).

Runs the legitimate memory-heavy workloads whose syscall patterns overlap with
the attacker, so we can measure how often Tracee false-alarms on them and how
much the AI triage cuts that. Every workload runs for --seconds (default 30)
and then exits 0. Compiled workloads are built into a temp directory first, so
no compiler runs inside the workload's process. On SIGTERM or SIGINT (the harness
ends a live capture that way) the workload is stopped and the temp directory
removed before this exits.

    python3 detection/benign/run_benign.py --workload NAME [--seconds N]
    python3 detection/benign/run_benign.py --stub [--seconds N]

Workloads (expected memory syscalls in parentheses):
  node     Node.js V8 JIT: compiles and runs functions with fresh source text
           every tick, so V8's compilation cache never short-circuits them
           (mprotect RW<->RX flips on code pages, mmap/munmap).
  go-gc    Go GC allocator loop, benign/gcstress.go, built with `go build`
           (madvise MADV_DONTNEED / MADV_FREE on scavenge; Go commits arena
           spans with mmap(MAP_FIXED), not mprotect, so few PROT_NONE flips).
  java-gc  JVM GC allocator loop, benign/GcStress.java, compiled in its own
           process, then run as `java -cp <tmp> GcStress`
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
import signal
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# n only grows, so every function's source is new and V8 compiles each one.
NODE_JS = (
    "const end=Date.now()+%s*1000;let n=0,rounds=0;"
    "(function t(){if(Date.now()>=end){console.log('[benign-node] '+rounds+' rounds');return}"
    "for(let i=0;i<200;i++){const f=new Function('a','return a*'+(++n)+'+1');"
    "for(let j=0;j<500;j++)f(j)}"
    "rounds++;setTimeout(t,1)})()"
)

# workload -> (required binary, Ubuntu install command)
REQUIRES = {
    "node": ("node", "sudo apt install nodejs"),
    "go-gc": ("go", "sudo apt install golang-go"),
    "java-gc": ("java", "sudo apt install default-jdk-headless"),
    "malloc": ("gcc", "sudo apt install build-essential"),
    "sqlite": (None, ""),
}


def _run(cmd: list[str]) -> int:
    """Run cmd to completion, and stop it if we are interrupted first."""
    child = subprocess.Popen(cmd)
    try:
        return child.wait()
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def _built(build: list[str], run: list[str]) -> int:
    """Run the build step, then the workload, unless the build fails."""
    return _run(build) or _run(run)


def run_malloc(seconds: float) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "malloc_churn")
        return _built(["gcc", "-O1", "-o", exe, str(HERE / "malloc_churn.c")], [exe, str(seconds)])


def run_go(seconds: float) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "gcstress")
        return _built(
            ["go", "build", "-o", exe, str(HERE / "gcstress.go")], [exe, "-seconds", str(seconds)]
        )


def run_java(seconds: float) -> int:
    # The compiler through the java launcher: Ubuntu's JRE ships jdk.compiler
    # without a javac binary, and a full JDK has both.
    with tempfile.TemporaryDirectory() as tmp:
        return _built(
            ["java", "-m", "jdk.compiler/com.sun.tools.javac.Main", "-d", tmp,
             str(HERE / "GcStress.java")],
            ["java", "-cp", tmp, "GcStress", str(seconds)],
        )


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
                # Alternate the parity so last round's survivors go too and the
                # DB stays near one round's rows, well inside mmap_size.
                db.execute("DELETE FROM t WHERE id % 2 = ?", (rounds % 2,))
            db.execute("VACUUM")
            rounds += 1
        db.close()
    print(f"[benign-sqlite] {rounds} rounds")
    return 0


WORKLOADS = {
    "node": lambda s: _run(["node", "-e", NODE_JS % s]),
    "go-gc": run_go,
    "java-gc": run_java,
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


def _exit_on_sigterm(signum, frame):
    raise SystemExit(128 + signum)  # unwinds, so the child stops and temp dirs go


def main() -> int:
    signal.signal(signal.SIGTERM, _exit_on_sigterm)
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
