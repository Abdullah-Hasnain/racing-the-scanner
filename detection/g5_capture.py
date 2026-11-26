"""G5 capture and scoring (#13).

`capture` (root) starts Tracee with the custom and default-signature policies,
then runs batches: the benign workloads for 40 s, and from +10 s the attackers
for 20 s (V2 with a different timing each batch, V3, V4). Every process each
launcher starts is recorded per batch in label,pid,comm CSVs. Workloads and
attackers run as the user who called pkexec, not as root. The userfaultfd
sysctl V3 needs is restored afterwards.

`capture` stops, naming the label, if a launcher has died or its deepest
process isn't the expected program when the batch is recorded, so a runtime
missing from pkexec's PATH can't be scored as a benign process. SIGTERM and
SIGHUP unwind like Ctrl-C, and Tracee and every launcher die with the capture.

`score` (no root) scores each batch with detection.harness, labelling the
deepest process under each launcher (gcstress, not the go toolchain). It skips
a batch whose run id is already in detection_g5.csv: scoring one twice would
duplicate its default_sigs and custom rows, which G5 sums.

From the repo root:

  pkexec "$PWD/.venv/bin/python" "$PWD/detection/g5_capture.py" capture --repo "$PWD"
  .venv/bin/python detection/g5_capture.py score results/g5/<run_id>
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import ctypes
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pwd  # POSIX only; imported where it's used so the module loads on Windows

# One V2 timing per batch: 10, 50, 2, 1 and 20 accesses/s, three access patterns.
V2_TIMINGS = [
    "--dwell-ms 10 --interval-ms 100 --pattern seq",
    "--dwell-ms 2 --interval-ms 20 --pattern random",
    "--dwell-ms 50 --interval-ms 500 --pattern stride",
    "--dwell-ms 20 --interval-ms 1000 --pattern seq",
    "--dwell-ms 5 --interval-ms 50 --pattern random",
]
BENIGN = ["node", "go-gc", "java-gc", "malloc", "sqlite"]  # plus the --stub JIT stand-in
POLICIES = ["detection/tracee/memory-hiding.yaml", "detection/tracee/default-signatures.yaml"]
UFFD_SYSCTL = Path("/proc/sys/vm/unprivileged_userfaultfd")
BENIGN_S, ATTACK_DELAY_S, ATTACK_S = 40, 10, 20
STOP_WAIT_S = 5
TRACEE_START_S = 60  # give up if Tracee writes no event in this long
PR_SET_PDEATHSIG = 1
REPO = Path(__file__).resolve().parents[1]
# The program each launcher's deepest process must be when the batch is recorded.
EXPECTED_COMM = {
    "benign:node": "node", "benign:go-gc": "gcstress", "benign:java-gc": "java",
    "benign:malloc": "malloc_churn", "benign:sqlite": "python", "benign:jit-stub": "python",
    "attacker:v2": "v2", "attacker:v3": "v3", "attacker:v4": "v4",
}


def batch_problems(rows: Iterable[dict], exit_codes: dict[str, int | None]) -> list[str]:
    """Why a recorded batch can't be scored: a launcher that already exited, or a
    deepest process that isn't the program its label expects (python matches
    python3). exit_codes maps each label to its launcher's exit code, None if running."""
    last: dict[str, str] = {}
    for r in rows:
        last[r["label"]] = r["comm"]
    problems = [f"{label} exited with code {rc} before the batch was recorded"
                for label, rc in exit_codes.items() if rc is not None]
    for label, comm in last.items():
        want = EXPECTED_COMM.get(label)
        if exit_codes.get(label) is None and want and not comm.startswith(want):
            problems.append(f"{label}: deepest process is {comm!r}, expected {want!r}")
    return problems


def scored_pids(rows: Iterable[dict]) -> tuple[dict[str, int], dict[str, int]]:
    """(attackers, benign) as name -> pid, taking the last (deepest) row per label."""
    last: dict[str, int] = {}
    for r in rows:
        last[r["label"]] = int(r["pid"])
    side = {"attacker": {}, "benign": {}}
    for label, pid in last.items():
        kind, name = label.split(":", 1)
        side[kind][name] = pid
    return side["attacker"], side["benign"]


def harness_args(rows: Iterable[dict]) -> list[str]:
    attackers, benign = scored_pids(rows)
    return ["--attacker-pid", *map(str, attackers.values()),
            "--benign-pid", *map(str, benign.values())]


def chain_below(path: Path, top: Path) -> list[Path]:
    """path and each parent of it below top, deepest first (just path if not under top)."""
    if not path.is_relative_to(top):
        return [path]
    rel = path.relative_to(top)
    return [top / q for q in [rel, *rel.parents][:-1]]  # parents ends with "."


def _hand_back(path: Path, top: Path, user: pwd.struct_passwd) -> None:
    """Give the user every root-owned entry from path up to (not including) top."""
    for p in chain_below(path, top):
        if p.exists() and p.stat().st_uid == 0:
            os.chown(p, user.pw_uid, user.pw_gid)


def _descendants(pid: int) -> list[int]:
    """pid and its descendants, parent first."""
    try:
        kids = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
    except OSError:
        return [pid]
    return [pid, *(d for k in kids for d in _descendants(int(k)))]


def _comm(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        return ""


def _die_with(parent: int) -> None:
    """In a child: get SIGKILLed when the capture dies, even by SIGKILL."""
    ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, signal.SIGKILL)
    if os.getppid() != parent:  # the capture died before prctl took effect
        os._exit(1)


def _as_user(user: pwd.struct_passwd):
    parent = os.getpid()

    def drop() -> None:
        os.setgid(user.pw_gid)
        os.initgroups(user.pw_name, user.pw_gid)
        os.setuid(user.pw_uid)
        _die_with(parent)  # after setuid, which clears the death signal
    return drop


def _stop(roots: Iterable[subprocess.Popen]) -> None:
    """SIGINT each launcher's process group still running, then SIGKILL it."""
    running = [p for p in roots if p.poll() is None]
    for p in running:
        with contextlib.suppress(ProcessLookupError):  # exited since poll()
            os.killpg(p.pid, signal.SIGINT)
    for p in running:
        try:
            p.wait(timeout=STOP_WAIT_S)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(p.pid, signal.SIGKILL)
            p.wait()


def _exit_on_signal(signum, frame):
    raise SystemExit(128 + signum)  # unwinds, so the finally blocks stop everything


def _batch(args: argparse.Namespace, i: int, run_dir: Path, user: pwd.struct_passwd) -> None:
    repo = Path(args.repo)
    env = {**os.environ, "HOME": user.pw_dir, "USER": user.pw_name, "LOGNAME": user.pw_name}
    run = lambda cmd, stdout=subprocess.DEVNULL: subprocess.Popen(  # noqa: E731
        cmd, cwd=repo, env=env, preexec_fn=_as_user(user), start_new_session=True,
        stdout=stdout, stderr=subprocess.STDOUT)
    benign_py = [sys.executable, str(repo / "detection/benign/run_benign.py")]
    bin_ = repo / "memory/bin"
    roots: dict[str, subprocess.Popen] = {}
    try:  # however this ends, no launcher outlives the batch
        for w in args.workloads:
            roots[f"benign:{w}"] = run([*benign_py, "--workload", w, "--seconds", str(BENIGN_S)])
        roots["benign:jit-stub"] = run([*benign_py, "--stub", "--seconds", str(BENIGN_S)])
        time.sleep(ATTACK_DELAY_S)  # go and java compile first
        with open(run_dir / f"v2_{i}.log", "w") as v2_log:
            roots["attacker:v2"] = run([str(bin_ / "v2"), *shlex.split(V2_TIMINGS[i % len(V2_TIMINGS)]),
                                        "--duration", str(ATTACK_S)], stdout=v2_log)
        roots["attacker:v3"] = run([str(bin_ / "v3")])  # V3 and V4 run until stopped
        roots["attacker:v4"] = run([str(bin_ / "v4")])
        time.sleep(5)
        rows = [{"label": label, "pid": pid, "comm": _comm(pid)}
                for label, p in roots.items() for pid in _descendants(p.pid)]
        if problems := batch_problems(rows, {label: p.poll() for label, p in roots.items()}):
            sys.exit(f"batch {i} can't be scored (is node/go/java on pkexec's PATH?):\n  "
                     + "\n  ".join(problems))
        time.sleep(ATTACK_S - 5)
        for label in ("attacker:v3", "attacker:v4"):
            roots[label].send_signal(signal.SIGINT)
        for label, p in roots.items():
            try:
                p.wait(timeout=BENIGN_S + STOP_WAIT_S)
            except subprocess.TimeoutExpired:  # the finally below stops it; the batch isn't recorded
                sys.exit(f"batch {i}: {label} still running after {BENIGN_S + STOP_WAIT_S} s; "
                         "stopped the capture")
    finally:
        _stop(roots.values())
    # Only a batch that passed its check and ran to the end is written, so score
    # never finds a broken or interrupted one.
    with open(run_dir / f"batch_{i}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["label", "pid", "comm"])
        w.writeheader()
        w.writerows(rows)


def invoker_uid_or_root() -> int:
    """The uid that ran pkexec or sudo; root when unset, empty or not a number."""
    for key in ("PKEXEC_UID", "SUDO_UID"):
        raw = os.environ.get(key, "").strip()
        if raw.isdigit():
            return int(raw)
    return 0


def wait_for_first_event(tracee: subprocess.Popen, log: Path, stderr: Path, deadline_s: float) -> None:
    """Block until Tracee writes its first event; exit if it dies or stays silent."""
    end = time.monotonic() + deadline_s
    while not (log.exists() and log.stat().st_size):
        if tracee.poll() is not None:
            sys.exit(f"Tracee exited early; see {stderr}")
        if time.monotonic() > end:
            sys.exit(f"Tracee wrote no event within {deadline_s:g} s; see {stderr}")
        time.sleep(min(1, deadline_s))


def capture(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        sys.exit(f"capture needs root; run: pkexec {sys.executable} {Path(__file__).resolve()} "
                 f"capture --repo {Path(args.repo).resolve()}")
    import pwd

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _exit_on_signal)
    user = pwd.getpwuid(invoker_uid_or_root())
    args.repo = str(Path(args.repo).resolve())
    run_id = time.strftime("%Y%m%d-%H%M%S")
    run_dir = Path(args.repo) / "results/g5" / run_id
    run_dir.mkdir(parents=True)
    log = Path(args.log or Path(user.pw_dir) / f"tracee/out/g5-{run_id}.json").resolve()
    log.parent.mkdir(parents=True, exist_ok=True)
    tracee_bin = args.tracee_bin or str(Path(user.pw_dir) / "tracee/v0.23.2/dist/tracee")
    uffd = UFFD_SYSCTL.read_text().strip()
    UFFD_SYSCTL.write_text("1")  # V3 runs as the user
    tracee = None
    completed = 0
    try:
        cmd = [tracee_bin, *(a for p in POLICIES for a in ("--policy", str(Path(args.repo) / p))),
               "--install-path", "/tmp/tracee-install",
               "--output", f"json:{log}", "--output", "option:parse-arguments"]
        with open(run_dir / "tracee.stderr", "w") as err:
            parent = os.getpid()
            tracee = subprocess.Popen(cmd, stdout=err, stderr=subprocess.STDOUT,
                                      preexec_fn=lambda: _die_with(parent))
        wait_for_first_event(tracee, log, run_dir / "tracee.stderr", TRACEE_START_S)
        time.sleep(15)  # let Tracee finish attaching
        for i in range(args.batches):
            if tracee.poll() is not None:
                sys.exit(f"Tracee exited during the capture; see {run_dir / 'tracee.stderr'}")
            _batch(args, i, run_dir, user)
            completed += 1
            print(f"batch {i} done ({V2_TIMINGS[i % len(V2_TIMINGS)]})", flush=True)
    finally:
        try:  # a second Ctrl-C while Tracee flushes must not skip the restore below
            if tracee is not None:
                tracee.send_signal(signal.SIGINT)
                try:
                    tracee.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    tracee.kill()
                    tracee.wait()
        finally:
            UFFD_SYSCTL.write_text(uffd)
            if completed:  # nothing to score otherwise
                (run_dir / "capture.json").write_text(
                    json.dumps({"tracee_log": str(log), "batches": completed}))
            for p in run_dir.iterdir():
                _hand_back(p, Path(args.repo), user)
            _hand_back(run_dir, Path(args.repo), user)  # also when no file was written
            _hand_back(log, Path(user.pw_dir), user)
    print(f"captured {completed} batches into {log}; score with:\n"
          f"  .venv/bin/python detection/g5_capture.py score {run_dir}")
    return 0


def scored_run_ids(csv_path: Path) -> set[str]:
    if not csv_path.exists():
        return set()
    with csv_path.open(newline="", encoding="utf-8") as f:
        return {r.get("run_id") for r in csv.DictReader(f)}


def score(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir).resolve()
    log = json.loads((run_dir / "capture.json").read_text())["tracee_log"]
    # the harness runs from the repo root, so a relative RTS_RESULTS_DIR is read from there
    done = scored_run_ids(REPO / os.environ.get("RTS_RESULTS_DIR", "results") / "detection_g5.csv")
    for batch in sorted(run_dir.glob("batch_*.csv")):
        run_id = f"{run_dir.name}-{batch.stem}"
        if run_id in done:
            print(f"{run_id} is already in detection_g5.csv; skipped (move that file aside to re-score)")
            continue
        with batch.open() as f:
            rows = list(csv.DictReader(f))
        cmd = [sys.executable, "-m", "detection.harness", "--tracee-log", log,
               "--run-id", run_id, *harness_args(rows)]
        if args.no_llm:
            cmd.append("--no-llm")
        subprocess.run(cmd, check=True, cwd=REPO)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="G5 capture (root) and scoring (#13)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("capture", help="run Tracee and the batches (needs root)")
    c.add_argument("--repo", default=".", help="repo root (pkexec starts in /root)")
    c.add_argument("--batches", type=int, default=len(V2_TIMINGS))
    c.add_argument("--workloads", nargs="+", default=BENIGN)
    c.add_argument("--tracee-bin", help="default: ~/tracee/v0.23.2/dist/tracee of the pkexec user")
    c.add_argument("--log", help="Tracee JSON output (default: ~/tracee/out/g5-<run_id>.json)")
    s = sub.add_parser("score", help="score each batch not yet in detection_g5.csv")
    s.add_argument("run_dir")
    s.add_argument("--no-llm", action="store_true")
    args = ap.parse_args(argv)
    return capture(args) if args.cmd == "capture" else score(args)


if __name__ == "__main__":
    raise SystemExit(main())
