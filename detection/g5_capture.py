"""G5 capture and scoring (#13).

`capture` (root) starts Tracee with the custom and default-signature policies,
then runs batches: the benign workloads for 40 s, and from +10 s the attackers
for 20 s (V2 with a different timing each batch, V3, V4). Every process each
launcher starts is recorded per batch in label,pid,comm CSVs. Workloads and
attackers run as the user who called pkexec, not as root. The userfaultfd
sysctl V3 needs is restored afterwards.

`score` (no root) scores each batch once with detection.harness, labelling the
deepest process under each launcher (gcstress, not the go toolchain). Scoring a
capture twice would duplicate its default_sigs and custom rows.

From the repo root:

  pkexec "$PWD/.venv/bin/python" "$PWD/detection/g5_capture.py" capture --repo "$PWD"
  .venv/bin/python detection/g5_capture.py score results/g5/<run_id>
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import pwd
import shlex
import signal
import subprocess
import sys
import time
from collections.abc import Iterable
from pathlib import Path

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


def _as_user(user: pwd.struct_passwd):
    def drop() -> None:
        os.setgid(user.pw_gid)
        os.initgroups(user.pw_name, user.pw_gid)
        os.setuid(user.pw_uid)
    return drop


def _batch(args: argparse.Namespace, i: int, run_dir: Path, user: pwd.struct_passwd) -> None:
    repo = Path(args.repo)
    env = {**os.environ, "HOME": user.pw_dir, "USER": user.pw_name, "LOGNAME": user.pw_name}
    run = lambda cmd, **kw: subprocess.Popen(  # noqa: E731
        cmd, cwd=repo, env=env, preexec_fn=_as_user(user), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, **kw)
    benign_py = [sys.executable, str(repo / "detection/benign/run_benign.py")]
    roots = {f"benign:{w}": run([*benign_py, "--workload", w, "--seconds", str(BENIGN_S)])
             for w in args.workloads}
    roots["benign:jit-stub"] = run([*benign_py, "--stub", "--seconds", str(BENIGN_S)])
    time.sleep(ATTACK_DELAY_S)  # go and java compile first
    bin_ = repo / "memory/bin"
    with open(run_dir / f"v2_{i}.log", "w") as v2_log:
        roots["attacker:v2"] = subprocess.Popen(
            [str(bin_ / "v2"), *shlex.split(V2_TIMINGS[i % len(V2_TIMINGS)]), "--duration", str(ATTACK_S)],
            cwd=repo, env=env, preexec_fn=_as_user(user), stdout=v2_log, stderr=subprocess.STDOUT)
    roots["attacker:v3"] = run([str(bin_ / "v3")])  # V3 and V4 run until stopped
    roots["attacker:v4"] = run([str(bin_ / "v4")])
    time.sleep(5)
    with open(run_dir / f"batch_{i}.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "pid", "comm"])
        for label, p in roots.items():
            for pid in _descendants(p.pid):
                w.writerow([label, pid, _comm(pid)])
    time.sleep(ATTACK_S - 5)
    for label in ("attacker:v3", "attacker:v4"):
        roots[label].send_signal(signal.SIGINT)
    for p in roots.values():
        p.wait()


def capture(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        sys.exit(f"capture needs root; run: pkexec {sys.executable} {Path(__file__).resolve()} "
                 f"capture --repo {Path(args.repo).resolve()}")
    user = pwd.getpwuid(int(os.environ.get("PKEXEC_UID", os.environ.get("SUDO_UID", "0"))))
    run_id = time.strftime("%Y%m%d-%H%M%S")
    run_dir = Path(args.repo) / "results/g5" / run_id
    run_dir.mkdir(parents=True)
    log = Path(args.log or Path(user.pw_dir) / f"tracee/out/g5-{run_id}.json")
    log.parent.mkdir(parents=True, exist_ok=True)
    tracee_bin = args.tracee_bin or str(Path(user.pw_dir) / "tracee/v0.23.2/dist/tracee")
    uffd = UFFD_SYSCTL.read_text().strip()
    UFFD_SYSCTL.write_text("1")  # V3 runs as the user
    tracee = None
    try:
        cmd = [tracee_bin, *(a for p in POLICIES for a in ("--policy", str(Path(args.repo) / p))),
               "--install-path", "/tmp/tracee-install",
               "--output", f"json:{log}", "--output", "option:parse-arguments"]
        with open(run_dir / "tracee.stderr", "w") as err:
            tracee = subprocess.Popen(cmd, stdout=err, stderr=subprocess.STDOUT)
        while not (log.exists() and log.stat().st_size):
            if tracee.poll() is not None:
                sys.exit(f"Tracee exited early; see {run_dir / 'tracee.stderr'}")
            time.sleep(1)
        time.sleep(15)  # let Tracee finish attaching
        for i in range(args.batches):
            _batch(args, i, run_dir, user)
            print(f"batch {i} done ({V2_TIMINGS[i % len(V2_TIMINGS)]})", flush=True)
    finally:
        if tracee is not None:
            tracee.send_signal(signal.SIGINT)
            try:
                tracee.wait(timeout=60)
            except subprocess.TimeoutExpired:
                tracee.kill()
        UFFD_SYSCTL.write_text(uffd)
        (run_dir / "capture.json").write_text(json.dumps({"tracee_log": str(log), "batches": args.batches}))
        for p in run_dir.iterdir():
            _hand_back(p, Path(args.repo), user)
        _hand_back(log, Path(user.pw_dir), user)
    print(f"captured {args.batches} batches into {log}; score with:\n"
          f"  .venv/bin/python detection/g5_capture.py score {run_dir}")
    return 0


def score(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    log = json.loads((run_dir / "capture.json").read_text())["tracee_log"]
    for batch in sorted(run_dir.glob("batch_*.csv")):
        with batch.open() as f:
            rows = list(csv.DictReader(f))
        cmd = [sys.executable, "-m", "detection.harness", "--tracee-log", log,
               "--run-id", f"{run_dir.name}-{batch.stem}", *harness_args(rows)]
        if args.no_llm:
            cmd.append("--no-llm")
        subprocess.run(cmd, check=True)
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
    s = sub.add_parser("score", help="score each batch once with detection.harness")
    s.add_argument("run_dir")
    s.add_argument("--no-llm", action="store_true")
    args = ap.parse_args(argv)
    return capture(args) if args.cmd == "capture" else score(args)


if __name__ == "__main__":
    raise SystemExit(main())
