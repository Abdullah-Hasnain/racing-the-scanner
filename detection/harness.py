"""G5 end-to-end harness: attacker + benign app under Tracee -> aggregate ->
triage -> catch rate and false-positive rate.

Offline (saved Tracee JSON log):
  python -m detection.harness --tracee-log saved.json \
      --attacker-comm v2 v3 --benign-comm node python3

Live (needs root and an installed Tracee; not runnable in CI):
  python -m detection.harness --live --attacker-bin memory/bin/v2 --seconds 20 \
      --attacker-comm v2 --benign-comm python

Processes matching neither the attacker nor the benign selectors are ignored.
A row is appended to $RTS_RESULTS_DIR/detection_g5.csv (default ./results).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from detection import aggregator, triage_llm

CSV_NAME = "detection_g5.csv"
CSV_COLUMNS = [
    "run_id", "mode", "attacker", "benign", "n_attackers", "n_benign",
    "caught", "false_alarms", "catch_rate", "fp_rate", "triage_backend",
]
DEFAULT_POLICY = "detection/tracee/memory-hiding.yaml"


@dataclass(frozen=True)
class LabelledVerdict:
    pid: int
    comm: str
    is_attacker: bool
    flagged: bool  # triage said "suspicious"


@dataclass(frozen=True)
class Score:
    n_attackers: int
    n_benign: int
    caught: int
    false_alarms: int

    @property
    def catch_rate(self) -> float | None:
        return self.caught / self.n_attackers if self.n_attackers else None

    @property
    def fp_rate(self) -> float | None:
        return self.false_alarms / self.n_benign if self.n_benign else None


def score(verdicts: Iterable[LabelledVerdict]) -> Score:
    vs = list(verdicts)
    att = [v for v in vs if v.is_attacker]
    ben = [v for v in vs if not v.is_attacker]
    return Score(
        n_attackers=len(att),
        n_benign=len(ben),
        caught=sum(v.flagged for v in att),
        false_alarms=sum(v.flagged for v in ben),
    )


def _matches(pid: int, comm: str, comms: Sequence[str], pids: Sequence[int]) -> bool:
    return pid in pids or any(comm.startswith(c) for c in comms)


def label_and_score(
    records: Iterable[dict],
    triage_fn: Callable[[dict], dict],
    attacker_comm: Sequence[str] = (),
    benign_comm: Sequence[str] = (),
    attacker_pid: Sequence[int] = (),
    benign_pid: Sequence[int] = (),
) -> Score:
    """Triage each feature record and score it. Records are opaque apart from
    pid/comm. A record matching both sides counts as an attacker; one matching
    neither is ignored."""
    out: list[LabelledVerdict] = []
    for rec in records:
        pid, comm = int(rec.get("pid", -1)), str(rec.get("comm", ""))
        if _matches(pid, comm, attacker_comm, attacker_pid):
            is_att = True
        elif _matches(pid, comm, benign_comm, benign_pid):
            is_att = False
        else:
            continue
        flagged = triage_fn(rec).get("verdict") == "suspicious"
        out.append(LabelledVerdict(pid, comm, is_att, flagged))
    return score(out)


def run_offline(
    log_lines: Iterable[str],
    no_llm: bool,
    attacker_comm: Sequence[str] = (),
    benign_comm: Sequence[str] = (),
    attacker_pid: Sequence[int] = (),
    benign_pid: Sequence[int] = (),
) -> tuple[Score, str]:
    """aggregate -> triage -> score. Returns the score and the backend name."""
    records = [w.as_features() for w in aggregator.aggregate(log_lines).values()]
    if no_llm:
        fn, backend = triage_llm._heuristic, "heuristic"
    else:
        fn, backend = triage_llm.triage, f"llm:{triage_llm.LLM_MODEL}"
    sc = label_and_score(records, fn, attacker_comm, benign_comm, attacker_pid, benign_pid)
    return sc, backend


def results_dir() -> Path:
    return Path(os.environ.get("RTS_RESULTS_DIR", "results"))


def _fmt(x: float | None) -> str:
    return "" if x is None else f"{x:.4f}"


def write_row(run_id: str, mode: str, attacker: str, benign: str, sc: Score, backend: str) -> Path:
    d = results_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / CSV_NAME
    new = not path.exists()
    with path.open("a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(CSV_COLUMNS)
        w.writerow([
            run_id, mode, attacker, benign, sc.n_attackers, sc.n_benign,
            sc.caught, sc.false_alarms, _fmt(sc.catch_rate), _fmt(sc.fp_rate), backend,
        ])
    return path


def run_live(args: argparse.Namespace, run_id: str) -> Path:
    """Launch Tracee, the attacker and a benign workload, wait, stop, and
    return the path of the saved raw Tracee log."""
    tracee = shutil.which(args.tracee_bin) or (
        args.tracee_bin if Path(args.tracee_bin).is_file() else None
    )
    if tracee is None:
        raise SystemExit(
            f"error: tracee not found ({args.tracee_bin!r}). Install Aqua Tracee or pass "
            "--tracee-bin; live mode also needs root (sudo)."
        )
    if not args.attacker_bin or not Path(args.attacker_bin).is_file():
        raise SystemExit(
            f"error: attacker binary not found ({args.attacker_bin!r}); "
            "build it with `make -C memory` and pass --attacker-bin."
        )
    d = results_dir()
    d.mkdir(parents=True, exist_ok=True)
    log_path = d / f"tracee_{run_id}.json"
    benign_cmd = [sys.executable, "detection/benign/run_benign.py"]
    benign_cmd += ["--workload", args.workload] if args.workload else ["--stub"]
    benign_cmd += ["--seconds", str(args.seconds)]
    tracee_cmd = [
        "sudo", tracee, "--policy", args.policy,
        "--output", "json", "--output", "option:parse-arguments",
    ]

    procs: list[subprocess.Popen] = []
    with log_path.open("w") as out, open(d / f"tracee_{run_id}.stderr", "w") as err:
        try:
            tr = subprocess.Popen(tracee_cmd, stdout=out, stderr=err)
            procs.append(tr)
            time.sleep(args.tracee_warmup)  # let Tracee attach before workloads start
            if tr.poll() is not None:
                raise SystemExit(f"error: tracee exited early (code {tr.returncode}); see {err.name}")
            procs.append(subprocess.Popen([args.attacker_bin]))
            procs.append(subprocess.Popen(benign_cmd))
            time.sleep(args.seconds)
        finally:
            for p in reversed(procs):  # workloads first, Tracee last so it flushes
                if p.poll() is None:
                    p.send_signal(signal.SIGINT if p is procs[0] else signal.SIGTERM)
            for p in reversed(procs):
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
    return log_path


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="G5 detection harness (catch / FP rate)")
    ap.add_argument("--tracee-log", help="saved Tracee JSON log (offline mode)")
    ap.add_argument("--live", action="store_true", help="run Tracee + attacker + benign")
    ap.add_argument("--attacker-comm", nargs="*", default=[], help="attacker comm prefixes")
    ap.add_argument("--benign-comm", nargs="*", default=[], help="benign comm prefixes")
    ap.add_argument("--attacker-pid", nargs="*", type=int, default=[])
    ap.add_argument("--benign-pid", nargs="*", type=int, default=[])
    ap.add_argument("--no-llm", action="store_true", help="use the heuristic, not the LLM")
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--attacker-bin", help="live: attacker binary, e.g. memory/bin/v2")
    ap.add_argument("--workload", help="live: benign workload name (default: --stub)")
    ap.add_argument("--seconds", type=int, default=20, help="live: run length")
    ap.add_argument("--tracee-bin", default="tracee")
    ap.add_argument("--policy", default=DEFAULT_POLICY)
    ap.add_argument("--tracee-warmup", type=float, default=5.0)
    return ap


def main(argv: Sequence[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    if bool(args.tracee_log) == bool(args.live):
        ap.error("give exactly one of --tracee-log or --live")
    if not (args.attacker_comm or args.attacker_pid):
        ap.error("need --attacker-comm or --attacker-pid")
    run_id = args.run_id or uuid.uuid4().hex[:8]

    if args.live:
        log_path = run_live(args, run_id)
        mode = "live"
    else:
        log_path, mode = Path(args.tracee_log), "offline"
    with log_path.open() as f:
        sc, backend = run_offline(
            f, args.no_llm, args.attacker_comm, args.benign_comm,
            args.attacker_pid, args.benign_pid,
        )
    attacker = " ".join(args.attacker_comm + [str(p) for p in args.attacker_pid])
    benign = " ".join(args.benign_comm + [str(p) for p in args.benign_pid])
    csv_path = write_row(run_id, mode, attacker, benign, sc, backend)
    print(json.dumps({
        "run_id": run_id, "mode": mode, "n_attackers": sc.n_attackers, "n_benign": sc.n_benign,
        "caught": sc.caught, "false_alarms": sc.false_alarms,
        "catch_rate": sc.catch_rate, "fp_rate": sc.fp_rate, "triage_backend": backend,
        "csv": str(csv_path),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
