"""G5 end-to-end harness: attacker + benign app under Tracee -> aggregate ->
triage -> catch rate and false-positive rate.

Offline (saved Tracee JSON log):
  python -m detection.harness --tracee-log saved.json \
      --attacker-comm v2 v3 --benign-comm node python3

Live (needs an installed Tracee and sudo, which prompts once at the start; not
runnable in CI):
  python -m detection.harness --live --attacker-bin memory/bin/v2 --seconds 20 \
      --attacker-comm v2 --benign-comm python

Processes matching neither the attacker nor the benign selectors are ignored.
Three rows (default_sigs, custom, ai) are appended per run to
$RTS_RESULTS_DIR/detection_g5.csv (default ./results).
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
    "run_id", "mode", "detector", "attacker", "benign", "n_attackers", "n_benign",
    "caught", "false_alarms", "catch_rate", "fp_rate", "triage_backend", "triage_ms_mean",
]
DEFAULT_POLICIES = [
    "detection/tracee/memory-hiding.yaml",
    "detection/tracee/default-signatures.yaml",
]
# Tracee drops root's file-permission override before creating its install dir,
# so it must not live under a private home directory.
DEFAULT_INSTALL_PATH = "/tmp/tracee-install"
RUN_BENIGN = Path(__file__).resolve().parent / "benign" / "run_benign.py"


@dataclass(frozen=True)
class LabelledVerdict:
    pid: int
    comm: str
    is_attacker: bool
    flagged: bool  # the detector fired on this process


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


# name -> does this detector fire, given the feature record and its triage result.
# Row order in the CSV follows this table. "ai" is the only one that uses triage.
DETECTORS: dict[str, Callable[[dict, dict], bool]] = {
    "default_sigs": lambda rec, tri: rec.get("tracee_alerts", 0) > 0,
    "custom": lambda rec, tri: (
        rec.get("relock_trips", 0) >= 1
        or rec.get("n_userfaultfd", 0) >= 1
        or rec.get("n_memfd_secret", 0) >= 1
    ),
    "ai": lambda rec, tri: tri.get("verdict") == "suspicious",
}
AI = "ai"


@dataclass(frozen=True)
class Evaluation:
    scores: dict[str, Score]  # one per detector, over the same labelled records
    triage_ms_mean: float | None  # wall-clock ms per triage call, labelled records only
    fell_back: bool  # triage used the heuristic for at least one record
    triage_backend: str  # "heuristic", "llm:<model>" or "llm-fallback:<model>"


def _matches(pid: int, comm: str, comms: Sequence[str], pids: Sequence[int]) -> bool:
    return pid in pids or any(comm.startswith(c) for c in comms)


def label_and_score(
    records: Iterable[dict],
    triage_fn: Callable[[dict], dict],
    attacker_comm: Sequence[str] = (),
    benign_comm: Sequence[str] = (),
    attacker_pid: Sequence[int] = (),
    benign_pid: Sequence[int] = (),
    llm_model: str | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> Evaluation:
    """Triage each labelled feature record once and score every detector on it.
    A record matching both sides counts as an attacker; one matching neither is
    ignored (and not triaged). `llm_model` is None when triage_fn is the plain
    heuristic; otherwise triage_fn reports its `source` per record."""
    out: dict[str, list[LabelledVerdict]] = {name: [] for name in DETECTORS}
    times_ms: list[float] = []
    fell_back = False
    for rec in records:
        pid, comm = int(rec.get("pid", -1)), str(rec.get("comm", ""))
        if _matches(pid, comm, attacker_comm, attacker_pid):
            is_att = True
        elif _matches(pid, comm, benign_comm, benign_pid):
            is_att = False
        else:
            continue
        t0 = clock()
        tri = triage_fn(rec)
        times_ms.append((clock() - t0) * 1000)
        fell_back = fell_back or tri.get("source") == "heuristic"
        for name, fires in DETECTORS.items():
            out[name].append(LabelledVerdict(pid, comm, is_att, fires(rec, tri)))
    if llm_model is None:
        backend = "heuristic"
    else:
        backend = f"{'llm-fallback' if fell_back else 'llm'}:{llm_model}"
    return Evaluation(
        scores={name: score(vs) for name, vs in out.items()},
        triage_ms_mean=sum(times_ms) / len(times_ms) if times_ms else None,
        fell_back=fell_back,
        triage_backend=backend,
    )


def run_offline(
    log_lines: Iterable[str],
    no_llm: bool,
    attacker_comm: Sequence[str] = (),
    benign_comm: Sequence[str] = (),
    attacker_pid: Sequence[int] = (),
    benign_pid: Sequence[int] = (),
) -> Evaluation:
    """aggregate -> triage -> score all detectors."""
    records = [w.as_features() for w in aggregator.aggregate(log_lines).values()]
    fn = triage_llm._heuristic if no_llm else triage_llm.triage
    model = None if no_llm else triage_llm.LLM_MODEL
    return label_and_score(
        records, fn, attacker_comm, benign_comm, attacker_pid, benign_pid, llm_model=model
    )


def results_dir() -> Path:
    return Path(os.environ.get("RTS_RESULTS_DIR", "results"))


def _fmt(x: float | None, places: int = 4) -> str:
    return "" if x is None else f"{x:.{places}f}"


def write_rows(run_id: str, mode: str, attacker: str, benign: str, ev: Evaluation) -> Path:
    d = results_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / CSV_NAME
    new = not path.exists()
    with path.open("a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(CSV_COLUMNS)
        for name, sc in ev.scores.items():
            ai = name == AI
            w.writerow([
                run_id, mode, name, attacker, benign, sc.n_attackers, sc.n_benign,
                sc.caught, sc.false_alarms, _fmt(sc.catch_rate), _fmt(sc.fp_rate),
                ev.triage_backend if ai else "", _fmt(ev.triage_ms_mean, 3) if ai else "",
            ])
    return path


def tracee_command(
    tracee: str, policies: Sequence[str], install_path: str, sudo: bool = True
) -> list[str]:
    cmd = [*(["sudo"] if sudo else []), tracee]
    for policy in policies:
        cmd += ["--policy", policy]
    cmd += ["--install-path", install_path]
    return cmd + ["--output", "json", "--output", "option:parse-arguments"]


def _stop_tracee(tr: subprocess.Popen, sudo: bool) -> None:
    """SIGINT so Tracee flushes its log, then SIGTERM. Through sudo, Tracee runs
    as root and only sudo may signal it; sudo relays both signals to Tracee."""
    for sig, timeout in ((signal.SIGINT, 10), (signal.SIGTERM, 5)):
        if tr.poll() is not None:
            return
        if sudo:
            subprocess.run(["sudo", "-n", "kill", f"-{sig.name[3:]}", str(tr.pid)], check=False)
        else:
            tr.send_signal(sig)
        try:
            tr.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            pass
    print(f"warning: tracee (pid {tr.pid}) ignored SIGINT and SIGTERM; "
          f"stop it with: sudo kill -KILL {tr.pid}", file=sys.stderr)


def _stop_group(p: subprocess.Popen) -> None:
    """SIGTERM a workload's whole process group, so the processes it started
    (node, java, a hider's helpers) stop with it; SIGKILL if it hangs."""
    for sig, timeout in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
        try:
            os.killpg(p.pid, sig)
        except ProcessLookupError:
            return  # the whole group already exited
        try:
            p.wait(timeout=timeout)
            return
        except subprocess.TimeoutExpired:
            pass


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
    benign_cmd = [sys.executable, str(RUN_BENIGN)]
    benign_cmd += ["--workload", args.workload] if args.workload else ["--stub"]
    benign_cmd += ["--seconds", str(args.seconds)]
    sudo = os.geteuid() != 0
    if sudo and subprocess.run(["sudo", "-v"]).returncode != 0:  # prompt now, not mid-run
        raise SystemExit("error: live mode needs sudo for Tracee")
    tracee_cmd = tracee_command(tracee, args.policy or DEFAULT_POLICIES, args.install_path, sudo)

    tr: subprocess.Popen | None = None
    workloads: list[subprocess.Popen] = []
    with log_path.open("w") as out, open(d / f"tracee_{run_id}.stderr", "w") as err:
        try:
            tr = subprocess.Popen(tracee_cmd, stdout=out, stderr=err)
            time.sleep(args.tracee_warmup)  # let Tracee attach before workloads start
            if tr.poll() is not None:
                raise SystemExit(f"error: tracee exited early (code {tr.returncode}); see {err.name}")
            for cmd in ([args.attacker_bin], benign_cmd):  # each in its own process group
                workloads.append(subprocess.Popen(cmd, start_new_session=True))
            time.sleep(args.seconds)
        finally:
            for p in workloads:  # workloads first, Tracee last so it flushes
                _stop_group(p)
            if tr is not None:
                _stop_tracee(tr, sudo)
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
    ap.add_argument(
        "--policy", action="append",
        help=f"live: Tracee policy file, repeatable (default: {' and '.join(DEFAULT_POLICIES)})",
    )
    ap.add_argument("--install-path", default=DEFAULT_INSTALL_PATH, help="live: Tracee install dir")
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
        ev = run_offline(
            f, args.no_llm, args.attacker_comm, args.benign_comm,
            args.attacker_pid, args.benign_pid,
        )
    attacker = " ".join(args.attacker_comm + [str(p) for p in args.attacker_pid])
    benign = " ".join(args.benign_comm + [str(p) for p in args.benign_pid])
    if ev.fell_back and not args.no_llm:
        print(f"warning: the LLM was unreachable for some records; they were triaged by "
              f"the heuristic (triage_backend={ev.triage_backend})", file=sys.stderr)
    csv_path = write_rows(run_id, mode, attacker, benign, ev)
    print(json.dumps({
        "run_id": run_id, "mode": mode,
        "detectors": {
            n: {"n_attackers": sc.n_attackers, "n_benign": sc.n_benign, "caught": sc.caught,
                "false_alarms": sc.false_alarms, "catch_rate": sc.catch_rate, "fp_rate": sc.fp_rate}
            for n, sc in ev.scores.items()
        },
        "triage_backend": ev.triage_backend, "triage_ms_mean": ev.triage_ms_mean,
        "csv": str(csv_path),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
