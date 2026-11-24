import csv
import json
import os
import time
from pathlib import Path

import pytest

from detection import harness, triage_llm
from detection.harness import LabelledVerdict, score


def lv(is_attacker, flagged):
    return LabelledVerdict(1, "x", is_attacker, flagged)


def test_score_counts_and_rates():
    s = score([lv(True, True), lv(True, False), lv(False, True), lv(False, False), lv(False, False)])
    assert (s.n_attackers, s.caught) == (2, 1)
    assert (s.n_benign, s.false_alarms) == (3, 1)
    assert s.catch_rate == 0.5
    assert s.fp_rate == pytest.approx(1 / 3)


def test_score_empty_class_has_no_rate():
    s = score([lv(True, True)])
    assert s.catch_rate == 1.0
    assert s.fp_rate is None


def _ev(pid, comm, name, **args):
    return json.dumps({
        "processId": pid, "processName": comm, "eventName": name,
        "args": [{"name": k, "value": v} for k, v in args.items()],
    })


@pytest.fixture
def log():
    # security_file_mprotect is the event with prev_prot; Tracee's parse-arguments
    # renders a PROT_NONE region's prev_prot (vm_flags 0x70) as "".
    lsm = "security_file_mprotect"
    page = {"addr": "0x7f0000001000", "len": 4096}
    unlock = {"prev_prot": "", "prot": "PROT_READ|PROT_WRITE", **page}
    relock = {"prev_prot": "PROT_READ|PROT_WRITE", "prot": "", **page}
    jit = {"prev_prot": "PROT_READ|PROT_WRITE", "prot": "PROT_READ|PROT_EXEC"}
    return [
        *[e for _ in range(5) for e in (_ev(100, "v2", lsm, **unlock), _ev(100, "v2", lsm, **relock))],
        _ev(101, "v3", "userfaultfd"),
        *[_ev(200, "node", lsm, **jit) for _ in range(5)],
        _ev(201, "python3", lsm, **jit),
        _ev(300, "bash", lsm, **unlock),  # unlabelled, must be ignored
    ]


def test_offline_pipeline_no_llm(log):
    sc, backend = harness.run_offline(
        log, no_llm=True, attacker_comm=["v2", "v3"], benign_comm=["node", "python3"]
    )
    assert backend == "heuristic"
    assert (sc.n_attackers, sc.caught) == (2, 2)
    assert (sc.n_benign, sc.false_alarms) == (2, 0)
    assert sc.catch_rate == 1.0 and sc.fp_rate == 0.0


def test_offline_labels_by_pid(log):
    sc, _ = harness.run_offline(log, True, attacker_pid=[100], benign_pid=[200])
    assert (sc.n_attackers, sc.n_benign, sc.caught) == (1, 1, 1)


def test_cli_writes_csv_row(log, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("RTS_RESULTS_DIR", str(tmp_path / "res"))
    p = tmp_path / "saved.json"
    p.write_text("\n".join(log))
    argv = ["--tracee-log", str(p), "--attacker-comm", "v2", "v3",
            "--benign-comm", "node", "python3", "--no-llm"]
    assert harness.main([*argv, "--run-id", "a"]) == 0
    assert harness.main([*argv, "--run-id", "b"]) == 0
    rows = list(csv.DictReader((tmp_path / "res" / "detection_g5.csv").open()))
    assert list(rows[0]) == harness.CSV_COLUMNS
    assert [r["run_id"] for r in rows] == ["a", "b"]
    r = rows[0]
    assert (r["mode"], r["n_attackers"], r["caught"], r["false_alarms"]) == ("offline", "2", "2", "0")
    assert (r["catch_rate"], r["fp_rate"], r["triage_backend"]) == ("1.0000", "0.0000", "heuristic")
    assert json.loads(capsys.readouterr().out.splitlines()[0])["catch_rate"] == 1.0


def test_live_fails_clearly_without_tracee():
    with pytest.raises(SystemExit) as e:
        harness.main(["--live", "--attacker-comm", "v2", "--tracee-bin", "/nonexistent/tracee"])
    assert "tracee not found" in str(e.value)


def test_unreachable_llm_is_labelled_as_a_fallback(log, monkeypatch):
    # Without Ollama, triage silently uses the heuristic; the CSV must say so.
    def down(*a, **kw):
        raise ConnectionError("no ollama")

    monkeypatch.setattr(triage_llm.requests, "post", down)
    _, backend = harness.run_offline(log, no_llm=False, attacker_comm=["v2"], benign_comm=["node"])
    assert backend == f"llm-fallback:{triage_llm.LLM_MODEL}"


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


def _gone(pid: int, timeout: float = 3.0) -> bool:
    end = time.monotonic() + timeout
    while Path(f"/proc/{pid}").exists() and time.monotonic() < end:
        time.sleep(0.05)
    return not Path(f"/proc/{pid}").exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="as root the harness does not go through sudo")
def test_live_stops_root_tracee_through_sudo_and_every_workload_process(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls, stopped, grandchild = tmp_path / "sudo.log", tmp_path / "stopped", tmp_path / "gc.pid"
    # Stand-in sudo: log the call, drop the flags, run the rest as this user.
    _script(bin_dir / "sudo", f'echo "$*" >> {calls}\n'
            'while [ "${1#-}" != "$1" ]; do shift; done\n[ $# -eq 0 ] || exec "$@"\n')
    tracee = _script(tmp_path / "tracee", f"trap 'echo INT > {stopped}; exit 0' INT\n"
                     "while :; do sleep 0.05; done\n")
    attacker = _script(tmp_path / "attacker", f"sleep 300 &\necho $! > {grandchild}\nwait\n")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("RTS_RESULTS_DIR", str(tmp_path / "res"))
    args = harness.build_parser().parse_args([
        "--live", "--attacker-comm", "attacker", "--attacker-bin", str(attacker),
        "--tracee-bin", str(tracee), "--seconds", "1", "--tracee-warmup", "0.3",
    ])

    harness.run_live(args, "t")

    sudo_calls = calls.read_text().splitlines()
    assert sudo_calls[0] == "-v", "sudo must prompt before the warm-up timer starts"
    assert any(c.startswith("-n kill -INT") for c in sudo_calls), "root Tracee needs sudo to stop"
    assert stopped.read_text().strip() == "INT", "Tracee must get SIGINT so it flushes"
    assert _gone(int(grandchild.read_text())), "the attacker's child outlived the run"


def test_benign_only_run_scores_false_alarms(log, tmp_path, monkeypatch):
    # #13's false-alarm runs have no attacker; catch rate is then blank.
    monkeypatch.setenv("RTS_RESULTS_DIR", str(tmp_path / "res"))
    p = tmp_path / "saved.json"
    p.write_text("\n".join(log))
    assert harness.main(["--tracee-log", str(p), "--benign-comm", "node", "--no-llm"]) == 0
    row = next(csv.DictReader((tmp_path / "res" / "detection_g5.csv").open()))
    assert (row["n_attackers"], row["catch_rate"], row["n_benign"]) == ("0", "", "1")


def test_empty_comm_prefix_matches_nothing(log):
    # `--benign-comm ""` must not label every process on the host as benign.
    sc, _ = harness.run_offline(log, True, attacker_comm=["v2"], benign_comm=[""])
    assert sc.n_benign == 0


@pytest.mark.skipif(os.geteuid() == 0, reason="as root the harness does not go through sudo")
def test_live_warns_when_a_workload_fails(tmp_path, monkeypatch, capsys):
    # A missing runtime makes run_benign.py exit 1 at once; say so, don't log n_benign=0 quietly.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    _script(bin_dir / "sudo", 'while [ "${1#-}" != "$1" ]; do shift; done\n[ $# -eq 0 ] || exec "$@"\n')
    tracee = _script(tmp_path / "tracee", "trap 'exit 0' INT\nwhile :; do sleep 0.05; done\n")
    attacker = _script(tmp_path / "attacker", "exit 3\n")
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("RTS_RESULTS_DIR", str(tmp_path / "res"))
    args = harness.build_parser().parse_args([
        "--live", "--attacker-comm", "attacker", "--attacker-bin", str(attacker),
        "--tracee-bin", str(tracee), "--seconds", "1", "--tracee-warmup", "0.3",
    ])

    harness.run_live(args, "t")

    assert f"{attacker} exited with code 3" in capsys.readouterr().err
