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


def rec(pid, comm, **f):
    return {"pid": pid, "comm": comm, "none_rw_flips": 0, "relock_trips": 0, "n_userfaultfd": 0,
            "n_memfd_secret": 0, "rw_rx_flips": 0, "tracee_alerts": 0, **f}


def disagreeing_records():
    return [
        rec(1, "v2", none_rw_flips=5, relock_trips=2),      # hider: custom + ai catch, no alert
        rec(2, "jit", tracee_alerts=3, rw_rx_flips=9),      # benign: default_sigs false alarm
        rec(3, "gogc", none_rw_flips=2, relock_trips=1, rw_rx_flips=2),  # custom false alarm, ai quiet
    ]


def test_three_detectors_disagree_on_same_records():
    ev = harness.label_and_score(
        disagreeing_records(), triage_llm._heuristic, attacker_comm=["v2"], benign_comm=["jit", "gogc"]
    )
    got = {n: (s.caught, s.false_alarms) for n, s in ev.scores.items()}
    assert got == {"default_sigs": (0, 1), "custom": (1, 1), "ai": (1, 0)}
    assert all((s.n_attackers, s.n_benign) == (1, 2) for s in ev.scores.values())


def test_custom_ignores_runtime_flips_without_relocks():
    # Real capture: the JVM made 1,413 PROT_NONE flips but relocked no region.
    java = rec(4, "java", none_rw_flips=1413)
    assert not harness.DETECTORS["custom"](java, {})
    assert harness.DETECTORS["custom"](rec(1, "v2", none_rw_flips=41, relock_trips=20), {})


def test_triage_latency_is_mean_ms_over_labelled_records_only():
    calls = []
    ticks = iter(range(100))

    def clock():  # each triage call spans two ticks of 10 ms
        return next(ticks) * 0.005

    def triage(r):
        calls.append(r["pid"])
        return {"verdict": "benign", "reason": ""}

    recs = [*disagreeing_records(), rec(9, "bash")]
    ev = harness.label_and_score(
        recs, triage, attacker_comm=["v2"], benign_comm=["jit", "gogc"], clock=clock
    )
    assert calls == [1, 2, 3]
    assert ev.triage_ms_mean == pytest.approx(5.0)


def test_offline_pipeline_no_llm(log):
    ev = harness.run_offline(
        log, no_llm=True, attacker_comm=["v2", "v3"], benign_comm=["node", "python3"]
    )
    assert ev.triage_backend == "heuristic"
    ai = ev.scores["ai"]
    assert (ai.n_attackers, ai.caught) == (2, 2)
    assert (ai.n_benign, ai.false_alarms) == (2, 0)
    assert ai.catch_rate == 1.0 and ai.fp_rate == 0.0


def test_offline_labels_by_pid(log):
    ev = harness.run_offline(log, True, attacker_pid=[100], benign_pid=[200])
    ai = ev.scores["ai"]
    assert (ai.n_attackers, ai.n_benign, ai.caught) == (1, 1, 1)


def test_cli_writes_one_row_per_detector(log, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("RTS_RESULTS_DIR", str(tmp_path / "res"))
    p = tmp_path / "saved.json"
    p.write_text("\n".join(log))
    argv = ["--tracee-log", str(p), "--attacker-comm", "v2", "v3",
            "--benign-comm", "node", "python3", "--no-llm"]
    assert harness.main([*argv, "--run-id", "a"]) == 0
    assert harness.main([*argv, "--run-id", "b"]) == 0
    rows = list(csv.DictReader((tmp_path / "res" / "detection_g5.csv").open()))
    assert list(rows[0]) == [
        "run_id", "mode", "detector", "attacker", "benign", "n_attackers", "n_benign",
        "caught", "false_alarms", "catch_rate", "fp_rate", "triage_backend", "triage_ms_mean",
    ]
    assert [(r["run_id"], r["detector"]) for r in rows] == [
        (i, d) for i in "ab" for d in ("default_sigs", "custom", "ai")
    ]
    by = {r["detector"]: r for r in rows[:3]}
    assert (by["custom"]["mode"], by["custom"]["n_attackers"], by["custom"]["caught"]) == ("offline", "2", "2")
    assert (by["custom"]["catch_rate"], by["custom"]["fp_rate"]) == ("1.0000", "0.0000")
    assert by["ai"]["triage_backend"] == "heuristic"
    assert float(by["ai"]["triage_ms_mean"]) >= 0
    for d in ("default_sigs", "custom"):
        assert by[d]["triage_backend"] == "" and by[d]["triage_ms_mean"] == ""
    assert json.loads(capsys.readouterr().out.splitlines()[0])["detectors"]["ai"]["catch_rate"] == 1.0


def test_fallback_is_read_from_source_not_reason():
    sel = dict(attacker_comm=["v2"], benign_comm=["jit"], llm_model="m1")
    # a reason mentioning fallback does not matter; only source does
    llm = lambda r: {"verdict": "benign", "reason": "heuristic fallback", "source": "llm"}  # noqa: E731
    ev = harness.label_and_score(disagreeing_records(), llm, **sel)
    assert not ev.fell_back and ev.triage_backend == "llm:m1"
    down = lambda r: {"verdict": "benign", "reason": "x", "source": "heuristic"}  # noqa: E731
    ev = harness.label_and_score(disagreeing_records(), down, **sel)
    assert ev.fell_back and ev.triage_backend == "llm-fallback:m1"


def test_triage_reports_source(monkeypatch):
    class Boom:
        @staticmethod
        def post(*a, **k):
            raise OSError("down")

    monkeypatch.setattr(triage_llm, "requests", Boom)
    assert triage_llm.triage(rec(1, "v2"))["source"] == "heuristic"

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": '{"verdict": "suspicious", "reason": "r"}'}

    monkeypatch.setattr(triage_llm, "requests", type("R", (), {"post": staticmethod(lambda *a, **k: Resp())}))
    assert triage_llm.triage(rec(1, "v2")) == {"verdict": "suspicious", "reason": "r", "source": "llm"}


def test_run_offline_names_llm_or_llm_fallback(log, monkeypatch):
    monkeypatch.setattr(triage_llm, "LLM_MODEL", "m1")
    sel = dict(attacker_comm=["v2"], benign_comm=["node"])
    monkeypatch.setattr(
        triage_llm, "triage", lambda r: {"verdict": "benign", "reason": "ok", "source": "llm"}
    )
    assert harness.run_offline(log, False, **sel).triage_backend == "llm:m1"
    monkeypatch.setattr(
        triage_llm, "triage", lambda r: {"verdict": "benign", "reason": "ok", "source": "heuristic"}
    )
    assert harness.run_offline(log, False, **sel).triage_backend == "llm-fallback:m1"


def test_tracee_command_loads_both_policies_and_install_path():
    args = harness.build_parser().parse_args(["--live", "--attacker-comm", "v2"])
    cmd = harness.tracee_command("/bin/tracee", args.policy or harness.DEFAULT_POLICIES, args.install_path)
    pairs = list(zip(cmd, cmd[1:], strict=False))
    assert ("--policy", "detection/tracee/memory-hiding.yaml") in pairs
    assert ("--policy", "detection/tracee/default-signatures.yaml") in pairs
    assert ("--install-path", "/tmp/tracee-install") in pairs


def test_policy_option_is_repeatable():
    args = harness.build_parser().parse_args(["--policy", "a.yaml", "--policy", "b.yaml"])
    assert args.policy == ["a.yaml", "b.yaml"]


def test_live_fails_clearly_without_tracee():
    with pytest.raises(SystemExit) as e:
        harness.main(["--live", "--attacker-comm", "v2", "--tracee-bin", "/nonexistent/tracee"])
    assert "tracee not found" in str(e.value)


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
    ev = harness.run_offline(log, True, attacker_comm=["v2"], benign_comm=[""])
    assert all(sc.n_benign == 0 for sc in ev.scores.values())


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
