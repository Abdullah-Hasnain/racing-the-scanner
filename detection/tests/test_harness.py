import csv
import json

import pytest

from detection import harness
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
    hide = {"prev_prot": "", "prot": "PROT_READ|PROT_WRITE"}
    jit = {"prev_prot": "PROT_READ|PROT_WRITE", "prot": "PROT_READ|PROT_EXEC"}
    return [
        *[_ev(100, "v2", lsm, **hide) for _ in range(5)],
        _ev(101, "v3", "userfaultfd"),
        *[_ev(200, "node", lsm, **jit) for _ in range(5)],
        _ev(201, "python3", lsm, **jit),
        _ev(300, "bash", lsm, **hide),  # unlabelled, must be ignored
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
