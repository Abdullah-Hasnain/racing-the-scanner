import csv
import json
import time

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
    hide = {"prev_prot": "", "prot": "PROT_READ|PROT_WRITE"}
    jit = {"prev_prot": "PROT_READ|PROT_WRITE", "prot": "PROT_READ|PROT_EXEC"}
    return [
        *[_ev(100, "v2", lsm, **hide) for _ in range(5)],
        _ev(101, "v3", "userfaultfd"),
        *[_ev(200, "node", lsm, **jit) for _ in range(5)],
        _ev(201, "python3", lsm, **jit),
        _ev(300, "bash", lsm, **hide),  # unlabelled, must be ignored
    ]


def rec(pid, comm, **f):
    return {"pid": pid, "comm": comm, "none_rw_flips": 0, "n_userfaultfd": 0,
            "n_memfd_secret": 0, "rw_rx_flips": 0, "tracee_alerts": 0, **f}


def disagreeing_records():
    return [
        rec(1, "v2", none_rw_flips=5),                      # hider: custom + ai catch, no alert
        rec(2, "jit", tracee_alerts=3, rw_rx_flips=9),      # benign: default_sigs false alarm
        rec(3, "gogc", none_rw_flips=2, rw_rx_flips=2),     # benign: custom false alarm, ai quiet
    ]


def test_three_detectors_disagree_on_same_records():
    ev = harness.label_and_score(
        disagreeing_records(), triage_llm._heuristic, attacker_comm=["v2"], benign_comm=["jit", "gogc"]
    )
    got = {n: (s.caught, s.false_alarms) for n, s in ev.scores.items()}
    assert got == {"default_sigs": (0, 1), "custom": (1, 1), "ai": (1, 0)}
    assert all((s.n_attackers, s.n_benign) == (1, 2) for s in ev.scores.values())


def test_triage_latency_is_mean_ms_over_labelled_records_only():
    calls = []

    def slow(r):
        calls.append(r["pid"])
        time.sleep(0.01)
        return {"verdict": "benign", "reason": ""}

    recs = [*disagreeing_records(), rec(9, "bash")]
    ev = harness.label_and_score(recs, slow, attacker_comm=["v2"], benign_comm=["jit", "gogc"])
    assert calls == [1, 2, 3]
    assert ev.triage_ms_mean >= 10


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


def test_llm_fallback_is_recorded_in_backend(monkeypatch):
    monkeypatch.setattr(triage_llm, "LLM_MODEL", "m1")
    monkeypatch.setattr(triage_llm, "triage", triage_llm._heuristic)  # heuristic reason says fallback
    ev = harness.label_and_score(
        disagreeing_records(), triage_llm.triage, attacker_comm=["v2"], benign_comm=["jit"]
    )
    assert ev.fell_back
    ok = lambda r: {"verdict": "benign", "reason": "fine"}  # noqa: E731
    ev = harness.label_and_score(disagreeing_records(), ok, attacker_comm=["v2"])
    assert not ev.fell_back


def test_run_offline_names_llm_or_llm_fallback(log, monkeypatch):
    monkeypatch.setattr(triage_llm, "LLM_MODEL", "m1")
    sel = dict(attacker_comm=["v2"], benign_comm=["node"])
    monkeypatch.setattr(triage_llm, "triage", lambda r: {"verdict": "benign", "reason": "ok"})
    assert harness.run_offline(log, False, **sel).triage_backend == "llm:m1"
    monkeypatch.setattr(triage_llm, "triage", triage_llm._heuristic)
    assert harness.run_offline(log, False, **sel).triage_backend == "llm-fallback:m1"


def test_live_fails_clearly_without_tracee():
    with pytest.raises(SystemExit) as e:
        harness.main(["--live", "--attacker-comm", "v2", "--tracee-bin", "/nonexistent/tracee"])
    assert "tracee not found" in str(e.value)
