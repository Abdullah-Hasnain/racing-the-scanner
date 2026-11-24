"""The heuristic fallback judges hiding by relocked regions, not raw flips (#13)."""

import json

from detection import triage_llm
from detection.triage_llm import _heuristic


def rec(**kw) -> dict:
    base = {"none_rw_flips": 0, "relock_trips": 0, "rw_rx_flips": 0,
            "n_userfaultfd": 0, "n_memfd_secret": 0}
    return {**base, **kw}


def test_runtime_flips_without_relocks_are_benign():
    # Real capture: the JVM made 1,413 PROT_NONE flips and relocked no region.
    assert _heuristic(rec(none_rw_flips=1413, relock_trips=0))["verdict"] == "benign"


def test_slow_hider_relocking_is_suspicious():
    # V2 at one access per second: 20 relocks in 20 s.
    assert _heuristic(rec(none_rw_flips=41, relock_trips=20))["verdict"] == "suspicious"


def test_userfaultfd_or_memfd_secret_alone_is_suspicious():
    assert _heuristic(rec(n_userfaultfd=1))["verdict"] == "suspicious"
    assert _heuristic(rec(n_memfd_secret=1))["verdict"] == "suspicious"


def test_userfaultfd_or_memfd_secret_stays_suspicious_beside_jit_flips():
    # V3/V4 call these once at setup; a few RW<->RX flips must not outvote them.
    assert _heuristic(rec(n_userfaultfd=1, rw_rx_flips=2))["verdict"] == "suspicious"
    assert _heuristic(rec(n_memfd_secret=1, rw_rx_flips=2))["verdict"] == "suspicious"


def test_llm_verdict_is_normalized(monkeypatch):
    # A small model may echo the prompt's "SUSPICIOUS" in capitals.
    class Reply:
        def raise_for_status(self):
            pass

        def json(self):
            return {"response": json.dumps({"verdict": " SUSPICIOUS ", "reason": "relocks"})}

    monkeypatch.setattr(triage_llm.requests, "post", lambda *a, **kw: Reply())
    assert triage_llm.triage(rec(relock_trips=5))["verdict"] == "suspicious"
