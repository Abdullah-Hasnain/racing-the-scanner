"""D3 (part 2): local-LLM triage.

Takes a per-PID feature record (from aggregator.py) and asks a LOCAL LLM
(Ollama by default, or any OpenAI-compatible llama.cpp server) whether the
activity is a real memory-hiding attempt or ordinary JIT/GC behavior. The goal
is to cut Tracee's false alarms on Node.js (V8), Go/Java GC, and jemalloc, which
use the same syscalls as the attacker.

Nothing leaves the machine: the model runs locally. If the LLM is unreachable,
a transparent rule-of-thumb fallback keeps the pipeline working so Member 3 can
develop offline.

Usage:
  python aggregator.py --input tracee.json | python triage_llm.py
  RTS_LLM_URL=http://localhost:11434 python triage_llm.py --input features.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests

LLM_URL = os.environ.get("RTS_LLM_URL", "http://localhost:11434")
LLM_MODEL = os.environ.get("RTS_LLM_MODEL", "llama3.1:8b")

SYSTEM = (
    "You are a security triage assistant. You are given counts of memory-related "
    "events for one Linux process over a capture. Decide if the behavior is "
    "BENIGN (normal JIT or garbage collector: many RW<->RX mprotect flips, guard "
    "pages, MADV_DONTNEED during GC) or SUSPICIOUS (hiding: pages repeatedly locked "
    "to PROT_NONE and unlocked again, userfaultfd refills, or memfd_secret).\n"
    "The features are:\n"
    "- none_rw_flips: mprotect changes to or from PROT_NONE (lock or unlock). "
    "Runtimes such as V8 and the JVM make many of these when they commit heap "
    "and set guard pages, so on their own they prove nothing.\n"
    "- relock_trips: memory regions unlocked from PROT_NONE and then locked "
    "again. This round trip is the hallmark of hiding; the benign runtimes we "
    "measured (Node 22, JDK 25, Go 1.26) made none.\n"
    "- rw_rx_flips: mprotect changes between writable and executable. Many of "
    "these are the hallmark of a JIT.\n"
    "- n_userfaultfd, n_memfd_secret: syscall counts. Benign JIT and GC apps do "
    "not use these; any count above 0 is suspicious.\n"
    "- n_mprotect, n_madvise: syscall counts, common in benign apps.\n"
    "- segv_handlers: times the process installed a SIGSEGV handler. Runtimes "
    "(Go, Java) install one too, so on its own it proves nothing.\n"
    "- tracee_alerts: Tracee signature alerts that fired for the process.\n"
    "Answer with a JSON object: {\"verdict\": \"benign|suspicious\", \"reason\": \"...\"}."
)


def _heuristic(rec: dict) -> dict:
    """Transparent fallback when no LLM is reachable.

    userfaultfd and memfd_secret are suspicious on their own, as the prompt says:
    V3/V4 call them once at setup, so JIT flips must not outvote them.
    """
    relocks, jit = rec.get("relock_trips", 0), rec.get("rw_rx_flips", 0)
    hiding_syscalls = rec.get("n_userfaultfd", 0) + rec.get("n_memfd_secret", 0)
    verdict = "suspicious" if hiding_syscalls > 0 or relocks > jit else "benign"
    return {"verdict": verdict, "reason": "heuristic fallback (LLM unreachable)"}


def triage(rec: dict, timeout: float = 20.0) -> dict:
    prompt = SYSTEM + "\n\nPROCESS FEATURES:\n" + json.dumps(rec)
    try:
        r = requests.post(
            f"{LLM_URL}/api/generate",
            json={
                "model": LLM_MODEL, "prompt": prompt, "stream": False, "format": "json",
                "options": {"temperature": 0},  # same record, same verdict
            },
            timeout=timeout,
        )
        r.raise_for_status()
        out = json.loads(r.json()["response"])
        verdict = str(out.get("verdict", "benign")).strip().lower()  # models echo "SUSPICIOUS"
        return {"verdict": verdict, "reason": out.get("reason", "")}
    except Exception as exc:  # unreachable, timeout, or bad JSON
        res = _heuristic(rec)
        res["reason"] += f" [{type(exc).__name__}]"
        return res


def main() -> int:
    ap = argparse.ArgumentParser(description="Local-LLM Tracee triage (D3)")
    ap.add_argument("--input", help="JSONL of per-PID features; omit to read stdin")
    args = ap.parse_args()

    src = open(args.input) if args.input else sys.stdin
    for line in src:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        verdict = triage(rec)
        print(json.dumps({"pid": rec.get("pid"), "comm": rec.get("comm"), **verdict}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
