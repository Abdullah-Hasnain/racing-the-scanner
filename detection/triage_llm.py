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
    "syscalls for one Linux process over one second. Decide if the behavior is "
    "BENIGN (normal JIT or garbage collector: many RW<->RX mprotect flips, guard "
    "pages, MADV_DONTNEED during GC) or SUSPICIOUS (hiding: PROT_NONE<->RW single "
    "pages with SIGSEGV faults, userfaultfd refills, or memfd_secret). "
    "Answer with a JSON object: {\"verdict\": \"benign|suspicious\", \"reason\": \"...\"}."
)


def _heuristic(rec: dict) -> dict:
    """Transparent fallback when no LLM is reachable."""
    hiding = rec.get("none_rw_flips", 0) + rec.get("n_userfaultfd", 0) + rec.get("n_memfd_secret", 0)
    jit = rec.get("rw_rx_flips", 0)
    verdict = "suspicious" if hiding > jit and hiding > 0 else "benign"
    return {"verdict": verdict, "reason": "heuristic fallback (LLM unreachable)"}


def triage(rec: dict, timeout: float = 20.0) -> dict:
    prompt = SYSTEM + "\n\nPROCESS FEATURES:\n" + json.dumps(rec)
    try:
        r = requests.post(
            f"{LLM_URL}/api/generate",
            json={"model": LLM_MODEL, "prompt": prompt, "stream": False, "format": "json"},
            timeout=timeout,
        )
        r.raise_for_status()
        out = json.loads(r.json()["response"])
        return {"verdict": out.get("verdict", "benign"), "reason": out.get("reason", "")}
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
