# Detection layer (Ibad)

Aqua Tracee plus a local-LLM triage layer, and the integrated evaluation.

## Pipeline

```
Tracee (JSON events) -> aggregator.py (per-PID features) -> triage_llm.py (verdict)
```

Every stage works offline on a saved log, so you can build the whole pipeline
before Tracee is even installed.

```bash
# 1. aggregate a saved Tracee log into per-PID feature records
python aggregator.py --input sample_tracee.json > features.jsonl

# 2. triage each record with the local LLM (falls back to a heuristic if no LLM)
python triage_llm.py --input features.jsonl
```

Point the triage at your local model with `RTS_LLM_URL` and `RTS_LLM_MODEL`
(see `.env.example`). Run the model on one of the NVIDIA machines.

## Tracee

`tracee/memory-hiding.yaml` is a starter policy watching `mprotect`, `madvise`,
`userfaultfd`, and `memfd_secret`. Compare default signatures vs this custom
policy for what each catches and what it false-alarms on.

## Benign suite

`benign/run_benign.py` runs the legitimate workloads (Node.js, Go/Java GC,
jemalloc/SQLite) that trip false alarms, with a dependency-free `--stub` for
pipeline testing.

## First issues

- Build the end-to-end harness that runs an attacker + a benign app, captures
  Tracee output, and reports catch rate and false-positive rate (G5).
- Tune the mprotect flag-transition filter (PROT_NONE<->RW vs RW<->RX).
- Wire the overhead measurement for the triage layer (G6).
