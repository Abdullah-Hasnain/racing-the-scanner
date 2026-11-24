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
`userfaultfd`, and `memfd_secret`, plus `security_file_mprotect`. Compare default
signatures vs this custom policy for what each catches and what it false-alarms on.

## mprotect flips

The `mprotect` syscall event has no previous protection, so it cannot show a
transition. The `security_file_mprotect` LSM event has both `prot` and
`prev_prot`, and the aggregator counts its flips per process:

| feature | flip | typical of |
|---|---|---|
| `none_rw_flips` | to or from PROT_NONE, whatever the other side | V2-style hiding (unlock, re-lock) |
| `rw_rx_flips` | write access swapped for exec, or back (RW to RX, RX to RW), neither side PROT_NONE | a JIT (V8, the benign stub) |

`none_rw_flips` counts any access on the other side (R, RW, RX, RWX), so a hider
cannot dodge it by unlocking with exec or read-only access. The cost is overlap
with benign apps: guard pages (Go, Java) and polling pages (older JVM safepoints)
also flip to and from PROT_NONE. Measuring that overlap is G5's job, and the
triage weighs the counts instead of treating one flip as a verdict.

Counts are per memory region (VMA), not per call: the kernel runs the LSM hook
once for each VMA an mprotect call spans. V2 touches one page per call, so it is
unaffected; a JIT protecting a range that spans several VMAs counts more than once.

Tracee reports `prev_prot` as the region's raw vm_flags (for example `0x70` for a
PROT_NONE region); only the R/W/X bits are read. With `parse-arguments`, a
PROT_NONE region's `prev_prot` renders as `""`, not `"PROT_NONE"`. Both forms
are handled.

Checked on a real capture (Tracee v0.24.1, kernel 7.0, 10 s, policy as shipped):

| process | Tracee events | aggregator |
|---|---|---|
| `v2 --dwell-ms 10 --interval-ms 50` | 200 unlocks `''` to `PROT_READ\|PROT_WRITE`, 201 locks back to `PROT_NONE` | `none_rw_flips` 401, `rw_rx_flips` 0 |
| `run_benign.py --stub` | 9343 RW to RX and 9343 RX to RW, `prev_prot` carrying `PROT_SEM` (VM_SHARED) | `none_rw_flips` 0, `rw_rx_flips` 18686 |

V2 made 200 faults and 200 re-locks, plus the initial whole-buffer lock: 401.
`security_file_mprotect` fires once per `mprotect` call here, anonymous memory
included. The stub's process name is `python`, not `python3`.

## Running Tracee

v0.24.1 runs on kernel 7.0. It needs real root: `perf_event_paranoid` is 4 on
Ubuntu, so the `CAP_BPF` + `CAP_PERFMON` route does not apply. Run it from a
real terminal, since `sudo` cannot prompt inside Claude Code's `!` commands.

```bash
mkdir -p ~/tracee/out && cd ~/tracee
curl -fLO https://github.com/aquasecurity/tracee/releases/download/v0.24.1/tracee-x86_64.v0.24.1.tar.gz
echo "8cc56bd8c8dd3efadb0441c84849592affc48a71d3afbe7751a9e2014ef9ec85  tracee-x86_64.v0.24.1.tar.gz" | sha256sum -c
tar -xzf tracee-x86_64.v0.24.1.tar.gz && ./dist/tracee version

cd ~/racing-the-scanner
sudo ~/tracee/dist/tracee --policy detection/tracee/memory-hiding.yaml \
  --install-path /tmp/tracee-install \
  --output json:$HOME/tracee/out/events.json --output option:parse-arguments
```

- `--install-path` must sit outside a private home directory (mode 750): Tracee
  drops root's file-permission override before it creates that directory.
- The shipped checksum file names `./dist/...` and fails `sha256sum -c`; check
  the hash inline as above.
- "plugin was built with a different version of package net" for
  `signatures/builtin.so` is logged as an error but is not fatal.
- Once it goes quiet it is attached; events go to the file, not the terminal.
  With `scope: global` it writes about 1 MB/s. Stop it with Ctrl-C.
- The output file is owned by root and world-readable.

## Benign suite

`benign/run_benign.py` runs the legitimate workloads (Node.js, Go/Java GC,
jemalloc/SQLite) that trip false alarms, with a dependency-free `--stub` for
pipeline testing.

## G5 harness

`python -m detection.harness` scores three detectors on the same labelled
processes of one Tracee capture and appends one row per detector to
`$RTS_RESULTS_DIR/detection_g5.csv`:

| detector | fires when |
| --- | --- |
| `default_sigs` | Tracee's own signatures fired: `tracee_alerts` > 0 |
| `custom` | raw custom-policy rule: `none_rw_flips` >= 1, `n_userfaultfd` >= 1 or `n_memfd_secret` >= 1 |
| `ai` | triage verdict is "suspicious" (LLM, or the heuristic with `--no-llm`) |

Only the `ai` row fills `triage_backend` and `triage_ms_mean` (mean wall-clock
ms per triage call over the labelled records, for G6). If any record fell back
to the heuristic the backend reads `llm-fallback:<model>` rather than
`llm:<model>`. Detectors live in the `DETECTORS` table in `harness.py`.

## First issues

- Build the end-to-end harness that runs an attacker + a benign app, captures
  Tracee output, and reports catch rate and false-positive rate (G5).
- Wire the overhead measurement for the triage layer (G6).
