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
| `none_rw_flips` | to or from PROT_NONE, whatever the other side | V2 hiding, but also runtime heap commits and guard pages |
| `relock_trips` | a region (same `addr`, `len`) unlocked from PROT_NONE, then locked again | V2-style hiding (unlock, re-lock) |
| `rw_rx_flips` | write access swapped for exec, or back (RW to RX, RX to RW), neither side PROT_NONE | a JIT (V8, the benign stub) |

`none_rw_flips` counts any access on the other side (R, RW, RX, RWX), so a hider
cannot dodge it by unlocking with exec or read-only access. The cost is overlap
with benign apps: guard pages (Go, Java) and polling pages (older JVM safepoints)
also flip to and from PROT_NONE. On the first G5 capture node made 158 and the
JVM 1,413 such flips.

What separates hiding is the round trip: V2 unlocks a page and later locks the
same page again. `relock_trips` counts regions (same `addr` and `len`) unlocked
from PROT_NONE and then locked again. On that capture V2 made 200, node and the
JVM 0. The `custom` detector and the heuristic use `relock_trips`, not raw flips.
Limits of `relock_trips`:
- A hider that relocks with a different `addr` or `len` than it unlocked with
  (say, the whole buffer at once) is not counted, though raw flips would catch
  it. Exact matching is deliberate: V8 unlocks pieces of a region and later
  locks the whole region, and overlap matching would count that.
- Tracee's stream is not strictly time-ordered across CPUs. A lock then unlock
  of one region that arrives reversed reads as a trip; so can an address reused
  after `munmap`, since the unlocked set is never cleared. Neither showed up on
  the 30 held-out benign processes.
- The benign runtimes measured are Node 22, JDK 25 and Go 1.26. Older JVMs flip
  a safepoint polling page to PROT_NONE and back, a benign round trip.

Counts are per memory region (VMA), not per call: the kernel runs the LSM hook
once for each VMA an mprotect call spans. V2 touches one page per call, so it is
unaffected; a JIT protecting a range that spans several VMAs counts more than once.

Two consequences for G5 and hand-written fixtures. Flips come only from
`security_file_mprotect`, so a log without the raw `mprotect` syscall event has
`n_mprotect` 0 beside nonzero flip counts. And a JIT that skips W^X and flips
RW to RWX never loses write access, so it adds no `rw_rx_flips`.

Tracee reports `prev_prot` as the region's raw vm_flags (for example `0x70` for a
PROT_NONE region); only the R/W/X bits are read. With `parse-arguments`, a
PROT_NONE region's `prev_prot` renders as `""`, not `"PROT_NONE"`. Both forms
are handled.

Checked on a real capture (Tracee v0.24.1, kernel 7.0, 10 s, policy as shipped):

| process | Tracee events | aggregator |
|---|---|---|
| `v2 --dwell-ms 10 --interval-ms 50` | 200 unlocks `''` to `PROT_READ\|PROT_WRITE`, 201 locks back to `PROT_NONE` | `none_rw_flips` 401, `relock_trips` 200, `rw_rx_flips` 0 |
| `run_benign.py --stub` | 9343 RW to RX and 9343 RX to RW, `prev_prot` carrying `PROT_SEM` (VM_SHARED) | `none_rw_flips` 0, `rw_rx_flips` 18686 |

V2 made 200 faults and 200 re-locks, plus the initial whole-buffer lock: 401.
`security_file_mprotect` fires once per `mprotect` call here, anonymous memory
included. The stub's process name is `python`, not `python3`.

## Signal features

Tracee (v0.23.2 and v0.24.1) has no event for a SIGSEGV being delivered, so the
policy watches the handler being installed:

| feature | event | meaning |
|---|---|---|
| `segv_handlers` | `rt_sigaction` with signum 11 and a non-null `act` | the process installed a SIGSEGV handler |

Go and Java install SIGSEGV handlers too, so `segv_handlers` alone is weak. What
marks V2 is the page its handler unlocks on each fault, which `none_rw_flips`
and `relock_trips` already count.

There is no `rt_sigreturn` feature because Tracee never emits that event, whatever
the policy says. In its eBPF code (`pkg/ebpf/c/tracee.bpf.c`, the same in v0.23.2,
v0.24.1 and main) `sys_enter` does not mark `rt_sigreturn` as in flight, so
`sys_exit` drops it, and `sys_enter_submit` skips it by id. A live V2 run that
handled 200 faults logged 0 `rt_sigreturn` events, and the G5 capture logged 0
beside 3,396 `rt_sigaction` events.

## Running Tracee

Use **v0.23.2**. v0.24.0 and v0.24.1 ship a signatures plugin that fails to load
("plugin was built with a different version of package net"), so they run with
no default signatures at all: `tracee list` shows an empty "Signature Events"
section, and the G5 `default_sigs` detector would measure nothing. v0.23.2 loads
65 signatures, 27 of them in the default set. Both versions report
`security_file_mprotect` and `rt_sigaction` with the same fields.

Tracee needs real root: `perf_event_paranoid` is 4 on Ubuntu, so the `CAP_BPF` +
`CAP_PERFMON` route does not apply. Run it from an interactive terminal where
`sudo` can prompt.

```bash
mkdir -p ~/tracee/out && cd ~/tracee
curl -fLO https://github.com/aquasecurity/tracee/releases/download/v0.23.2/tracee-x86_64.v0.23.2.tar.gz
echo "6a3f2cdc5023bc833d261cf4e3d84ff258b24a8b313f8f20438f0b04842060fa  tracee-x86_64.v0.23.2.tar.gz" | sha256sum -c
mkdir -p v0.23.2 && tar -xzf tracee-x86_64.v0.23.2.tar.gz -C v0.23.2
./v0.23.2/dist/tracee list --wide | grep -c "signatures, default"   # expect 27

cd ~/racing-the-scanner
sudo ~/tracee/v0.23.2/dist/tracee \
  --policy detection/tracee/memory-hiding.yaml \
  --policy detection/tracee/default-signatures.yaml \
  --install-path /tmp/tracee-install \
  --output json:$HOME/tracee/out/events.json --output option:parse-arguments
```

`default-signatures.yaml` lists the default set by name, because a policy rule
cannot name an event set (`event: default` is rejected as "not valid").

- `--install-path` must sit outside a private home directory (mode 750): Tracee
  drops root's file-permission override before it creates that directory.
- Check the hash inline as above; the shipped checksum file names `./dist/...`.
- Once it goes quiet it is attached; events go to the file, not the terminal.
  With `scope: global` it writes about 1 MB/s. Stop it with Ctrl-C.
- The output file is owned by root and world-readable.

## Benign suite

`benign/run_benign.py` runs the legitimate workloads (Node.js, Go/Java GC,
jemalloc/SQLite) that trip false alarms, with a dependency-free `--stub` for
pipeline testing.

```bash
python3 detection/benign/run_benign.py --workload {node,go-gc,java-gc,malloc,sqlite} [--seconds 30]
python3 detection/benign/run_benign.py --stub
```

Compiled workloads are built first, so no compiler runs in the measured
process. Tracee's `processName` for each is `node`, `gcstress`, `java` (plus JVM
thread names such as `G1 Conc#0`), `malloc_churn`, and `python3` for `sqlite`.

## G5 harness

`python -m detection.harness` scores three detectors on the same labelled
processes of one Tracee capture and appends one row per detector to
`$RTS_RESULTS_DIR/detection_g5.csv`:

| detector | fires when |
| --- | --- |
| `default_sigs` | Tracee's own signatures fired: `tracee_alerts` > 0 |
| `custom` | custom-policy rule: `relock_trips` >= 1, `n_userfaultfd` >= 1 or `n_memfd_secret` >= 1 |
| `ai` | triage verdict is "suspicious" (LLM, or the heuristic with `--no-llm`) |

Only the `ai` row fills `triage_backend` and `triage_ms_mean` (mean wall-clock
ms per triage call over the labelled records, for G6). If any record fell back
to the heuristic the backend reads `llm-fallback:<model>` rather than
`llm:<model>`. Detectors live in the `DETECTORS` table in `harness.py`.

Score each capture once. `default_sigs` and `custom` don't depend on the
triage backend, so scoring the same capture twice (say `--no-llm`, then with
the LLM) appends duplicate rows for them, and G5 pools rows by summing. The
harness refuses to append to a `detection_g5.csv` with an older column layout;
move that file aside first.

## First issues

- Build the end-to-end harness that runs an attacker + a benign app, captures
  Tracee output, and reports catch rate and false-positive rate (G5).
- Wire the overhead measurement for the triage layer (G6).
