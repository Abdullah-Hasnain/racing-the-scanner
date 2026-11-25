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
| `v2 --dwell-ms 10 --interval-ms 50` | 200 unlocks `''` to `PROT_READ\|PROT_WRITE`, 201 locks back to `PROT_NONE` | `none_rw_flips` 401, `rw_rx_flips` 0 |
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

## Coupled attack on the real kernel

`coupled_live.py` runs the reservation half of the simulation's claim on real
Linux (#15), in the simulation's four G3 conditions. The attacker shares one
core with the live RAM scanner and claims nice -20, as the simulation's attacker
claims a high priority:

| condition | attacker |
|---|---|
| `none` | V1, which never hides its marker |
| `starvation` | V1 plus 4 CPU hogs |
| `hiding` | V2, which hides its marker except for 10 ms per 100 ms |
| `coupled` | V2 plus 4 CPU hogs |

The hogs start after the scanner's first scan, since a monitor is already
running when an attack begins, and only the scans in the next 20 s count.
Policies for the scanner: `eevdf` (stock, no reservation), `cgroup_weight`
(alone in a cgroup with cpu.weight 10000 vs the attacker's 100) and
`sched_fifo` (SCHED_FIFO 10). The ML policies exist only in the simulation.
It needs root. The real-kernel half of G3 is drawn from the CSV by #33:

```bash
make -C memory
pkexec "$PWD/.venv/bin/python" "$PWD/detection/coupled_live.py" --repo "$PWD"
# the equal-nice control row (3 reps):
pkexec "$PWD/.venv/bin/python" "$PWD/detection/coupled_live.py" --repo "$PWD" \
  --attacker-nice 0 --conditions coupled --policies eevdf --out results/coupled_live_equal_nice.csv
```

A cell fails loudly, rather than recording a starved-looking row, if the scanner
never scans or stops early, or the attacker exits early. Rows are written as
each cell finishes, and every child dies with the harness.

Kernel 7.0.0-44, Intel Core i7-14700F (bare metal), pinned to CPU 2 (a P-core),
3 reps of 20 s per cell, at commit 0fde0f5 (run `20261125-151359`; equal-nice row
`20261125-152640`). The scanner sleeps 37 ms between scans, which does not divide
V2's 100 ms period, so scans sample its whole cycle.

| condition | policy | scans/s | scans that caught the attacker |
|---|---|---|---|
| none | all three | 26.75 to 26.8 | 535 to 536 (every scan) |
| starvation | eevdf | 2.6 to 3.15 | 52 to 63 (every scan) |
| starvation | cgroup_weight, sched_fifo | 26.85 to 26.9 | 537 to 538 |
| hiding | all three | 26.75 to 26.85 | 52 to 59 |
| coupled | eevdf | 4.2 to 4.75 | 15 to 17 |
| coupled | cgroup_weight, sched_fifo | 26.9 to 26.95 | 50 to 55 |
| coupled, attacker at nice 0 | eevdf | 26.55 | 56 to 62 |

- The scanner loses CPU only when the attacker hogs, and only under stock
  EEVDF: about 89% of its scans under starvation, about 83% under the coupled
  attack (catches down about 70% against hiding alone). Either reservation keeps
  every condition at the no-attack level, without judging any process.
- Hiding alone costs the scanner no scans; it only means about 10% of scans
  land in V2's exposure window.
- Under the coupled attack, catches fall less than scans because the scans that
  do run catch V2 more often (16 to 18% of scans, 15/94 to 17/95, against 10%).
  That is observed, not explained; sharing a core with V2 may bunch the
  scanner's turns around V2's wakeups. If so, the starved scanner's catches are
  inflated, and the catch loss under the coupled attack is a lower bound.
- Scan time itself does not grow (p95 at most 0.42 ms in any cell); the
  starvation is the scanner waiting longer for its turn between scans.
- At equal nice the hogs do not starve the scanner (last row,
  `results/coupled_live_equal_nice.csv`). The attack needs the claimed priority.
- V2 made 210 to 215 faults in every cell, so the hogs did not slow the hider.
- An earlier run of the same grid (pre-#45 scanner, harness not pinned) lost less
  under EEVDF: 6.0 to 6.2 scans/s under starvation and 10.8 to 11.0 under the
  coupled attack, with every reservation row the same as here. Between the two
  runs the scanner changed (#45/#49: chunked reads, no file-backed mappings,
  per-scan percentiles) and the harness moved off the measured core; which one
  moved the EEVDF rows is not established. The conclusion does not change.

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

## First issues

- Build the end-to-end harness that runs an attacker + a benign app, captures
  Tracee output, and reports catch rate and false-positive rate (G5).
- Wire the overhead measurement for the triage layer (G6).
