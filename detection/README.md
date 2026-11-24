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
It needs root; `analysis/make_graphs.py` draws `G3_real_kernel.png` from the CSV:

```bash
make -C memory
pkexec "$PWD/.venv/bin/python" "$PWD/detection/coupled_live.py" --repo "$PWD"
```

Kernel 7.0.0-44, Intel Core i7-14700F (bare metal), pinned to CPU 2 (a P-core),
3 reps of 20 s per cell. The scanner sleeps 37 ms between scans, which does not
divide V2's 100 ms period, so scans sample its whole cycle.

| condition | policy | scans/s | scans that caught the attacker |
|---|---|---|---|
| none | all three | 26.6 to 26.7 | 531 to 534 (every scan) |
| starvation | eevdf | 6.0 to 6.2 | 119 to 123 (every scan) |
| starvation | cgroup_weight, sched_fifo | 26.7 to 26.8 | 534 to 536 |
| hiding | all three | 26.8 | 52 to 58 |
| coupled | eevdf | 10.8 to 11.0 | 30 to 38 |
| coupled | cgroup_weight, sched_fifo | 26.9 | 52 to 57 |
| coupled, attacker at nice 0 | eevdf | 26.5 | 53 to 60 |

- The scanner loses CPU only when the attacker hogs, and only under stock
  EEVDF: about 77% of its scans under starvation, about 60% under the coupled
  attack (catches down about 35%). Either reservation keeps every condition at
  the no-attack level, without judging any process.
- Hiding alone costs the scanner no scans; it only means about 10% of scans
  land in V2's exposure window.
- Under the coupled attack, catches fall less than scans because the scans that
  do run catch V2 more often (14 to 17% of scans against 10%). That is observed,
  not explained; sharing a core with V2 may bunch the scanner's turns around
  V2's wakeups.
- Scan time itself does not grow (p95 at most 0.6 ms in any cell); the
  starvation is the scanner waiting longer for its turn between scans.
- At equal nice the hogs do not starve the scanner (last row,
  `results/coupled_live_equal_nice.csv`): it uses about 1% of a core, and EEVDF
  already gives a light, mostly sleeping task that much. The attack needs the
  claimed priority.
- V2 made 210 to 211 faults in every cell, so the hogs did not slow the hider.

## Benign suite

`benign/run_benign.py` runs the legitimate workloads (Node.js, Go/Java GC,
jemalloc/SQLite) that trip false alarms, with a dependency-free `--stub` for
pipeline testing.

## First issues

- Build the end-to-end harness that runs an attacker + a benign app, captures
  Tracee output, and reports catch rate and false-positive rate (G5).
- Wire the overhead measurement for the triage layer (G6).
