# Memory layer (Khan)

The four hiding payloads and the live RAM scanner. **Linux only** (kernel 6.12+
for the full project; V4 needs secret memory enabled). Build on the MacBook's
Linux VM or a dedicated Linux box, not on macOS or Windows directly.

## Build

```bash
make            # builds bin/v1 .. bin/v4
make check      # syntax-check only (what CI runs)
```

## The payloads

| Variant | Mechanism | What the scanner sees |
|---------|-----------|-----------------------|
| `v1` | plain resident 1 MB buffer | always finds the marker (control) |
| `v2` | `mprotect(PROT_NONE)` + SIGSEGV single-page unlock | marker only during the few ms a page is unlocked |
| `v3` | `userfaultfd` + `MADV_DONTNEED` | dropped pages read as zero; refilled on fault |
| `v4` | `memfd_secret` | nothing: secret memory is off the kernel direct map |

Each prints its PID. Keep it running while you scan it. All four variants accept `--interval-ms <ms>` (delay between page touches, `0` for tight loop), `--pattern <seq|random|stride>`, `--duration <sec>` (`0` until Ctrl-C), and `--seed <u64>`, and print a `done: accesses=... faults=... elapsed_s=... faults_per_s=...` summary line on exit.

### V2 options

```bash
./bin/v2 --dwell-ms 10 --interval-ms 100 --pattern seq
```

Additional V2 flag: `--dwell-ms <ms>` (exposure window per page, min `0.1`).

### V3 options

```bash
./bin/v3 --dwell-ms 10 --interval-ms 100 --pattern seq
```

Accepts the same flags as V2 (`--dwell-ms`, `--interval-ms`, `--pattern`, `--duration`, `--seed`). For live `/proc/<pid>/mem` scanner runs where dropped pages return zero-fill, ensure unprivileged userfaultfd can intercept remote faults (`sudo sysctl -w vm.unprivileged_userfaultfd=1` or `CAP_SYS_PTRACE`); otherwise V3 falls back to `UFFD_USER_MODE_ONLY` with a warning on `stderr`.

## Live RAM scanner (`scanner/scanner.py`)

```bash
# from repo root or memory/, as the same user or root
python3 memory/scanner/scanner.py --pid <PID> --variant v2 --dwell-ms 10 --interval 0.1 --duration 30
```

Flags:
- `--pid <int>`: target process ID (required).
- `--interval <sec>`: sleep between scans (default `0.1`).
- `--duration <sec>`: total scan window in seconds (default `30.0`).
- `--rule <path>`: YARA rule file (falls back to plain `RTS_SECRET_MARKER_v1` byte search if `yara-python` is not installed).
- `--entropy-threshold <float>`: 4 KB page Shannon-entropy threshold in bits/byte (default `7.2`, range `(0.0, 8.0]`).
- `--no-entropy`: skip the per-page Shannon-entropy pass and short-circuit on the first marker match (fast path recommended for timing-sensitive runs such as `coupled_live.py` and G1/G2 sweeps).
- `--no-entropy-catch`: log `max_entropy` and `entropy_flagged` without counting high-entropy pages as `found=1`.
- `--variant <str>` / `--dwell-ms <float>` / `--run-id <str>`: sweep metadata written into the CSV rows.
- `--out-dir <path>` (default `$RTS_RESULTS_DIR` or `<repo>/results`), `--scans-csv <path>`, `--summary-csv <path>`, `--no-csv`.

### Entropy & memory-region behavior

- **Anonymous RW filtering**: scans readable+writable anonymous, `[heap]`, `[stack]`, `[anon:...]`, `anon_inode:secretmem`, and `/memfd:*` regions while skipping disk-backed shared-library mappings.
- **Chunk overlap**: reads in `1 MiB` chunks carrying overlap across boundaries (`len(MARKER) - 1` bytes for plain search, `4096 B` when a YARA rule is active) for matching only, while `pages_scanned`, `bytes_scanned`, and page-level Shannon entropy always run on un-overlapped 4 KB pages.
- **Per-page fallback**: if a bulk chunk read raises `EIO` (e.g. V3 under `UFFD_USER_MODE_ONLY`), falls back to 4 KB page reads so any resident page is still scanned. `anon_inode:secretmem` (V4) skips the fallback immediately since kernel direct-map reads always fail.
- **Entropy profiles**: `RTS_MARKER` and its single-byte XOR (`^ 0x5A`) both measure `~3.25` bits/byte; V3 decoy zero-fill pages measure `0.0`; strongly encrypted or PRNG-masked resident pages measure `>= 7.2` (up to `8.0`) and trigger `entropy_flagged=1`.

### CSV outputs for G1 & G2

Unless `--no-csv` is set (recommended for external harnesses that `SIGKILL` the scanner subprocess, such as `coupled_live.py`), completed scans append to two CSVs in `$RTS_RESULTS_DIR` (default `<repo>/results/`):

- `scanner_scans.csv` (flushed per scan): `run_id`, `variant`, `pid`, `interval_s`, `dwell_ms`, `scan`, `elapsed_s`, `found`, `marker_found`, `entropy_flagged`, `max_entropy`, `high_entropy_pages`, `pages_scanned`, `bytes_scanned`, `scan_ms`, plus cumulative `p50_scan_ms`, `p95_scan_ms`, and `p99_scan_ms`.
- `scanner_summary.csv` (1 row per completed run with `scans > 0`): `run_id`, `variant`, `pid`, `interval_s`, `dwell_ms`, `duration_s`, `elapsed_s`, `entropy_threshold`, `scans`, `catches`, `marker_catches`, `entropy_catches`, `catch_rate` (G1), `miss_rate` (G2), `scans_per_s`, `mean_scan_ms`, `p50_scan_ms`, `p95_scan_ms`, `p99_scan_ms`, and `max_entropy`.

The scanner reports catch rate and `p50`/`p95`/`p99` scan latency. V1 should be ~100%. V2/V3 are caught on about the fraction of scans that land in an exposure window, so their per-scan catch rate falls as the dwell time shrinks but does not depend on the scan interval; a longer interval only delays the first catch (G1; see #63, where intervals that were multiples of 50 ms phase-locked to the payload's 100 ms cycle and made it look interval-dependent). V4 should be ~0% from the RAM scanner: it is the case only Tracee's syscall view (Ibad) can flag.

## G1 Sweep (`sweep_g1.py`)

`memory/sweep_g1.py` sweeps scan intervals (`0.037`, `0.137`, `0.537`, `1.537`, `5.037` s: each 37 ms past a multiple of 100 ms, so scans step through V2/V3's 100 ms cycle instead of locking to one phase of it, #63) and dwell times (`1`, `5`, `10`, `25` ms for `v2`/`v3`; `v1`/`v4` have empty `dwell_ms`) across the compiled payloads and writes one row per run/rep to `$RTS_RESULTS_DIR/g1_scan.csv` (default `<repo>/results/g1_scan.csv`, or `g1_scan_smoke.csv` with `--smoke`):

```bash
sudo python3 -m memory.sweep_g1 --smoke   # quick WSL/local verification -> results/g1_scan_smoke.csv
sudo python3 -m memory.sweep_g1           # full #38 sweep on Linux -> results/g1_scan.csv
```

On Ubuntu (`kernel.yama.ptrace_scope=1`), root (`sudo` or `pkexec`) is required so the scanner can read a sibling payload's `/proc/<pid>/mem` (and also grants `CAP_SYS_PTRACE` for full `v3` userfaultfd support without altering `vm.unprivileged_userfaultfd`). In non-interactive environments where `sudo` cannot prompt:

```bash
pkexec sh -c 'cd /path/to/repo && .venv/bin/python -m memory.sweep_g1'
```

Key flags:
- `--intervals <sec ...>`, `--dwell-ms <ms ...>`, `--reps <int>`: override the default grid (`0.037 0.137 0.537 1.537 5.037` s, `1 5 10 25` ms, `3` reps).
- `--seed <int>` (default `1`): with `--pattern random`, rep N runs its payload with `--seed <seed + N>`, so reps don't repeat one page order.
- `--cpu <int>` / `--no-pin`: pin both payload and scanner to one core (default `2` on Linux via `sched_setaffinity`, matching G3).
- `--resume`: skip `(variant, dwell_ms, interval_s, pattern, duration_s, rep)` cells already present in the output CSV.
- `--with-entropy`: enable the per-page Shannon-entropy pass (disabled by default via `--no-entropy`, leaving `max_entropy` blank).
- `--strict`: abort instead of skipping `v4` if `memfd_secret` (`secretmem.enable=1`) is unavailable.

Output columns in `results/g1_scan.csv`: `run_id`, `rep`, `variant`, `dwell_ms`, `interval_s`, `pattern`, `duration_s`, `scans`, `catches`, `catch_rate`, `miss_rate`, `p50_scan_ms`, `p95_scan_ms`, `p99_scan_ms`, `max_entropy`. Cells interrupted mid-run or ending early (`< 90%` of `duration_s`) are discarded rather than written, and `g1_scan.csv` ownership is restored to the `sudo`/`pkexec` caller.

## G2 Sweep (`sweep_g2.py`)

`memory/sweep_g2.py` measures the hiding-vs-slowdown Pareto curve and page-fault cost across `v1`–`v4` (`1`, `5`, `10`, `25` ms dwell times for `v2`/`v3`) and writes one row per cell to `$RTS_RESULTS_DIR/g2_pareto.csv` (or `g2_pareto_smoke.csv` with `--smoke`):

```bash
sudo python3 -m memory.sweep_g2 --smoke   # quick local verification -> results/g2_pareto_smoke.csv
sudo python3 -m memory.sweep_g2           # full #38 sweep on Linux -> results/g2_pareto.csv
```

Each cell runs two pinned phases (default CPU `2`, no competing hogs):
1. **Cost & faults pass**: runs the payload in a tight loop (`--interval-ms 0 --duration 5`) with no scanner to measure `accesses_per_s`, `slowdown_vs_v1 = v1_accesses_per_s / variant_accesses_per_s`, payload `faults`, and kernel `/proc/<pid>/stat` `minflt` delta.
2. **Evasion pass**: runs the paced payload (`--interval-ms 100`) against `scanner.py --interval 0.037 --no-entropy` to measure `evasion_rate = 1 - catch_rate` and `p95_scan_ms`.

Key flags:
- `--dwell-ms <ms ...>`, `--scan-interval <sec>`, `--touch-interval-ms <ms>`, `--pattern <seq|random|stride>`, `--reps <int>`, `--duration <sec>`: override the default `#38` grid (`1 5 10 25` ms, `0.037` s scan, `100` ms touch, `seq`, `3` reps, `5.0` s).
- `--seed <int>` (default `1`): with `--pattern random`, rep N runs its payload with `--seed <seed + N>`.
- `--cpu <int>` / `--no-pin`: pin payload and scanner to one core (default `2` on Linux, `-1` disables).
- `--resume`: skip `(variant, dwell_ms, pattern, duration_s, rep)` cells already present in the CSV and reuse recorded `v1` baselines.
- `--with-entropy` / `--strict`: enable scanner entropy pass (`max_entropy` telemetry only) or abort instead of skipping `v4` if `memfd_secret` is unavailable.

Output columns in `results/g2_pareto.csv`: `run_id`, `rep`, `variant`, `dwell_ms`, `pattern`, `duration_s`, `accesses`, `accesses_per_s`, `slowdown_vs_v1`, `faults`, `faults_per_s`, `minflt`, `evasion_rate`, `catch_rate`, `p95_scan_ms`.
