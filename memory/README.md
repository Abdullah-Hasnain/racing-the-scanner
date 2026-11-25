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

Each prints its PID. Keep it running while you scan it.

### V2 options

```bash
./bin/v2 --dwell-ms 10 --interval-ms 100 --pattern seq
```

Flags: `--dwell-ms <ms>` (exposure window per page, min 0.1), `--interval-ms <ms>` (delay between touches, `0` for tight loop), `--pattern <seq|random|stride>`, `--duration <sec>` (`0` until Ctrl-C), and `--seed <u64>`.

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

The scanner reports catch rate and `p50`/`p95`/`p99` scan latency. V1 should be ~100%. V2/V3 fall as the scan interval grows or dwell time shrinks (that is G1). V4 should be ~0% from the RAM scanner: it is the case only Tracee's syscall view (Ibad) can flag.
