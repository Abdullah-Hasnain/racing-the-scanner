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

## Scan it

```bash
# in another terminal, as the same user or root
python scanner/scanner.py --pid <PID> --interval 0.1 --duration 30
```

The scanner reports a catch rate. V1 should be ~100%. V2/V3 fall as the scan
interval grows or dwell time shrinks (that is G1). V4 should be ~0% from the RAM
scanner: it is the case only Tracee's syscall view (Ibad) can flag.

## First issues

- V2: implement dwell-based re-locking of the previous page and the access
  pattern that drives it.
- V3: implement drop-after-use and the measurement hooks.
- Scanner: add entropy checks and per-scan p50/p95/p99 logging to CSV.

See the repo issues for the full acceptance criteria.
