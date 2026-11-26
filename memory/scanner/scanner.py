"""D1: live RAM scanner.

Reads a target process's writable anonymous regions from /proc/<pid>/maps and
scans /proc/<pid>/mem for the YARA marker and high-entropy 4 KB pages at a
configurable interval. Logs per-scan latency percentiles (p50/p95/p99), entropy
metrics, and catch results to CSV files in results/ for G1 and G2.

Linux only at runtime (it reads /proc). Needs permission to read the target's
memory (same user, or root).

Uses yara-python if installed; otherwise falls back to a plain byte search so
the module works with zero third-party runtime dependencies.

Usage:
  sudo python3 memory/scanner/scanner.py --pid 12345 --interval 0.1 --duration 30
"""

from __future__ import annotations

import argparse
import bisect
import csv
import math
import os
import re
import signal
import sys
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

MARKER = b"RTS_SECRET_MARKER_v1"
PAGE_SIZE = 4096
CHUNK_SIZE = 1024 * 1024  # 1 MiB (exact multiple of PAGE_SIZE)
MAX_FALLBACK_REGION_BYTES = 16 * 1024 * 1024
DEFAULT_ENTROPY_THRESHOLD = 7.2

_ZERO_PAGE = b"\x00" * PAGE_SIZE
_PAGE_ENTROPY_LUT: tuple[float, ...] = tuple(
    0.0 if count == 0 else -(count / PAGE_SIZE) * math.log2(count / PAGE_SIZE)
    for count in range(PAGE_SIZE + 1)
)
_MAPS_RE = re.compile(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+\S+\s+\S+\s+\S+(?:\s+(.*))?$")

SCANS_FIELDS = [
    "run_id",
    "variant",
    "pid",
    "interval_s",
    "dwell_ms",
    "scan",
    "elapsed_s",
    "found",
    "marker_found",
    "entropy_flagged",
    "max_entropy",
    "high_entropy_pages",
    "pages_scanned",
    "bytes_scanned",
    "scan_ms",
    "p50_scan_ms",
    "p95_scan_ms",
    "p99_scan_ms",
]

SUMMARY_FIELDS = [
    "run_id",
    "variant",
    "pid",
    "interval_s",
    "dwell_ms",
    "duration_s",
    "elapsed_s",
    "entropy_threshold",
    "scans",
    "catches",
    "marker_catches",
    "entropy_catches",
    "catch_rate",
    "miss_rate",
    "scans_per_s",
    "mean_scan_ms",
    "p50_scan_ms",
    "p95_scan_ms",
    "p99_scan_ms",
    "max_entropy",
]

try:
    import yara  # type: ignore

    _HAVE_YARA = True
except (ImportError, OSError):  # not installed, or libyara itself fails to load
    _HAVE_YARA = False


@dataclass(frozen=True)
class Region:
    """A readable, writable target mapping parsed from /proc/<pid>/maps."""

    start: int
    end: int
    perms: str
    pathname: str = ""

    @property
    def is_secretmem(self) -> bool:
        """Return True for memfd_secret mappings (anon_inode:secretmem)."""
        return "secretmem" in self.pathname


@dataclass(frozen=True)
class ScanResult:
    """Outcome and telemetry from one full scan of a target's memory."""

    found: bool
    marker_found: bool
    entropy_flagged: bool
    max_entropy: float
    high_entropy_pages: int
    pages_scanned: int
    bytes_scanned: int


def shannon_entropy(data: bytes | bytearray | memoryview) -> float:
    """Compute Shannon entropy in bits/byte over [0.0, 8.0]."""
    n = len(data)
    if n == 0:
        return 0.0
    if n == PAGE_SIZE:
        if data == _ZERO_PAGE:
            return 0.0
        counts = Counter(data)
        if len(counts) <= 1:
            return 0.0
        return sum(_PAGE_ENTROPY_LUT[c] for c in counts.values())

    counts = Counter(data)
    if len(counts) <= 1:
        return 0.0
    inv_n = 1.0 / n
    return -sum((c * inv_n) * math.log2(c * inv_n) for c in counts.values())


def percentile_sorted(sorted_vals: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile on an already-sorted non-empty sequence."""
    if not sorted_vals:
        raise ValueError("cannot compute percentile of an empty sequence")
    if not 0.0 <= q <= 100.0:
        raise ValueError(f"percentile q must be in [0, 100], got {q}")
    n = len(sorted_vals)
    if n == 1:
        return float(sorted_vals[0])
    pos = (q / 100.0) * (n - 1)
    lo = int(pos)
    hi = min(lo + 1, n - 1)
    frac = pos - lo
    return float(sorted_vals[lo] + frac * (sorted_vals[hi] - sorted_vals[lo]))


def percentile(vals: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile matching numpy's default method."""
    if not vals:
        raise ValueError("cannot compute percentile of an empty sequence")
    return percentile_sorted(sorted(vals), q)


def _parse_maps(maps_text: str) -> list[Region]:
    """Parse /proc/<pid>/maps text into readable+writable anonymous regions."""
    regions: list[Region] = []
    for line in maps_text.splitlines():
        m = _MAPS_RE.match(line)
        if not m:
            continue
        perms = m.group(3)
        if "r" not in perms or "w" not in perms:
            continue
        pathname = (m.group(4) or "").strip()
        # Skip disk-backed libraries/binaries, but retain anonymous, [heap],
        # [stack], [anon:...], anon_inode:secretmem (V4), and /memfd:* regions.
        if pathname.startswith("/") and not pathname.startswith("/memfd"):
            continue
        regions.append(
            Region(
                start=int(m.group(1), 16),
                end=int(m.group(2), 16),
                perms=perms,
                pathname=pathname,
            )
        )
    return regions


def _readable_regions(pid: int) -> list[Region]:
    """Return readable, writable anonymous regions for `pid`."""
    maps_text = Path(f"/proc/{pid}/maps").read_text(encoding="utf-8", errors="replace")
    return _parse_maps(maps_text)


def _next_tail(prev_tail: bytes, raw_chunk: bytes, overlap_len: int) -> bytes:
    if overlap_len <= 0:
        return b""
    if len(raw_chunk) >= overlap_len:
        return raw_chunk[-overlap_len:]
    return (prev_tail + raw_chunk)[-overlap_len:]


def _scan_stream(
    regions: Sequence[Region],
    mem: BinaryIO,
    rule=None,
    *,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    catch_on_entropy: bool = True,
    compute_entropy: bool = True,
) -> ScanResult:
    """Scan `regions` from an open memory stream for marker matches and entropy."""
    marker_found = False
    max_entropy = 0.0
    high_entropy_pages = 0
    pages_scanned = 0
    bytes_scanned = 0
    overlap_len = PAGE_SIZE if rule is not None else max(len(MARKER) - 1, 0)

    def _process_raw_chunk(raw_chunk: bytes, prev_tail: bytes) -> bytes:
        nonlocal marker_found, max_entropy, high_entropy_pages, pages_scanned, bytes_scanned

        # Compute byte/page counts and page-aligned entropy strictly on raw_chunk
        # so overlap bytes never shift page boundaries or double-count bytes.
        bytes_scanned += len(raw_chunk)
        if compute_entropy:
            for off in range(0, len(raw_chunk), PAGE_SIZE):
                page = raw_chunk[off : off + PAGE_SIZE]
                pages_scanned += 1
                ent = shannon_entropy(page)
                if ent > max_entropy:
                    max_entropy = ent
                if ent >= entropy_threshold:
                    high_entropy_pages += 1
        else:
            pages_scanned += (len(raw_chunk) + PAGE_SIZE - 1) // PAGE_SIZE

        if not marker_found:
            search_buf = prev_tail + raw_chunk if prev_tail else raw_chunk
            if rule is not None:
                if rule.match(data=search_buf):
                    marker_found = True
            elif MARKER in search_buf:
                marker_found = True

        return _next_tail(prev_tail, raw_chunk, overlap_len)

    for reg in regions:
        if marker_found and not compute_entropy:
            break
        prev_tail = b""
        pos = reg.start
        while pos < reg.end:
            want = min(CHUNK_SIZE, reg.end - pos)
            try:
                mem.seek(pos)
                raw_chunk = mem.read(want)
            except (OSError, ValueError, OverflowError):
                prev_tail = b""
                if reg.is_secretmem or (reg.end - reg.start) > MAX_FALLBACK_REGION_BYTES:
                    break
                # Fallback to 4 KB reads so EIO on a dropped page (e.g. V3 under
                # UFFD_USER_MODE_ONLY) still allows scanning any resident page.
                chunk_end = pos + want
                for page_addr in range(pos, chunk_end, PAGE_SIZE):
                    page_want = min(PAGE_SIZE, chunk_end - page_addr)
                    try:
                        mem.seek(page_addr)
                        page_bytes = mem.read(page_want)
                    except (OSError, ValueError, OverflowError):
                        prev_tail = b""
                        continue
                    if page_bytes:
                        prev_tail = _process_raw_chunk(page_bytes, prev_tail)
                        if marker_found and not compute_entropy:
                            break
                    else:
                        prev_tail = b""
                if marker_found and not compute_entropy:
                    break
                pos = chunk_end
                continue

            if not raw_chunk:
                break
            prev_tail = _process_raw_chunk(raw_chunk, prev_tail)
            if marker_found and not compute_entropy:
                break
            pos += len(raw_chunk)

    entropy_flagged = compute_entropy and high_entropy_pages > 0
    found = marker_found or (entropy_flagged and catch_on_entropy)
    return ScanResult(
        found=found,
        marker_found=marker_found,
        entropy_flagged=entropy_flagged,
        max_entropy=max_entropy,
        high_entropy_pages=high_entropy_pages,
        pages_scanned=pages_scanned,
        bytes_scanned=bytes_scanned,
    )


def _scan_once(
    pid: int,
    rule=None,
    *,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    catch_on_entropy: bool = True,
    compute_entropy: bool = True,
) -> ScanResult:
    regions = _readable_regions(pid)
    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        return _scan_stream(
            regions,
            mem,
            rule,
            entropy_threshold=entropy_threshold,
            catch_on_entropy=catch_on_entropy,
            compute_entropy=compute_entropy,
        )


def _default_out_dir() -> Path:
    env_dir = os.environ.get("RTS_RESULTS_DIR")
    if env_dir:
        return Path(env_dir)
    return Path(__file__).resolve().parents[2] / "results"


def _caller_ugid() -> tuple[int, int] | None:
    """Return (uid, gid) of the sudo/pkexec caller when running as root on POSIX."""
    if os.name != "posix" or not hasattr(os, "geteuid") or not hasattr(os, "chown"):
        return None
    if os.geteuid() != 0:
        return None
    uid_raw = os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID")
    if not uid_raw:
        return None
    try:
        uid = int(uid_raw)
    except ValueError:
        return None
    if uid < 0:
        return None

    gid_raw = os.environ.get("PKEXEC_GID") or os.environ.get("SUDO_GID")
    gid = -1
    if gid_raw:
        try:
            gid = int(gid_raw)
        except ValueError:
            gid = -1
    if gid < 0:
        try:
            import pwd

            gid = pwd.getpwuid(uid).pw_gid
        except (ImportError, KeyError, ValueError, OSError):
            gid = -1
    return (uid, gid)


def _chown_if_sudo(path: Path) -> None:
    ugid = _caller_ugid()
    if ugid is None:
        return
    uid, gid = ugid
    try:
        os.chown(path, uid, gid)
    except OSError as exc:
        print(f"[scanner] warning: could not hand {path} back to uid {uid}: {exc}", file=sys.stderr)


def _ensure_parent_dir(path: Path) -> None:
    parent = path.parent
    missing = [d for d in (parent, *parent.parents) if not d.exists()]
    parent.mkdir(parents=True, exist_ok=True)
    ugid = _caller_ugid()
    if ugid is not None:
        uid, gid = ugid
        for d in reversed(missing):
            try:
                os.chown(d, uid, gid)
            except OSError as exc:
                print(f"[scanner] warning: could not hand {d} back to uid {uid}: {exc}", file=sys.stderr)


def _validate_csv_header(path: Path, expected_fields: Sequence[str]) -> bool:
    """Return True if `path` exists and is non-empty; raise ValueError on schema mismatch."""
    if not path.exists() or path.stat().st_size == 0:
        return False
    with path.open("r", newline="", encoding="utf-8") as f:
        header = next(csv.reader(f), None)
    if header != list(expected_fields):
        raise ValueError(
            f"{path} has mismatched CSV columns: {header!r} != {list(expected_fields)!r}"
        )
    return True


def _open_csv_writer(path: Path, fieldnames: Sequence[str]):
    """Ensure parent dir, validate or write header, and return (file_handle, DictWriter)."""
    has_data = _validate_csv_header(path, fieldnames)
    _ensure_parent_dir(path)
    existed = path.exists()
    handle = path.open("a", newline="", encoding="utf-8")
    if not existed:
        _chown_if_sudo(path)
    writer = csv.DictWriter(handle, fieldnames=list(fieldnames))
    if not has_data:
        writer.writeheader()
        handle.flush()
    return handle, writer


def _make_run_id(pid: int) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return f"{ts}-{os.getpid()}-{pid}"


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Live RAM scanner (D1)")
    ap.add_argument("--pid", type=int, required=True, help="target process ID")
    ap.add_argument("--interval", type=float, default=0.1, help="seconds between scans")
    ap.add_argument("--duration", type=float, default=30.0, help="scan duration in seconds")
    ap.add_argument("--rule", default=str(Path(__file__).parent / "rules" / "test.yar"))
    ap.add_argument(
        "--entropy-threshold",
        type=float,
        default=DEFAULT_ENTROPY_THRESHOLD,
        help="Shannon entropy threshold in bits/byte for flagging 4 KB pages",
    )
    ap.add_argument(
        "--no-entropy",
        action="store_true",
        help="skip the per-page Shannon-entropy pass (fast path for timing runs)",
    )
    ap.add_argument(
        "--no-entropy-catch",
        action="store_true",
        help="log entropy metrics without counting high-entropy pages as found=1",
    )
    ap.add_argument("--variant", default="", help="payload variant label (e.g. v1, v2, v3, v4)")
    ap.add_argument("--dwell-ms", type=float, default=None, help="target dwell_ms metadata for CSV")
    ap.add_argument("--run-id", default=None, help="run identifier for CSV rows")
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=_default_out_dir(),
        help="directory for scanner CSV outputs (default: $RTS_RESULTS_DIR or <repo>/results)",
    )
    ap.add_argument("--scans-csv", type=Path, default=None, help="override per-scan CSV path")
    ap.add_argument("--summary-csv", type=Path, default=None, help="override summary CSV path")
    ap.add_argument("--no-csv", action="store_true", help="disable CSV output")
    args = ap.parse_args(argv)

    if args.interval < 0.0:
        ap.error("--interval must be non-negative")
    if args.duration <= 0.0:
        ap.error("--duration must be positive")
    if not 0.0 < args.entropy_threshold <= 8.0:
        ap.error("--entropy-threshold must be in (0.0, 8.0]")
    if args.dwell_ms is not None and args.dwell_ms < 0.0:
        ap.error("--dwell-ms must be non-negative")

    scans_csv = args.scans_csv or (args.out_dir / "scanner_scans.csv")
    summary_csv = args.summary_csv or (args.out_dir / "scanner_summary.csv")

    if not args.no_csv:
        try:
            _validate_csv_header(scans_csv, SCANS_FIELDS)
            _validate_csv_header(summary_csv, SUMMARY_FIELDS)
        except ValueError as exc:
            print(f"[scanner] {exc}", file=sys.stderr)
            return 2

    rule = None
    if _HAVE_YARA and Path(args.rule).exists():
        rule = yara.compile(filepath=args.rule)
    else:
        print("[scanner] yara not available; using plain byte search", flush=True)

    run_id = args.run_id or _make_run_id(args.pid)
    dwell_str = "" if args.dwell_ms is None else f"{args.dwell_ms:.4g}"
    compute_entropy = not args.no_entropy
    catch_on_entropy = compute_entropy and not args.no_entropy_catch

    stop = False

    def _on_signal(_signum, _frame) -> None:
        nonlocal stop
        stop = True

    prev_sigint = signal.getsignal(signal.SIGINT)
    prev_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    hits = marker_hits = entropy_hits = total = 0
    sum_scan_ms = 0.0
    run_max_entropy = 0.0
    sorted_ms: list[float] = []
    scans_fh = None
    scans_writer = None

    perf_start = time.perf_counter()
    t_end = time.monotonic() + args.duration

    try:
        while not stop and time.monotonic() < t_end:
            t0 = time.perf_counter()
            try:
                res = _scan_once(
                    args.pid,
                    rule,
                    entropy_threshold=args.entropy_threshold,
                    catch_on_entropy=catch_on_entropy,
                    compute_entropy=compute_entropy,
                )
            except (FileNotFoundError, ProcessLookupError):
                print("[scanner] target process gone", flush=True)
                break
            dt = (time.perf_counter() - t0) * 1000.0
            elapsed_s = time.perf_counter() - perf_start

            total += 1
            hits += int(res.found)
            marker_hits += int(res.marker_found)
            entropy_hits += int(res.entropy_flagged)
            sum_scan_ms += dt
            if res.max_entropy > run_max_entropy:
                run_max_entropy = res.max_entropy
            bisect.insort(sorted_ms, dt)

            p50 = percentile_sorted(sorted_ms, 50.0)
            p95 = percentile_sorted(sorted_ms, 95.0)
            p99 = percentile_sorted(sorted_ms, 99.0)

            print(
                f"scan {total:>4}  found={int(res.found)}  scan_ms={dt:7.2f}"
                f"  max_entropy={res.max_entropy:5.2f}  entropy_flag={int(res.entropy_flagged)}",
                flush=True,
            )

            if not args.no_csv:
                if scans_writer is None:
                    scans_fh, scans_writer = _open_csv_writer(scans_csv, SCANS_FIELDS)
                scans_writer.writerow(
                    {
                        "run_id": run_id,
                        "variant": args.variant,
                        "pid": args.pid,
                        "interval_s": args.interval,
                        "dwell_ms": dwell_str,
                        "scan": total,
                        "elapsed_s": round(elapsed_s, 6),
                        "found": int(res.found),
                        "marker_found": int(res.marker_found),
                        "entropy_flagged": int(res.entropy_flagged),
                        "max_entropy": round(res.max_entropy, 4),
                        "high_entropy_pages": res.high_entropy_pages,
                        "pages_scanned": res.pages_scanned,
                        "bytes_scanned": res.bytes_scanned,
                        "scan_ms": round(dt, 4),
                        "p50_scan_ms": round(p50, 4),
                        "p95_scan_ms": round(p95, 4),
                        "p99_scan_ms": round(p99, 4),
                    }
                )
                scans_fh.flush()

            if not stop and args.interval > 0.0:
                rem = t_end - time.monotonic()
                if rem > 0.0:
                    time.sleep(min(args.interval, rem))
    finally:
        if scans_fh is not None:
            scans_fh.close()
        signal.signal(signal.SIGINT, prev_sigint)
        signal.signal(signal.SIGTERM, prev_sigterm)

    if total > 0:
        total_elapsed_s = time.perf_counter() - perf_start
        catch_rate = hits / total
        miss_rate = 1.0 - catch_rate
        scans_per_s = total / total_elapsed_s if total_elapsed_s > 0.0 else 0.0
        mean_ms = sum_scan_ms / total
        p50 = percentile_sorted(sorted_ms, 50.0)
        p95 = percentile_sorted(sorted_ms, 95.0)
        p99 = percentile_sorted(sorted_ms, 99.0)

        print(
            f"\ncatch rate: {hits}/{total} = {catch_rate:.2%}"
            f" (marker={marker_hits}, entropy={entropy_hits})"
        )
        print(
            f"scan_ms: p50={p50:.2f}  p95={p95:.2f}  p99={p99:.2f}"
            f"  max_entropy={run_max_entropy:.2f}",
            flush=True,
        )

        if not args.no_csv:
            sum_fh, sum_writer = _open_csv_writer(summary_csv, SUMMARY_FIELDS)
            try:
                sum_writer.writerow(
                    {
                        "run_id": run_id,
                        "variant": args.variant,
                        "pid": args.pid,
                        "interval_s": args.interval,
                        "dwell_ms": dwell_str,
                        "duration_s": args.duration,
                        "elapsed_s": round(total_elapsed_s, 6),
                        "entropy_threshold": args.entropy_threshold,
                        "scans": total,
                        "catches": hits,
                        "marker_catches": marker_hits,
                        "entropy_catches": entropy_hits,
                        "catch_rate": round(catch_rate, 6),
                        "miss_rate": round(miss_rate, 6),
                        "scans_per_s": round(scans_per_s, 4),
                        "mean_scan_ms": round(mean_ms, 4),
                        "p50_scan_ms": round(p50, 4),
                        "p95_scan_ms": round(p95, 4),
                        "p99_scan_ms": round(p99, 4),
                        "max_entropy": round(run_max_entropy, 4),
                    }
                )
                sum_fh.flush()
            finally:
                sum_fh.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
