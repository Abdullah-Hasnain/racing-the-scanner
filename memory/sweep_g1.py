"""G1 sweep harness: catch rate vs scan interval and dwell time across V1-V4.

Runs the C memory payloads (v1..v4) against the live RAM scanner
(memory/scanner/scanner.py) across the #38 parameter grid and writes one row
per run/rep to results/g1_scan.csv (or results/g1_scan_smoke.csv with --smoke)
for analysis/make_graphs.py.

Linux only at runtime (targets /proc/<pid>/mem via scanner.py).

Usage:
  sudo python3 -m memory.sweep_g1 --smoke
  sudo python3 -m memory.sweep_g1
"""

from __future__ import annotations

import argparse
import csv
import os
import queue
import re
import signal
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from memory.scanner import scanner

VARIANTS_ALL = ("v1", "v2", "v3", "v4")
DWELL_VARIANTS = frozenset({"v2", "v3"})
PATTERNS = ("seq", "random", "stride")

DEFAULT_VARIANTS = ("v1", "v2", "v3", "v4")
# Each interval is 37 ms past a multiple of 100 ms. V2/V3 expose a page once per
# 100 ms, and a multiple of 50 ms keeps every scan on the same phase of that cycle
# (#63); stepping 37 ms per scan visits every phase, as #34's 37 ms interval does.
DEFAULT_INTERVALS = (0.037, 0.137, 0.537, 1.537, 5.037)
DEFAULT_DWELLS_MS = (1.0, 5.0, 10.0, 25.0)
DEFAULT_TOUCH_INTERVAL_MS = 100.0
DEFAULT_PATTERN = "seq"
DEFAULT_SEED = 1
DEFAULT_REPS = 3
DEFAULT_DURATION_S = 10.0
DEFAULT_LONG_DURATION_S = 20.0
MIN_ELAPSED_FRACTION = 0.9

SMOKE_INTERVALS = (0.037, 0.537)
SMOKE_DWELLS_MS = (5.0, 25.0)
SMOKE_REPS = 1
SMOKE_DURATION_S = 2.0
SMOKE_LONG_DURATION_S = 2.0

UFFD_SYSCTL_PATH = Path("/proc/sys/vm/unprivileged_userfaultfd")
SCANNER_PATH = Path(__file__).resolve().parent / "scanner" / "scanner.py"
DEFAULT_BIN_DIR = Path(__file__).resolve().parent / "bin"

_PID_RE = re.compile(r"\bpid=(\d+)\b")

G1_FIELDS = [
    "run_id",
    "rep",
    "variant",
    "dwell_ms",
    "interval_s",
    "pattern",
    "duration_s",
    "scans",
    "catches",
    "catch_rate",
    "miss_rate",
    "p50_scan_ms",
    "p95_scan_ms",
    "p99_scan_ms",
    "max_entropy",
]


class PayloadStartError(RuntimeError):
    """Raised when a payload binary fails to start or report its PID."""


class IncompleteCellError(RuntimeError):
    """Raised when a cell is interrupted or ends well short of its requested duration."""


@dataclass(frozen=True)
class SweepCell:
    """Single execution unit in the G1 parameter sweep."""

    variant: str
    interval_s: float
    dwell_ms: float | None
    pattern: str
    rep: int
    duration_s: float
    seed: int | None = None  # --seed for the random pattern, else the payload's default


def _norm_float_str(val: float | str | None) -> str:
    """Normalize numeric strings/floats so '10' and '10.0' compare equal."""
    if val is None:
        return ""
    text = str(val).strip()
    if text == "":
        return ""
    return f"{float(text):g}"


def _cell_key(
    variant: str,
    dwell_ms: float | str | None,
    interval_s: float | str,
    pattern: str,
    duration_s: float | str,
    rep: int | str,
) -> tuple[str, str, str, str, str, int]:
    return (
        variant.strip(),
        _norm_float_str(dwell_ms),
        _norm_float_str(interval_s),
        pattern.strip(),
        _norm_float_str(duration_s),
        int(rep),
    )


def build_sweep_grid(
    variants: Sequence[str],
    intervals: Sequence[float],
    dwells_ms: Sequence[float],
    *,
    pattern: str = DEFAULT_PATTERN,
    reps: int = DEFAULT_REPS,
    duration_s: float = DEFAULT_DURATION_S,
    long_duration_s: float = DEFAULT_LONG_DURATION_S,
    seed: int | None = None,
) -> list[SweepCell]:
    """Build the ordered list of G1 sweep cells without multiplying v1/v4 by dwell."""
    cells: list[SweepCell] = []
    for variant in variants:
        dwell_list: Sequence[float | None] = dwells_ms if variant in DWELL_VARIANTS else (None,)
        cell_pattern = pattern if variant in DWELL_VARIANTS else ""
        for interval_s in intervals:
            eff_duration = long_duration_s if interval_s >= 5.0 else duration_s
            for dwell_ms in dwell_list:
                for rep in range(1, reps + 1):
                    cells.append(
                        SweepCell(
                            variant=variant,
                            interval_s=float(interval_s),
                            dwell_ms=None if dwell_ms is None else float(dwell_ms),
                            pattern=cell_pattern,
                            rep=rep,
                            duration_s=float(eff_duration),
                            seed=seed + rep if seed is not None and cell_pattern == "random" else None,
                        )
                    )
    return cells


def _load_completed_keys(csv_path: Path) -> set[tuple[str, str, str, str, str, int]]:
    """Return normalized keys of rows already present in `csv_path`."""
    if not scanner._validate_csv_header(csv_path, G1_FIELDS):
        return set()
    completed: set[tuple[str, str, str, str, str, int]] = set()
    with csv_path.open("r", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            completed.add(
                _cell_key(
                    row["variant"],
                    row["dwell_ms"],
                    row["interval_s"],
                    row["pattern"],
                    row["duration_s"],
                    row["rep"],
                )
            )
    return completed


def _make_pin_fn(cpu: int | None) -> Callable[[], None] | None:
    """Return a preexec_fn pinning the child to `cpu`, or None if disabled/unsupported."""
    if cpu is None or not hasattr(os, "sched_setaffinity"):
        return None

    def _pin() -> None:
        os.sched_setaffinity(0, {cpu})

    return _pin


def _warn_if_unprivileged_uffd_disabled(
    variants: Sequence[str],
    sysctl_path: Path = UFFD_SYSCTL_PATH,
) -> None:
    """Warn non-root callers when vm.unprivileged_userfaultfd=0 for V3."""
    if "v3" not in variants or not sysctl_path.exists():
        return
    try:
        cur = sysctl_path.read_text(encoding="utf-8").strip()
    except OSError:
        return
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if cur == "0" and not is_root:
        print(
            f"[sweep_g1] warning: {sysctl_path}=0 and not running as root; "
            "v3 may fall back to UFFD_USER_MODE_ONLY (run as root for CAP_SYS_PTRACE)",
            file=sys.stderr,
        )


def _read_first_line(proc: subprocess.Popen[str], timeout_s: float) -> str | None:
    """Read the first stdout line from `proc` without blocking past `timeout_s`."""
    if proc.stdout is None:
        return None
    line_q: queue.Queue[str | None] = queue.Queue(maxsize=1)

    def _reader() -> None:
        try:
            line = proc.stdout.readline()  # type: ignore[union-attr]
            line_q.put(line)
        except (OSError, ValueError):  # ValueError: the pipe was closed under us
            line_q.put(None)

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    try:
        return line_q.get(timeout=timeout_s)
    except queue.Empty:
        return None


def _stop_payload(proc: subprocess.Popen[str]) -> None:
    """Terminate a payload subprocess cleanly, escalating to SIGKILL if needed."""
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2.0)
    finally:
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def _start_payload(
    bin_path: Path,
    cell: SweepCell,
    *,
    touch_interval_ms: float,
    pin_fn: Callable[[], None] | None,
    startup_timeout_s: float = 5.0,
) -> tuple[subprocess.Popen[str], int]:
    """Start `bin_path` for `cell` and wait for its startup PID banner."""
    cmd = [str(bin_path)]
    if cell.variant in DWELL_VARIANTS:
        assert cell.dwell_ms is not None
        cmd.extend(
            [
                "--dwell-ms",
                f"{cell.dwell_ms:g}",
                "--interval-ms",
                f"{touch_interval_ms:g}",
                "--pattern",
                cell.pattern,
            ]
        )
    if cell.seed is not None:
        cmd.extend(["--seed", str(cell.seed)])

    popen_kwargs: dict[str, object] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    if pin_fn is not None:
        popen_kwargs["preexec_fn"] = pin_fn

    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)  # type: ignore[call-overload]
    except OSError as exc:
        raise PayloadStartError(f"failed to launch {bin_path}: {exc}") from exc

    line = _read_first_line(proc, startup_timeout_s)
    if not line:
        rc = proc.poll()
        stderr_out = ""
        if rc is not None and proc.stderr is not None:
            try:
                stderr_out = proc.stderr.read().strip()
            except OSError:
                stderr_out = ""
        _stop_payload(proc)
        detail = stderr_out or (f"exited with code {rc}" if rc is not None else "startup timed out")
        raise PayloadStartError(f"{cell.variant} failed to initialize: {detail}")

    m = _PID_RE.search(line)
    pid = int(m.group(1)) if m else proc.pid
    return proc, pid


def _make_run_id(cell: SweepCell) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dwell_tag = "na" if cell.dwell_ms is None else f"{cell.dwell_ms:g}ms"
    return f"g1-{cell.variant}-{dwell_tag}-{cell.interval_s:g}s-r{cell.rep}-{ts}"


def _build_g1_row(
    cell: SweepCell,
    summary_row: dict[str, str],
    *,
    with_entropy: bool,
) -> dict[str, object]:
    return {
        "run_id": summary_row["run_id"],
        "rep": cell.rep,
        "variant": cell.variant,
        "dwell_ms": "" if cell.dwell_ms is None else f"{cell.dwell_ms:g}",
        "interval_s": f"{cell.interval_s:g}",
        "pattern": cell.pattern,
        "duration_s": summary_row["duration_s"],
        "scans": summary_row["scans"],
        "catches": summary_row["catches"],
        "catch_rate": summary_row["catch_rate"],
        "miss_rate": summary_row["miss_rate"],
        "p50_scan_ms": summary_row["p50_scan_ms"],
        "p95_scan_ms": summary_row["p95_scan_ms"],
        "p99_scan_ms": summary_row["p99_scan_ms"],
        "max_entropy": summary_row["max_entropy"] if with_entropy else "",
    }


def run_cell(
    cell: SweepCell,
    *,
    bin_dir: Path,
    out_csv: Path,
    touch_interval_ms: float,
    with_entropy: bool,
    pin_fn: Callable[[], None] | None,
    should_stop: Callable[[], bool] | None = None,
) -> dict[str, object]:
    """Run one (variant, interval, dwell, rep) cell and append its row to `out_csv`."""
    bin_path = bin_dir / cell.variant
    if not bin_path.exists():
        raise PayloadStartError(f"missing payload binary: {bin_path} (run `make -C memory` first)")

    proc, pid = _start_payload(
        bin_path,
        cell,
        touch_interval_ms=touch_interval_ms,
        pin_fn=pin_fn,
    )
    run_id = _make_run_id(cell)

    try:
        with tempfile.TemporaryDirectory(prefix="rts_g1_") as tmp_dir:
            tmp_path = Path(tmp_dir)
            scans_csv = tmp_path / "scanner_scans.csv"
            summary_csv = tmp_path / "scanner_summary.csv"

            cmd = [
                sys.executable,
                str(SCANNER_PATH),
                "--pid",
                str(pid),
                "--interval",
                f"{cell.interval_s:g}",
                "--duration",
                f"{cell.duration_s:g}",
                "--variant",
                cell.variant,
                "--run-id",
                run_id,
                "--scans-csv",
                str(scans_csv),
                "--summary-csv",
                str(summary_csv),
            ]
            if cell.dwell_ms is not None:
                cmd.extend(["--dwell-ms", f"{cell.dwell_ms:g}"])
            if not with_entropy:
                cmd.append("--no-entropy")

            run_kwargs: dict[str, object] = {
                "check": False,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
            }
            if pin_fn is not None:
                run_kwargs["preexec_fn"] = pin_fn

            res = subprocess.run(cmd, **run_kwargs)  # type: ignore[call-overload]
            if should_stop is not None and should_stop():
                raise IncompleteCellError("interrupted while cell was in flight")
            if res.returncode != 0:
                err = (res.stderr or res.stdout or "").strip()
                raise RuntimeError(
                    f"scanner exited with code {res.returncode} for {cell.variant}: {err}"
                )
            if not summary_csv.exists():
                raise RuntimeError(f"scanner produced no summary CSV for {cell.variant}")

            with summary_csv.open("r", newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))
            if not rows:
                raise RuntimeError(f"scanner produced 0 summary rows for {cell.variant}")

            summary_row = rows[-1]
            elapsed_s = float(summary_row.get("elapsed_s", "0") or 0.0)
            min_elapsed = cell.duration_s * MIN_ELAPSED_FRACTION
            if elapsed_s < min_elapsed:
                raise IncompleteCellError(
                    f"{cell.variant} ended early: elapsed={elapsed_s:.2f}s < {min_elapsed:.2f}s"
                )

            g1_row = _build_g1_row(cell, summary_row, with_entropy=with_entropy)
    finally:
        _stop_payload(proc)

    out_fh, writer = scanner._open_csv_writer(out_csv, G1_FIELDS)
    try:
        writer.writerow(g1_row)
        out_fh.flush()
    finally:
        out_fh.close()

    return g1_row


def _default_cpu() -> int | None:
    if not hasattr(os, "sched_setaffinity"):
        return None
    if hasattr(os, "sched_getaffinity"):
        try:
            avail = sorted(os.sched_getaffinity(0))
            if 2 in avail:
                return 2
            if avail:
                return avail[-1]
        except OSError:
            pass
    return 2


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="G1 sweep: catch rate vs scan interval and dwell time")
    ap.add_argument(
        "--variants",
        nargs="+",
        choices=VARIANTS_ALL,
        default=list(DEFAULT_VARIANTS),
        help="payload variants to sweep (default: v1 v2 v3 v4)",
    )
    ap.add_argument(
        "--intervals",
        nargs="+",
        type=float,
        default=None,
        help="scan intervals in seconds (default: 0.037 0.137 0.537 1.537 5.037)",
    )
    ap.add_argument(
        "--dwell-ms",
        nargs="+",
        type=float,
        default=None,
        help="dwell times in ms for v2/v3 (default: 1 5 10 25)",
    )
    ap.add_argument(
        "--touch-interval-ms",
        type=float,
        default=DEFAULT_TOUCH_INTERVAL_MS,
        help="delay between page touches in v2/v3 in ms (default: 100.0)",
    )
    ap.add_argument(
        "--pattern",
        choices=PATTERNS,
        default=DEFAULT_PATTERN,
        help="access pattern for v2/v3 (default: seq)",
    )
    ap.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="base PRNG seed for --pattern random; rep N runs with seed + N (default: 1)",
    )
    ap.add_argument(
        "--reps",
        type=int,
        default=None,
        help="repetitions per cell (default: 3)",
    )
    ap.add_argument(
        "--duration",
        type=float,
        default=None,
        help="cell duration in seconds for intervals < 5s (default: 10.0)",
    )
    ap.add_argument(
        "--long-duration",
        type=float,
        default=None,
        help="cell duration in seconds for intervals >= 5s (default: 20.0)",
    )
    ap.add_argument(
        "--smoke",
        action="store_true",
        help="fast verification grid -> g1_scan_smoke.csv (0.037/0.537s, 5/25ms, 1 rep, 2s)",
    )
    ap.add_argument(
        "--cpu",
        type=int,
        default=_default_cpu(),
        help="CPU core to pin payload and scanner (-1 to disable; default: 2 on Linux)",
    )
    ap.add_argument(
        "--no-pin",
        action="store_true",
        help="disable CPU core pinning for payload and scanner",
    )
    ap.add_argument(
        "--with-entropy",
        action="store_true",
        help="enable per-page Shannon-entropy pass in scanner.py (omits --no-entropy)",
    )
    ap.add_argument(
        "--resume",
        action="store_true",
        help="skip (variant, dwell_ms, interval_s, pattern, duration_s, rep) cells already in CSV",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="abort instead of skipping if v4 cannot start (e.g. secretmem disabled)",
    )
    ap.add_argument(
        "--bin-dir",
        type=Path,
        default=DEFAULT_BIN_DIR,
        help="directory containing compiled v1..v4 binaries",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=scanner._default_out_dir(),
        help="directory for g1_scan.csv (default: $RTS_RESULTS_DIR or <repo>/results)",
    )
    ap.add_argument(
        "--out-csv",
        type=Path,
        default=None,
        help="override output CSV path (default: <out-dir>/g1_scan.csv or g1_scan_smoke.csv)",
    )

    args = ap.parse_args(argv)

    if args.intervals is None:
        args.intervals = list(SMOKE_INTERVALS if args.smoke else DEFAULT_INTERVALS)
    if args.dwell_ms is None:
        args.dwell_ms = list(SMOKE_DWELLS_MS if args.smoke else DEFAULT_DWELLS_MS)
    if args.reps is None:
        args.reps = SMOKE_REPS if args.smoke else DEFAULT_REPS
    if args.duration is None:
        args.duration = SMOKE_DURATION_S if args.smoke else DEFAULT_DURATION_S
    if args.long_duration is None:
        args.long_duration = SMOKE_LONG_DURATION_S if args.smoke else DEFAULT_LONG_DURATION_S

    if any(x <= 0.0 for x in args.intervals):
        ap.error("--intervals values must all be positive")
    if any(x < 0.1 for x in args.dwell_ms):
        ap.error("--dwell-ms values must all be >= 0.1")
    if args.touch_interval_ms < 0.0:
        ap.error("--touch-interval-ms must be non-negative")
    if args.reps < 1:
        ap.error("--reps must be >= 1")
    if args.duration <= 0.0:
        ap.error("--duration must be positive")
    if args.long_duration <= 0.0:
        ap.error("--long-duration must be positive")
    if args.no_pin or args.cpu == -1:
        args.cpu = None
    elif args.cpu is not None and args.cpu < -1:
        ap.error("--cpu must be >= 0 (or -1 to disable)")

    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    default_name = "g1_scan_smoke.csv" if args.smoke else "g1_scan.csv"
    out_csv = args.out_csv or (args.out_dir / default_name)

    if args.resume and args.touch_interval_ms != DEFAULT_TOUCH_INTERVAL_MS:
        print(
            "[sweep_g1] warning: --touch-interval-ms is not stored in CSV and is not checked by --resume",
            file=sys.stderr,
        )

    try:
        completed = _load_completed_keys(out_csv) if args.resume else set()
        if not args.resume:
            scanner._validate_csv_header(out_csv, G1_FIELDS)
    except ValueError as exc:
        print(f"[sweep_g1] {exc}", file=sys.stderr)
        return 2

    cells = build_sweep_grid(
        args.variants,
        args.intervals,
        args.dwell_ms,
        pattern=args.pattern,
        reps=args.reps,
        duration_s=args.duration,
        long_duration_s=args.long_duration,
        seed=args.seed,
    )

    pin_fn = _make_pin_fn(args.cpu)
    stop = False

    def _on_signal(_signum, _frame) -> None:
        nonlocal stop
        stop = True

    prev_sigint = signal.getsignal(signal.SIGINT)
    prev_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    skipped_variants: set[str] = set()
    ran = 0
    skipped = 0
    total = len(cells)

    try:
        _warn_if_unprivileged_uffd_disabled(args.variants)
        for idx, cell in enumerate(cells, start=1):
            if stop:
                print("[sweep_g1] interrupted; stopping after completed cell", flush=True)
                break
            if cell.variant in skipped_variants:
                skipped += 1
                continue
            if (
                args.resume
                and _cell_key(
                    cell.variant,
                    cell.dwell_ms,
                    cell.interval_s,
                    cell.pattern,
                    cell.duration_s,
                    cell.rep,
                )
                in completed
            ):
                skipped += 1
                continue

            dwell_label = "n/a" if cell.dwell_ms is None else f"{cell.dwell_ms:g}ms"
            print(
                f"[sweep_g1] ({idx}/{total}) {cell.variant} dwell={dwell_label} "
                f"interval={cell.interval_s:g}s dur={cell.duration_s:g}s rep={cell.rep}",
                flush=True,
            )

            try:
                row = run_cell(
                    cell,
                    bin_dir=args.bin_dir,
                    out_csv=out_csv,
                    touch_interval_ms=args.touch_interval_ms,
                    with_entropy=args.with_entropy,
                    pin_fn=pin_fn,
                    should_stop=lambda: stop,
                )
            except PayloadStartError as exc:
                if cell.variant == "v4" and not args.strict:
                    print(
                        f"[sweep_g1] warning: skipping remaining v4 cells ({exc})",
                        file=sys.stderr,
                        flush=True,
                    )
                    skipped_variants.add("v4")
                    skipped += 1
                    continue
                print(f"[sweep_g1] error: {exc}", file=sys.stderr)
                return 1
            except IncompleteCellError as exc:
                if stop:
                    print(
                        "[sweep_g1] interrupted; discarded incomplete in-flight cell",
                        flush=True,
                    )
                    return 130
                print(f"[sweep_g1] error: {exc}", file=sys.stderr)
                return 1

            ran += 1
            print(
                f"  -> scans={row['scans']} catches={row['catches']} "
                f"catch_rate={row['catch_rate']} p50={row['p50_scan_ms']}ms",
                flush=True,
            )
    finally:
        signal.signal(signal.SIGINT, prev_sigint)
        signal.signal(signal.SIGTERM, prev_sigterm)

    if stop:
        return 130

    print(f"[sweep_g1] done: ran={ran}, skipped={skipped}, csv={out_csv}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
