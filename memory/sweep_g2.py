"""G2 sweep harness: hiding-vs-slowdown Pareto + page-fault counts across V1-V4.

Runs two phases per (variant, dwell, pattern, rep) cell against the C memory
payloads (v1..v4) and live RAM scanner (memory/scanner/scanner.py), writing
one row per cell to results/g2_pareto.csv (or results/g2_pareto_smoke.csv with
--smoke) for analysis/make_graphs.py.

  Phase A (cost & faults): tight loop (--interval-ms 0 --duration 5), no scanner.
      Records accesses, accesses_per_s, faults, faults_per_s, and /proc/<pid>/stat
      minflt delta, computing slowdown_vs_v1 = v1_accesses_per_s / accesses_per_s.
  Phase B (evasion): paced loop (--interval-ms 100) scanned every 0.037 s.
      Records evasion_rate = 1 - catch_rate, catch_rate, and p95_scan_ms.

Linux only at runtime (targets /proc/<pid>/mem and /proc/<pid>/stat).

Usage:
  sudo python3 -m memory.sweep_g2 --smoke
  sudo python3 -m memory.sweep_g2
"""

from __future__ import annotations

import argparse
import csv
import os
import queue
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from memory.scanner import scanner

VARIANTS_ALL = ("v1", "v2", "v3", "v4")
DWELL_VARIANTS = frozenset({"v2", "v3"})
PATTERNS = ("seq", "random", "stride")

DEFAULT_VARIANTS = ("v1", "v2", "v3", "v4")
DEFAULT_DWELLS_MS = (1.0, 5.0, 10.0, 25.0)
DEFAULT_SCAN_INTERVAL_S = 0.037
DEFAULT_TOUCH_INTERVAL_MS = 100.0
DEFAULT_PATTERN = "seq"
DEFAULT_REPS = 3
DEFAULT_DURATION_S = 5.0
MIN_ELAPSED_FRACTION = 0.9
COST_TIMEOUT_MARGIN_S = 15.0

SMOKE_DWELLS_MS = (5.0, 25.0)
SMOKE_REPS = 1
SMOKE_DURATION_S = 2.0

UFFD_SYSCTL_PATH = Path("/proc/sys/vm/unprivileged_userfaultfd")
SCANNER_PATH = Path(__file__).resolve().parent / "scanner" / "scanner.py"
DEFAULT_BIN_DIR = Path(__file__).resolve().parent / "bin"

_PID_RE = re.compile(r"\bpid=(\d+)\b")
_ACCESSES_RE = re.compile(r"\baccesses=(\d+)\b")
_FAULTS_RE = re.compile(r"\bfaults=(\d+)\b")
_ELAPSED_RE = re.compile(r"\belapsed_s=([0-9]+(?:\.[0-9]+)?)\b")
_REAL_POPEN = subprocess.Popen

G2_FIELDS = [
    "run_id",
    "rep",
    "variant",
    "dwell_ms",
    "pattern",
    "duration_s",
    "accesses",
    "accesses_per_s",
    "slowdown_vs_v1",
    "faults",
    "faults_per_s",
    "minflt",
    "evasion_rate",
    "catch_rate",
    "p95_scan_ms",
]


class PayloadStartError(RuntimeError):
    """Raised when a payload binary fails to start or report its PID."""


class IncompleteCellError(RuntimeError):
    """Raised when a cell is interrupted, times out, or ends short of its duration."""


class MissingBaselineError(RuntimeError):
    """Raised when non-v1 variants are run without an available v1 baseline."""


@dataclass(frozen=True)
class SweepCell:
    """Single execution unit in the G2 Pareto sweep."""

    variant: str
    dwell_ms: float | None
    pattern: str
    rep: int
    duration_s: float


@dataclass(frozen=True)
class CostResult:
    """Throughput and page-fault telemetry from the tight-loop cost pass."""

    accesses: int
    elapsed_s: float
    accesses_per_s: float
    faults: int
    faults_per_s: float
    minflt: int


@dataclass(frozen=True)
class EvasionResult:
    """Scanner evasion telemetry from the 37 ms scanner pass."""

    catch_rate: float
    evasion_rate: float
    p95_scan_ms: float
    elapsed_s: float
    scans: int
    catches: int


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
    pattern: str,
    duration_s: float | str,
    rep: int | str,
) -> tuple[str, str, str, str, int]:
    return (
        variant.strip(),
        _norm_float_str(dwell_ms),
        pattern.strip(),
        _norm_float_str(duration_s),
        int(rep),
    )


def build_sweep_grid(
    variants: Sequence[str],
    dwells_ms: Sequence[float],
    *,
    pattern: str = DEFAULT_PATTERN,
    reps: int = DEFAULT_REPS,
    duration_s: float = DEFAULT_DURATION_S,
) -> list[SweepCell]:
    """Build G2 sweep cells with v1 ordered first and v1/v4 not multiplied by dwell."""
    ordered: list[str] = []
    for variant in variants:
        if variant not in ordered:
            ordered.append(variant)
    if "v1" in ordered:
        ordered = ["v1", *(v for v in ordered if v != "v1")]

    cells: list[SweepCell] = []
    for variant in ordered:
        dwell_list: Sequence[float | None] = dwells_ms if variant in DWELL_VARIANTS else (None,)
        for dwell_ms in dwell_list:
            for rep in range(1, reps + 1):
                cells.append(
                    SweepCell(
                        variant=variant,
                        dwell_ms=None if dwell_ms is None else float(dwell_ms),
                        pattern=pattern,
                        rep=rep,
                        duration_s=float(duration_s),
                    )
                )
    return cells


def _load_existing_state(
    csv_path: Path,
    *,
    pattern: str,
    duration_s: float,
) -> tuple[set[tuple[str, str, str, str, int]], dict[int, float]]:
    """Load completed cell keys and matching v1 baseline rates from `csv_path`."""
    if not scanner._validate_csv_header(csv_path, G2_FIELDS):
        return set(), {}

    completed: set[tuple[str, str, str, str, int]] = set()
    v1_rates_by_rep: dict[int, float] = {}
    want_pattern = pattern.strip()
    want_duration = _norm_float_str(duration_s)

    with csv_path.open("r", newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            rep = int(row["rep"])
            variant = row["variant"].strip()
            row_pattern = row["pattern"].strip()
            row_duration = _norm_float_str(row["duration_s"])
            completed.add(
                _cell_key(
                    variant,
                    row["dwell_ms"],
                    row_pattern,
                    row_duration,
                    rep,
                )
            )
            if variant == "v1" and row_pattern == want_pattern and row_duration == want_duration:
                try:
                    rate = float(row["accesses_per_s"])
                except (TypeError, ValueError):
                    continue
                if rate > 0.0:
                    v1_rates_by_rep[rep] = rate

    return completed, v1_rates_by_rep


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
            f"[sweep_g2] warning: {sysctl_path}=0 and not running as root; "
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
        except Exception:
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


def _read_remaining_stdout_interruptible(
    proc: subprocess.Popen[str],
    *,
    timeout_s: float,
    should_stop: Callable[[], bool] | None = None,
) -> str:
    """Read remaining stdout from `proc` with bounded polling so stop signals interrupt it."""
    if proc.stdout is None:
        return ""

    out_q: queue.Queue[tuple[str, BaseException | None]] = queue.Queue(maxsize=1)

    def _reader() -> None:
        try:
            data = proc.stdout.read()  # type: ignore[union-attr]
            out_q.put((data, None))
        except BaseException as exc:  # noqa: BLE001
            out_q.put(("", exc))

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    deadline = time.monotonic() + timeout_s

    while True:
        if should_stop is not None and should_stop():
            _stop_payload(proc)
            raise IncompleteCellError("interrupted while cost pass was in flight")
        rem = deadline - time.monotonic()
        if rem <= 0.0:
            _stop_payload(proc)
            raise IncompleteCellError(f"cost pass timed out after {timeout_s:.1f}s")
        try:
            data, exc = out_q.get(timeout=min(0.1, rem))
        except queue.Empty:
            continue
        if exc is not None:
            raise exc
        return data


def _parse_proc_stat_minflt(stat_text: str) -> int:
    """Parse field 10 (minflt) from `/proc/<pid>/stat` text."""
    if ")" not in stat_text:
        raise ValueError("malformed /proc/<pid>/stat line: missing ')'")
    _, rest = stat_text.rsplit(")", 1)
    fields = rest.split()
    if len(fields) <= 7:
        raise ValueError("truncated /proc/<pid>/stat line")
    return int(fields[7])


def _read_proc_stat_minflt(pid: int) -> int | None:
    """Read minor page-fault count from `/proc/<pid>/stat`, or None if unavailable."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        return _parse_proc_stat_minflt(text)
    except (OSError, ValueError):
        return None


def _parse_done_line(stdout_text: str, variant: str) -> tuple[int, int, float]:
    """Extract (accesses, faults, elapsed_s) from a payload's `done:` summary line."""
    for line in stdout_text.splitlines():
        if "done:" not in line:
            continue
        m_acc = _ACCESSES_RE.search(line)
        m_flt = _FAULTS_RE.search(line)
        m_sec = _ELAPSED_RE.search(line)
        if m_acc and m_flt and m_sec:
            return int(m_acc.group(1)), int(m_flt.group(1)), float(m_sec.group(1))
    raise RuntimeError(f"{variant} produced no valid `done:` summary line")


def _launch_payload(
    bin_path: Path,
    cell: SweepCell,
    *,
    interval_ms: float,
    duration_s: float,
    pin_fn: Callable[[], None] | None,
    startup_timeout_s: float = 5.0,
) -> tuple[subprocess.Popen[str], int]:
    """Start `bin_path` for `cell` and wait for its startup PID banner."""
    cmd = [
        str(bin_path),
        "--interval-ms",
        f"{interval_ms:g}",
        "--pattern",
        cell.pattern,
        "--duration",
        f"{duration_s:g}",
    ]
    if cell.variant in DWELL_VARIANTS:
        assert cell.dwell_ms is not None
        cmd.extend(["--dwell-ms", f"{cell.dwell_ms:g}"])

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


def _reap_with_optional_wait4(
    proc: subprocess.Popen[str],
    *,
    need_minflt: bool,
) -> tuple[int, int | None]:
    """Reap `proc` and return (returncode, ru_minflt fallback if wait4 was used)."""
    if need_minflt and isinstance(proc, _REAL_POPEN) and hasattr(os, "wait4"):
        try:
            _, status, ru = os.wait4(proc.pid, 0)
            rc = os.waitstatus_to_exitcode(status)
            proc.returncode = rc
            return rc, int(ru.ru_minflt)
        except ChildProcessError:
            pass
    return proc.wait(timeout=5.0), None


def _run_cost_pass(
    bin_path: Path,
    cell: SweepCell,
    *,
    pin_fn: Callable[[], None] | None,
    should_stop: Callable[[], bool] | None = None,
    startup_timeout_s: float = 5.0,
    proc_stat_reader: Callable[[int], int | None] | None = None,
) -> CostResult:
    """Run Phase A (tight loop, no scanner) and collect throughput, faults, and minflt."""
    stat_reader = proc_stat_reader or _read_proc_stat_minflt
    proc, pid = _launch_payload(
        bin_path,
        cell,
        interval_ms=0.0,
        duration_s=cell.duration_s,
        pin_fn=pin_fn,
        startup_timeout_s=startup_timeout_s,
    )

    try:
        minflt_start = stat_reader(pid)
        rest_out = _read_remaining_stdout_interruptible(
            proc,
            timeout_s=cell.duration_s + COST_TIMEOUT_MARGIN_S,
            should_stop=should_stop,
        )
        # Read /proc/<pid>/stat while child is still an un-reaped zombie so all
        # thread-group minor faults remain visible before wait() removes the entry.
        minflt_end = stat_reader(pid)
        rc, wait4_minflt = _reap_with_optional_wait4(proc, need_minflt=(minflt_end is None))
        if minflt_end is None and wait4_minflt is not None:
            minflt_end = wait4_minflt

        if should_stop is not None and should_stop():
            raise IncompleteCellError("interrupted while cost pass was in flight")
        if rc != 0:
            err = ""
            if proc.stderr is not None:
                try:
                    err = proc.stderr.read().strip()
                except OSError:
                    err = ""
            raise RuntimeError(f"{cell.variant} cost pass exited with code {rc}: {err}")

        accesses, faults, elapsed_s = _parse_done_line(rest_out, cell.variant)
    finally:
        _stop_payload(proc)

    min_elapsed = cell.duration_s * MIN_ELAPSED_FRACTION
    if elapsed_s < min_elapsed:
        raise IncompleteCellError(
            f"{cell.variant} cost pass ended early: elapsed={elapsed_s:.2f}s < {min_elapsed:.2f}s"
        )
    if accesses <= 0:
        raise RuntimeError(f"{cell.variant} cost pass recorded 0 accesses")

    minflt = 0 if minflt_end is None else max(0, minflt_end - (minflt_start or 0))
    return CostResult(
        accesses=accesses,
        elapsed_s=elapsed_s,
        accesses_per_s=accesses / elapsed_s,
        faults=faults,
        faults_per_s=faults / elapsed_s,
        minflt=minflt,
    )


def _run_evasion_pass(
    bin_path: Path,
    cell: SweepCell,
    run_id: str,
    *,
    scan_interval_s: float,
    touch_interval_ms: float,
    with_entropy: bool,
    pin_fn: Callable[[], None] | None,
    should_stop: Callable[[], bool] | None = None,
    startup_timeout_s: float = 5.0,
) -> EvasionResult:
    """Run Phase B (paced payload + 37 ms scanner) and collect evasion rate and scan p95."""
    proc, pid = _launch_payload(
        bin_path,
        cell,
        interval_ms=touch_interval_ms,
        duration_s=0.0,
        pin_fn=pin_fn,
        startup_timeout_s=startup_timeout_s,
    )

    try:
        with tempfile.TemporaryDirectory(prefix="rts_g2_") as tmp_dir:
            tmp_path = Path(tmp_dir)
            scans_csv = tmp_path / "scanner_scans.csv"
            summary_csv = tmp_path / "scanner_summary.csv"

            cmd = [
                sys.executable,
                str(SCANNER_PATH),
                "--pid",
                str(pid),
                "--interval",
                f"{scan_interval_s:g}",
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
                raise IncompleteCellError("interrupted while evasion pass was in flight")
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
                    f"{cell.variant} evasion pass ended early: elapsed={elapsed_s:.2f}s < {min_elapsed:.2f}s"
                )

            catch_rate = float(summary_row["catch_rate"])
            evasion_rate = max(0.0, min(1.0, 1.0 - catch_rate))
            return EvasionResult(
                catch_rate=catch_rate,
                evasion_rate=evasion_rate,
                p95_scan_ms=float(summary_row["p95_scan_ms"]),
                elapsed_s=elapsed_s,
                scans=int(summary_row["scans"]),
                catches=int(summary_row["catches"]),
            )
    finally:
        _stop_payload(proc)


def _make_run_id(cell: SweepCell) -> str:
    ts = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dwell_tag = "na" if cell.dwell_ms is None else f"{cell.dwell_ms:g}ms"
    return f"g2-{cell.variant}-{dwell_tag}-r{cell.rep}-{ts}"


def _build_g2_row(
    cell: SweepCell,
    run_id: str,
    cost: CostResult,
    evasion: EvasionResult,
    slowdown_vs_v1: float,
) -> dict[str, object]:
    return {
        "run_id": run_id,
        "rep": cell.rep,
        "variant": cell.variant,
        "dwell_ms": "" if cell.dwell_ms is None else f"{cell.dwell_ms:g}",
        "pattern": cell.pattern,
        "duration_s": f"{cell.duration_s:g}",
        "accesses": cost.accesses,
        "accesses_per_s": round(cost.accesses_per_s, 3),
        "slowdown_vs_v1": round(slowdown_vs_v1, 6),
        "faults": cost.faults,
        "faults_per_s": round(cost.faults_per_s, 3),
        "minflt": cost.minflt,
        "evasion_rate": round(evasion.evasion_rate, 6),
        "catch_rate": round(evasion.catch_rate, 6),
        "p95_scan_ms": round(evasion.p95_scan_ms, 4),
    }


def run_cell(
    cell: SweepCell,
    *,
    bin_dir: Path,
    out_csv: Path,
    scan_interval_s: float,
    touch_interval_ms: float,
    with_entropy: bool,
    pin_fn: Callable[[], None] | None,
    v1_baseline_rate: float | None = None,
    should_stop: Callable[[], bool] | None = None,
    proc_stat_reader: Callable[[int], int | None] | None = None,
) -> dict[str, object]:
    """Run Phase A and Phase B for one G2 cell and append its row to `out_csv`."""
    bin_path = bin_dir / cell.variant
    if not bin_path.exists():
        raise PayloadStartError(f"missing payload binary: {bin_path} (run `make -C memory` first)")

    if cell.variant != "v1" and (v1_baseline_rate is None or v1_baseline_rate <= 0.0):
        raise MissingBaselineError(
            f"cannot compute slowdown_vs_v1 for {cell.variant} rep={cell.rep}: no v1 baseline available"
        )

    cost = _run_cost_pass(
        bin_path,
        cell,
        pin_fn=pin_fn,
        should_stop=should_stop,
        proc_stat_reader=proc_stat_reader,
    )
    if should_stop is not None and should_stop():
        raise IncompleteCellError("interrupted between cost and evasion passes")

    run_id = _make_run_id(cell)
    evasion = _run_evasion_pass(
        bin_path,
        cell,
        run_id,
        scan_interval_s=scan_interval_s,
        touch_interval_ms=touch_interval_ms,
        with_entropy=with_entropy,
        pin_fn=pin_fn,
        should_stop=should_stop,
    )

    slowdown = 1.0 if cell.variant == "v1" else float(v1_baseline_rate) / cost.accesses_per_s
    g2_row = _build_g2_row(cell, run_id, cost, evasion, slowdown)

    out_fh, writer = scanner._open_csv_writer(out_csv, G2_FIELDS)
    try:
        writer.writerow(g2_row)
        out_fh.flush()
    finally:
        out_fh.close()

    return g2_row


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
    ap = argparse.ArgumentParser(
        description="G2 sweep: hiding-vs-slowdown Pareto + page-fault counts"
    )
    ap.add_argument(
        "--variants",
        nargs="+",
        choices=VARIANTS_ALL,
        default=list(DEFAULT_VARIANTS),
        help="payload variants to sweep (default: v1 v2 v3 v4)",
    )
    ap.add_argument(
        "--dwell-ms",
        nargs="+",
        type=float,
        default=None,
        help="dwell times in ms for v2/v3 (default: 1 5 10 25)",
    )
    ap.add_argument(
        "--scan-interval",
        type=float,
        default=DEFAULT_SCAN_INTERVAL_S,
        help="scanner interval in seconds for evasion pass (default: 0.037)",
    )
    ap.add_argument(
        "--touch-interval-ms",
        type=float,
        default=DEFAULT_TOUCH_INTERVAL_MS,
        help="delay between page touches in evasion pass in ms (default: 100.0)",
    )
    ap.add_argument(
        "--pattern",
        choices=PATTERNS,
        default=DEFAULT_PATTERN,
        help="access pattern for all variants (default: seq)",
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
        help="pass duration in seconds (default: 5.0)",
    )
    ap.add_argument(
        "--smoke",
        action="store_true",
        help="fast verification grid -> g2_pareto_smoke.csv (5/25ms, 1 rep, 2s)",
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
        help="skip (variant, dwell_ms, pattern, duration_s, rep) cells already in CSV",
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
        help="directory for g2_pareto.csv (default: $RTS_RESULTS_DIR or <repo>/results)",
    )
    ap.add_argument(
        "--out-csv",
        type=Path,
        default=None,
        help="override output CSV path (default: <out-dir>/g2_pareto.csv or g2_pareto_smoke.csv)",
    )

    args = ap.parse_args(argv)

    if args.dwell_ms is None:
        args.dwell_ms = list(SMOKE_DWELLS_MS if args.smoke else DEFAULT_DWELLS_MS)
    if args.reps is None:
        args.reps = SMOKE_REPS if args.smoke else DEFAULT_REPS
    if args.duration is None:
        args.duration = SMOKE_DURATION_S if args.smoke else DEFAULT_DURATION_S

    if args.scan_interval <= 0.0:
        ap.error("--scan-interval must be positive")
    if any(x < 0.1 for x in args.dwell_ms):
        ap.error("--dwell-ms values must all be >= 0.1")
    if args.touch_interval_ms < 0.0:
        ap.error("--touch-interval-ms must be non-negative")
    if args.reps < 1:
        ap.error("--reps must be >= 1")
    if args.duration <= 0.0:
        ap.error("--duration must be positive")
    if args.no_pin or args.cpu == -1:
        args.cpu = None
    elif args.cpu is not None and args.cpu < -1:
        ap.error("--cpu must be >= 0 (or -1 to disable)")

    return args


def _lookup_v1_baseline(v1_rates_by_rep: dict[int, float], rep: int) -> float | None:
    if rep in v1_rates_by_rep:
        return v1_rates_by_rep[rep]
    if v1_rates_by_rep:
        return float(statistics.median(v1_rates_by_rep.values()))
    return None


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    default_name = "g2_pareto_smoke.csv" if args.smoke else "g2_pareto.csv"
    out_csv = args.out_csv or (args.out_dir / default_name)

    if args.resume:
        if args.scan_interval != DEFAULT_SCAN_INTERVAL_S:
            print(
                "[sweep_g2] warning: --scan-interval is not stored in CSV and is not checked by --resume",
                file=sys.stderr,
            )
        if args.touch_interval_ms != DEFAULT_TOUCH_INTERVAL_MS:
            print(
                "[sweep_g2] warning: --touch-interval-ms is not stored in CSV and is not checked by --resume",
                file=sys.stderr,
            )

    try:
        completed, v1_rates_by_rep = _load_existing_state(
            out_csv,
            pattern=args.pattern,
            duration_s=args.duration,
        )
    except ValueError as exc:
        print(f"[sweep_g2] {exc}", file=sys.stderr)
        return 2

    cells = build_sweep_grid(
        args.variants,
        args.dwell_ms,
        pattern=args.pattern,
        reps=args.reps,
        duration_s=args.duration,
    )

    pending_cells = [
        c
        for c in cells
        if not (
            args.resume
            and _cell_key(c.variant, c.dwell_ms, c.pattern, c.duration_s, c.rep) in completed
        )
    ]
    needs_v1 = any(c.variant != "v1" for c in pending_cells)
    has_pending_v1 = any(c.variant == "v1" for c in pending_cells)
    if needs_v1 and not has_pending_v1 and not v1_rates_by_rep:
        print(
            f"[sweep_g2] error: cannot run {sorted({c.variant for c in pending_cells if c.variant != 'v1'})} "
            f"without a v1 baseline (include v1 or run against an existing CSV with v1 rows for "
            f"pattern={args.pattern}, duration_s={args.duration:g})",
            file=sys.stderr,
        )
        return 2

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
                print("[sweep_g2] interrupted; stopping after completed cell", flush=True)
                break
            if cell.variant in skipped_variants:
                skipped += 1
                continue
            if (
                args.resume
                and _cell_key(
                    cell.variant,
                    cell.dwell_ms,
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
                f"[sweep_g2] ({idx}/{total}) {cell.variant} dwell={dwell_label} "
                f"pattern={cell.pattern} dur={cell.duration_s:g}s rep={cell.rep}",
                flush=True,
            )

            v1_rate = (
                None if cell.variant == "v1" else _lookup_v1_baseline(v1_rates_by_rep, cell.rep)
            )
            try:
                row = run_cell(
                    cell,
                    bin_dir=args.bin_dir,
                    out_csv=out_csv,
                    scan_interval_s=args.scan_interval,
                    touch_interval_ms=args.touch_interval_ms,
                    with_entropy=args.with_entropy,
                    pin_fn=pin_fn,
                    v1_baseline_rate=v1_rate,
                    should_stop=lambda: stop,
                )
            except PayloadStartError as exc:
                if cell.variant == "v4" and not args.strict:
                    print(
                        f"[sweep_g2] warning: skipping remaining v4 cells ({exc})",
                        file=sys.stderr,
                        flush=True,
                    )
                    skipped_variants.add("v4")
                    skipped += 1
                    continue
                print(f"[sweep_g2] error: {exc}", file=sys.stderr)
                return 1
            except IncompleteCellError as exc:
                if stop:
                    print(
                        "[sweep_g2] interrupted; discarded incomplete in-flight cell",
                        flush=True,
                    )
                    return 130
                print(f"[sweep_g2] error: {exc}", file=sys.stderr)
                return 1
            except MissingBaselineError as exc:
                print(f"[sweep_g2] error: {exc}", file=sys.stderr)
                return 2

            if cell.variant == "v1":
                v1_rates_by_rep[cell.rep] = float(row["accesses_per_s"])

            ran += 1
            print(
                f"  -> slowdown={row['slowdown_vs_v1']}x evasion={row['evasion_rate']} "
                f"faults={row['faults']} minflt={row['minflt']} p95={row['p95_scan_ms']}ms",
                flush=True,
            )
    finally:
        signal.signal(signal.SIGINT, prev_sigint)
        signal.signal(signal.SIGTERM, prev_sigterm)

    if stop:
        return 130

    print(f"[sweep_g2] done: ran={ran}, skipped={skipped}, csv={out_csv}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
