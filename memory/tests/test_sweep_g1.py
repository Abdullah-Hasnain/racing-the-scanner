"""Cross-platform unit tests for the G1 sweep harness (memory/sweep_g1.py)."""

from __future__ import annotations

import csv
import io
import os
import subprocess
from pathlib import Path

import pytest

from memory import sweep_g1
from memory.scanner import scanner


class _FakeProc:
    """Minimal Popen stand-in for testing payload lifecycle."""

    def __init__(
        self,
        *,
        pid: int = 4242,
        stdout_lines: list[str] | None = None,
        stderr_text: str = "",
        exit_code: int | None = None,
    ) -> None:
        self.pid = pid
        self.stdout = io.StringIO("".join(stdout_lines or []))
        self.stderr = io.StringIO(stderr_text)
        self._exit_code = exit_code
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self._exit_code

    def terminate(self) -> None:
        self.terminated = True
        if self._exit_code is None:
            self._exit_code = 0

    def kill(self) -> None:
        self.killed = True
        self._exit_code = -9

    def wait(self, timeout: float | None = None) -> int:
        if self._exit_code is None:
            self._exit_code = 0
        return self._exit_code


def _touch_binaries(bin_dir: Path, variants: tuple[str, ...] = sweep_g1.VARIANTS_ALL) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    for v in variants:
        (bin_dir / v).write_text("", encoding="utf-8")


def _write_fake_summary_csv(path: Path, cmd: list[str]) -> None:
    arg_map: dict[str, str] = {}
    i = 0
    while i < len(cmd):
        if cmd[i].startswith("--") and i + 1 < len(cmd) and not cmd[i + 1].startswith("--"):
            arg_map[cmd[i]] = cmd[i + 1]
            i += 2
        else:
            i += 1

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=scanner.SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                "run_id": arg_map.get("--run-id", "run-1"),
                "variant": arg_map.get("--variant", "v1"),
                "pid": arg_map.get("--pid", "4242"),
                "interval_s": arg_map.get("--interval", "0.05"),
                "dwell_ms": arg_map.get("--dwell-ms", ""),
                "duration_s": arg_map.get("--duration", "10"),
                "elapsed_s": arg_map.get("--duration", "10"),
                "entropy_threshold": "7.2",
                "scans": "20",
                "catches": "4",
                "marker_catches": "4",
                "entropy_catches": "0",
                "catch_rate": "0.2",
                "miss_rate": "0.8",
                "scans_per_s": "2.0",
                "mean_scan_ms": "1.25",
                "p50_scan_ms": "1.1",
                "p95_scan_ms": "2.2",
                "p99_scan_ms": "2.5",
                "max_entropy": "0.0",
            }
        )


def test_build_sweep_grid_defaults():
    cells = sweep_g1.build_sweep_grid(
        sweep_g1.DEFAULT_VARIANTS,
        sweep_g1.DEFAULT_INTERVALS,
        sweep_g1.DEFAULT_DWELLS_MS,
    )
    # (v1, v4: 5 intervals * 1 dwell + v2, v3: 5 intervals * 4 dwells) * 3 reps = 150
    assert len(cells) == 150

    v1_cells = [c for c in cells if c.variant == "v1"]
    v4_cells = [c for c in cells if c.variant == "v4"]
    v2_cells = [c for c in cells if c.variant == "v2"]
    v3_cells = [c for c in cells if c.variant == "v3"]

    assert len(v1_cells) == 15
    assert len(v4_cells) == 15
    assert len(v2_cells) == 60
    assert len(v3_cells) == 60

    assert all(c.dwell_ms is None and c.pattern == "" for c in v1_cells + v4_cells)
    assert all(c.dwell_ms in sweep_g1.DEFAULT_DWELLS_MS and c.pattern == "seq" for c in v2_cells + v3_cells)

    for c in cells:
        expected_dur = 20.0 if c.interval_s >= 5.0 else 10.0
        assert c.duration_s == expected_dur


def test_smoke_grid_and_cli_validation():
    args = sweep_g1.parse_args(["--smoke"])
    assert args.intervals == [0.05, 0.5]
    assert args.dwell_ms == [5.0, 25.0]
    assert args.reps == 1
    assert args.duration == 2.0
    assert args.long_duration == 2.0

    cells = sweep_g1.build_sweep_grid(
        args.variants,
        args.intervals,
        args.dwell_ms,
        pattern=args.pattern,
        reps=args.reps,
        duration_s=args.duration,
        long_duration_s=args.long_duration,
    )
    assert len(cells) == 2 * 2 + 2 * 2 * 2

    for bad_argv in [
        ["--intervals", "0"],
        ["--intervals", "-0.1"],
        ["--dwell-ms", "0.05"],
        ["--touch-interval-ms", "-1"],
        ["--reps", "0"],
        ["--duration", "0"],
        ["--long-duration", "-5"],
        ["--cpu", "-2"],
    ]:
        with pytest.raises(SystemExit):
            sweep_g1.parse_args(bad_argv)


def test_resume_key_normalization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    bin_dir = tmp_path / "bin"
    out_dir = tmp_path / "results"
    _touch_binaries(bin_dir, ("v1", "v2"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_csv = out_dir / "g1_scan.csv"

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=sweep_g1.G1_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                "run_id": "pre-v1",
                "rep": "1",
                "variant": "v1",
                "dwell_ms": "",
                "interval_s": "0.50",
                "pattern": "",
                "duration_s": "2",
                "scans": "4",
                "catches": "4",
                "catch_rate": "1.0",
                "miss_rate": "0.0",
                "p50_scan_ms": "1.0",
                "p95_scan_ms": "1.2",
                "p99_scan_ms": "1.3",
                "max_entropy": "0.0",
            }
        )
        writer.writerow(
            {
                "run_id": "pre-v2",
                "rep": "1",
                "variant": "v2",
                "dwell_ms": "10.0",
                "interval_s": "0.50",
                "pattern": "seq",
                "duration_s": "2",
                "scans": "4",
                "catches": "1",
                "catch_rate": "0.25",
                "miss_rate": "0.75",
                "p50_scan_ms": "1.0",
                "p95_scan_ms": "1.2",
                "p99_scan_ms": "1.3",
                "max_entropy": "0.0",
            }
        )

    completed = sweep_g1._load_completed_keys(out_csv)
    assert ("v1", "", "0.5", 1) in completed
    assert ("v2", "10", "0.5", 1) in completed

    launched_cmds: list[list[str]] = []

    def _fake_popen(cmd, **kwargs):
        launched_cmds.append(list(cmd))
        return _FakeProc(pid=1111, stdout_lines=["[v2] pid=1111 ready\n"])

    def _fake_run(cmd, **kwargs):
        summary_path = Path(cmd[cmd.index("--summary-csv") + 1])
        _write_fake_summary_csv(summary_path, cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(sweep_g1.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(sweep_g1.subprocess, "run", _fake_run)
    monkeypatch.setattr(sweep_g1, "_unprivileged_uffd_guard", sweep_g1._unprivileged_uffd_guard)

    rc = sweep_g1.main(
        [
            "--variants",
            "v1",
            "v2",
            "--intervals",
            "0.5",
            "--dwell-ms",
            "10",
            "25",
            "--reps",
            "1",
            "--duration",
            "2",
            "--resume",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc == 0
    assert len(launched_cmds) == 1
    assert "--dwell-ms" in launched_cmds[0]
    assert launched_cmds[0][launched_cmds[0].index("--dwell-ms") + 1] == "25"

    with out_csv.open("r", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 3


def test_run_sweep_writes_g1_scan_csv_and_isolates_temp_csvs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    bin_dir = tmp_path / "bin"
    out_dir = tmp_path / "results"
    _touch_binaries(bin_dir, ("v1", "v2"))

    procs: list[_FakeProc] = []
    scanner_cmds: list[list[str]] = []

    def _fake_popen(cmd, **kwargs):
        proc = _FakeProc(pid=2222, stdout_lines=["[payload] pid=2222 ready\n"])
        procs.append(proc)
        return proc

    def _fake_run(cmd, **kwargs):
        scanner_cmds.append(list(cmd))
        summary_path = Path(cmd[cmd.index("--summary-csv") + 1])
        scans_path = Path(cmd[cmd.index("--scans-csv") + 1])
        assert summary_path.parent != out_dir
        assert scans_path.parent != out_dir
        _write_fake_summary_csv(summary_path, cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(sweep_g1.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(sweep_g1.subprocess, "run", _fake_run)

    rc = sweep_g1.main(
        [
            "--variants",
            "v1",
            "v2",
            "--intervals",
            "0.05",
            "--dwell-ms",
            "5",
            "--reps",
            "1",
            "--duration",
            "2",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc == 0
    assert all("--no-entropy" in cmd for cmd in scanner_cmds)
    assert all(p.terminated for p in procs)
    assert not (out_dir / "scanner_scans.csv").exists()
    assert not (out_dir / "scanner_summary.csv").exists()

    out_csv = out_dir / "g1_scan.csv"
    with out_csv.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == sweep_g1.G1_FIELDS
        rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["variant"] == "v1"
    assert rows[0]["dwell_ms"] == ""
    assert rows[0]["pattern"] == ""
    assert rows[1]["variant"] == "v2"
    assert rows[1]["dwell_ms"] == "5"
    assert rows[1]["pattern"] == "seq"

    # --with-entropy omits --no-entropy, and payload is still terminated when scanner fails.
    scanner_cmds.clear()
    procs.clear()

    def _failing_run(cmd, **kwargs):
        scanner_cmds.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

    monkeypatch.setattr(sweep_g1.subprocess, "run", _failing_run)
    with pytest.raises(RuntimeError, match="scanner exited with code 1"):
        sweep_g1.run_cell(
            sweep_g1.SweepCell(
                variant="v2",
                interval_s=0.05,
                dwell_ms=5.0,
                pattern="seq",
                rep=1,
                duration_s=2.0,
            ),
            bin_dir=bin_dir,
            out_csv=out_csv,
            touch_interval_ms=100.0,
            with_entropy=True,
            pin_fn=None,
        )
    assert "--no-entropy" not in scanner_cmds[0]
    assert procs[0].terminated is True


def test_v4_graceful_skip_and_strict_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    bin_dir = tmp_path / "bin"
    out_dir = tmp_path / "results"
    _touch_binaries(bin_dir, ("v1", "v4"))

    def _fake_popen(cmd, **kwargs):
        if Path(cmd[0]).name == "v4":
            return _FakeProc(
                pid=9999,
                stdout_lines=[],
                stderr_text="memfd_secret: Function not implemented\n",
                exit_code=1,
            )
        return _FakeProc(pid=1010, stdout_lines=["[v1] pid=1010 ready\n"])

    def _fake_run(cmd, **kwargs):
        summary_path = Path(cmd[cmd.index("--summary-csv") + 1])
        _write_fake_summary_csv(summary_path, cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(sweep_g1.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(sweep_g1.subprocess, "run", _fake_run)

    rc = sweep_g1.main(
        [
            "--variants",
            "v1",
            "v4",
            "--intervals",
            "0.05",
            "0.5",
            "--reps",
            "1",
            "--duration",
            "2",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc == 0

    with (out_dir / "g1_scan.csv").open("r", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert [r["variant"] for r in rows] == ["v1", "v1"]

    rc_strict = sweep_g1.main(
        [
            "--variants",
            "v4",
            "--intervals",
            "0.05",
            "--reps",
            "1",
            "--duration",
            "2",
            "--strict",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc_strict == 1


def test_unprivileged_uffd_guard_flips_and_restores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    sysctl_file = tmp_path / "unprivileged_userfaultfd"
    sysctl_file.write_text("0\n", encoding="utf-8")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)

    with sweep_g1._unprivileged_uffd_guard(["v3"], sysctl_path=sysctl_file):
        assert sysctl_file.read_text(encoding="utf-8").strip() == "1"
    assert sysctl_file.read_text(encoding="utf-8").strip() == "0"

    with pytest.raises(RuntimeError, match="boom"):
        with sweep_g1._unprivileged_uffd_guard(["v3"], sysctl_path=sysctl_file):
            assert sysctl_file.read_text(encoding="utf-8").strip() == "1"
            raise RuntimeError("boom")
    assert sysctl_file.read_text(encoding="utf-8").strip() == "0"


def test_pin_fn_calls_sched_setaffinity(monkeypatch: pytest.MonkeyPatch):
    calls: list[tuple[int, set[int]]] = []

    def _fake_affinity(pid: int, cpus: set[int]) -> None:
        calls.append((pid, set(cpus)))

    monkeypatch.setattr(os, "sched_setaffinity", _fake_affinity, raising=False)

    assert sweep_g1._make_pin_fn(None) is None
    pin_fn = sweep_g1._make_pin_fn(0)
    assert pin_fn is not None
    pin_fn()
    assert calls == [(0, {0})]
