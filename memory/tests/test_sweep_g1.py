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


def _write_fake_summary_csv(
    path: Path,
    cmd: list[str],
    *,
    elapsed_s: str | None = None,
) -> None:
    arg_map: dict[str, str] = {}
    i = 0
    while i < len(cmd):
        if cmd[i].startswith("--") and i + 1 < len(cmd) and not cmd[i + 1].startswith("--"):
            arg_map[cmd[i]] = cmd[i + 1]
            i += 2
        else:
            i += 1

    duration_s = arg_map.get("--duration", "10")
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
                "duration_s": duration_s,
                "elapsed_s": duration_s if elapsed_s is None else elapsed_s,
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
                "max_entropy": "0.0" if "--no-entropy" in cmd else "7.85",
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
    assert all(
        c.dwell_ms in sweep_g1.DEFAULT_DWELLS_MS and c.pattern == "seq"
        for c in v2_cells + v3_cells
    )

    for c in cells:
        expected_dur = 20.0 if c.interval_s >= 5.0 else 10.0
        assert c.duration_s == expected_dur


def test_smoke_grid_and_cli_validation():
    args = sweep_g1.parse_args(["--smoke"])
    assert args.intervals == [0.037, 0.537]
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


def test_smoke_writes_to_g1_scan_smoke_csv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    bin_dir = tmp_path / "bin"
    out_dir = tmp_path / "results"
    _touch_binaries(bin_dir, ("v1",))

    def _fake_popen(cmd, **kwargs):
        return _FakeProc(pid=3131, stdout_lines=["[v1] pid=3131 ready\n"])

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
            "--smoke",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc == 0
    assert (out_dir / "g1_scan_smoke.csv").exists()
    assert not (out_dir / "g1_scan.csv").exists()


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
                "duration_s": "2.0",
                "scans": "4",
                "catches": "4",
                "catch_rate": "1.0",
                "miss_rate": "0.0",
                "p50_scan_ms": "1.0",
                "p95_scan_ms": "1.2",
                "p99_scan_ms": "1.3",
                "max_entropy": "",
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
                "duration_s": "2.0",
                "scans": "4",
                "catches": "1",
                "catch_rate": "0.25",
                "miss_rate": "0.75",
                "p50_scan_ms": "1.0",
                "p95_scan_ms": "1.2",
                "p99_scan_ms": "1.3",
                "max_entropy": "",
            }
        )

    completed = sweep_g1._load_completed_keys(out_csv)
    assert ("v1", "", "0.5", "", "2", 1) in completed
    assert ("v2", "10", "0.5", "seq", "2", 1) in completed

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

    # Matching duration/pattern skips v1 and v2@10ms, running only v2@25ms.
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
    assert launched_cmds[0][launched_cmds[0].index("--dwell-ms") + 1] == "25"

    # Changing --pattern or --duration must NOT falsely skip the pre-existing cell.
    launched_cmds.clear()
    rc2 = sweep_g1.main(
        [
            "--variants",
            "v2",
            "--intervals",
            "0.5",
            "--dwell-ms",
            "10",
            "--pattern",
            "random",
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
    assert rc2 == 0
    assert len(launched_cmds) == 1
    assert launched_cmds[0][launched_cmds[0].index("--pattern") + 1] == "random"

    launched_cmds.clear()
    rc3 = sweep_g1.main(
        [
            "--variants",
            "v2",
            "--intervals",
            "0.5",
            "--dwell-ms",
            "10",
            "--pattern",
            "seq",
            "--reps",
            "1",
            "--duration",
            "10",
            "--resume",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc3 == 0
    assert len(launched_cmds) == 1


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
    assert rows[0]["max_entropy"] == ""
    assert rows[1]["variant"] == "v2"
    assert rows[1]["dwell_ms"] == "5"
    assert rows[1]["pattern"] == "seq"
    assert rows[1]["max_entropy"] == ""

    # --with-entropy omits --no-entropy and records scanner's max_entropy.
    scanner_cmds.clear()
    procs.clear()
    row = sweep_g1.run_cell(
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
    assert row["max_entropy"] == "7.85"

    # Payload is still terminated when scanner fails.
    procs.clear()

    def _failing_run(cmd, **kwargs):
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
    assert procs[0].terminated is True


def test_incomplete_cell_not_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    bin_dir = tmp_path / "bin"
    out_dir = tmp_path / "results"
    out_csv = out_dir / "g1_scan.csv"
    _touch_binaries(bin_dir, ("v2",))

    def _fake_popen(cmd, **kwargs):
        return _FakeProc(pid=5151, stdout_lines=["[v2] pid=5151 ready\n"])

    # Case A: payload died early (elapsed_s=0.5s out of 10.0s).
    def _early_run(cmd, **kwargs):
        summary_path = Path(cmd[cmd.index("--summary-csv") + 1])
        _write_fake_summary_csv(summary_path, cmd, elapsed_s="0.5")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(sweep_g1.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(sweep_g1.subprocess, "run", _early_run)

    rc = sweep_g1.main(
        [
            "--variants",
            "v2",
            "--intervals",
            "0.05",
            "--dwell-ms",
            "5",
            "--reps",
            "1",
            "--duration",
            "10",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc == 1
    assert not out_csv.exists()

    # Case B: interrupted mid-cell (should_stop=True) even if elapsed_s looks complete.
    def _full_run(cmd, **kwargs):
        summary_path = Path(cmd[cmd.index("--summary-csv") + 1])
        _write_fake_summary_csv(summary_path, cmd, elapsed_s="10.0")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(sweep_g1.subprocess, "run", _full_run)
    with pytest.raises(sweep_g1.IncompleteCellError, match="interrupted"):
        sweep_g1.run_cell(
            sweep_g1.SweepCell(
                variant="v2",
                interval_s=0.05,
                dwell_ms=5.0,
                pattern="seq",
                rep=1,
                duration_s=10.0,
            ),
            bin_dir=bin_dir,
            out_csv=out_csv,
            touch_interval_ms=100.0,
            with_entropy=False,
            pin_fn=None,
            should_stop=lambda: True,
        )
    assert not out_csv.exists()


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


def test_unprivileged_uffd_does_not_modify_sysctl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    sysctl_file = tmp_path / "unprivileged_userfaultfd"
    sysctl_file.write_text("0\n", encoding="utf-8")

    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    sweep_g1._warn_if_unprivileged_uffd_disabled(["v3"], sysctl_path=sysctl_file)
    assert sysctl_file.read_text(encoding="utf-8").strip() == "0"
    assert capsys.readouterr().err == ""

    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    sweep_g1._warn_if_unprivileged_uffd_disabled(["v3"], sysctl_path=sysctl_file)
    assert sysctl_file.read_text(encoding="utf-8").strip() == "0"
    assert "CAP_SYS_PTRACE" in capsys.readouterr().err


def test_pin_fn_calls_sched_setaffinity(monkeypatch: pytest.MonkeyPatch):
    calls: list[tuple[int, set[int]]] = []

    def _fake_affinity(pid: int, cpus: set[int]) -> None:
        calls.append((pid, set(cpus)))

    monkeypatch.setattr(os, "sched_setaffinity", _fake_affinity, raising=False)
    monkeypatch.setattr(os, "sched_getaffinity", lambda _pid: {0, 1, 2, 3}, raising=False)
    assert sweep_g1._default_cpu() == 2

    monkeypatch.setattr(os, "sched_getaffinity", lambda _pid: {0, 1}, raising=False)
    assert sweep_g1._default_cpu() == 1

    assert sweep_g1._make_pin_fn(None) is None
    pin_fn = sweep_g1._make_pin_fn(2)
    assert pin_fn is not None
    pin_fn()
    assert calls == [(0, {2})]


def test_default_intervals_step_through_the_payloads_100ms_cycle():
    # V2/V3 expose a page once per 100 ms. An interval that is a multiple of 50 ms keeps
    # every scan on the same phase of that cycle (#63), so each must be k*100 ms + r with
    # r coprime to 100: then successive scans visit every phase.
    import math

    for interval in (*sweep_g1.DEFAULT_INTERVALS, *sweep_g1.SMOKE_INTERVALS):
        r = round(interval * 1000) % 100
        assert math.gcd(r, 100) == 1, interval
