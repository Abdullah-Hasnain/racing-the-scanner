"""Cross-platform unit tests for the G2 Pareto sweep harness (memory/sweep_g2.py)."""

from __future__ import annotations

import csv
import io
import subprocess
from pathlib import Path

import pandas as pd
import pytest

from analysis import make_graphs as mg
from memory import sweep_g2
from memory.scanner import scanner


class _FakeCostProc:
    """Minimal Popen stand-in for Phase A cost-pass lifecycle and zombie stat tests."""

    def __init__(
        self,
        *,
        pid: int = 4242,
        banner: str = "[v1] pid=4242 ready\n",
        done_line: str = "[v1] done: accesses=100000 faults=0 elapsed_s=5.002 faults_per_s=0.0\n",
        stderr_text: str = "",
        exit_code: int = 0,
        wait_events: list[tuple[str, int]] | None = None,
        block_until_terminated: bool = False,
    ) -> None:
        self.pid = pid
        self.stderr = io.StringIO(stderr_text)
        self._exit_code = exit_code
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False
        self._wait_events = wait_events
        self._block_until_terminated = block_until_terminated
        self._banner = banner
        self._done_line = done_line
        self._read_calls = 0
        self.stdout = self

    def readline(self) -> str:
        if self._read_calls == 0:
            self._read_calls += 1
            return self._banner
        return ""

    def read(self) -> str:
        if self._block_until_terminated:
            import threading

            if not hasattr(self, "_stop_ev"):
                self._stop_ev = threading.Event()
            self._stop_ev.wait(timeout=5.0)
            return ""
        return self._done_line

    def close(self) -> None:
        pass

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        if self.returncode is None:
            self.returncode = 0
        if hasattr(self, "_stop_ev"):
            self._stop_ev.set()

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9
        if hasattr(self, "_stop_ev"):
            self._stop_ev.set()

    def wait(self, timeout: float | None = None) -> int:
        if self._wait_events is not None:
            self._wait_events.append(("wait", self.pid))
        if self.returncode is None:
            self.returncode = self._exit_code
        return self.returncode


class _FakeEvasionProc:
    """Minimal Popen stand-in for Phase B evasion-pass payload lifecycle."""

    def __init__(
        self,
        *,
        pid: int = 5252,
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


def _touch_binaries(bin_dir: Path, variants: tuple[str, ...] = sweep_g2.VARIANTS_ALL) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    for v in variants:
        (bin_dir / v).write_text("", encoding="utf-8")


def _write_fake_summary_csv(
    path: Path,
    cmd: list[str],
    *,
    catch_rate: str = "0.2",
    elapsed_s: str | None = None,
    p95_scan_ms: str = "2.2",
) -> None:
    arg_map: dict[str, str] = {}
    i = 0
    while i < len(cmd):
        if cmd[i].startswith("--") and i + 1 < len(cmd) and not cmd[i + 1].startswith("--"):
            arg_map[cmd[i]] = cmd[i + 1]
            i += 2
        else:
            i += 1

    duration_s = arg_map.get("--duration", "5")
    cr = float(catch_rate)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=scanner.SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                "run_id": arg_map.get("--run-id", "run-1"),
                "variant": arg_map.get("--variant", "v1"),
                "pid": arg_map.get("--pid", "5252"),
                "interval_s": arg_map.get("--interval", "0.037"),
                "dwell_ms": arg_map.get("--dwell-ms", ""),
                "duration_s": duration_s,
                "elapsed_s": duration_s if elapsed_s is None else elapsed_s,
                "entropy_threshold": "7.2",
                "scans": "100",
                "catches": str(round(cr * 100)),
                "marker_catches": str(round(cr * 100)),
                "entropy_catches": "0",
                "catch_rate": f"{cr:g}",
                "miss_rate": f"{1.0 - cr:g}",
                "scans_per_s": "20.0",
                "mean_scan_ms": "1.25",
                "p50_scan_ms": "1.1",
                "p95_scan_ms": p95_scan_ms,
                "p99_scan_ms": "2.5",
                "max_entropy": "0.0" if "--no-entropy" in cmd else "7.85",
            }
        )


def test_build_sweep_grid_defaults_and_v1_first():
    cells = sweep_g2.build_sweep_grid(
        sweep_g2.DEFAULT_VARIANTS,
        sweep_g2.DEFAULT_DWELLS_MS,
    )
    # (v1, v4: 1 dwell each + v2, v3: 4 dwells each) * 3 reps = 30
    assert len(cells) == 30

    v1_cells = [c for c in cells if c.variant == "v1"]
    v4_cells = [c for c in cells if c.variant == "v4"]
    v2_cells = [c for c in cells if c.variant == "v2"]
    v3_cells = [c for c in cells if c.variant == "v3"]

    assert len(v1_cells) == 3
    assert len(v4_cells) == 3
    assert len(v2_cells) == 12
    assert len(v3_cells) == 12
    assert all(c.dwell_ms is None and c.pattern == "seq" for c in v1_cells + v4_cells)
    assert all(c.dwell_ms in sweep_g2.DEFAULT_DWELLS_MS and c.pattern == "seq" for c in v2_cells + v3_cells)
    assert all(c.duration_s == 5.0 for c in cells)

    reordered = sweep_g2.build_sweep_grid(["v3", "v2", "v1", "v2"], [5.0], reps=1)
    assert [c.variant for c in reordered] == ["v1", "v3", "v2"]


def test_smoke_grid_and_cli_validation():
    args = sweep_g2.parse_args(["--smoke"])
    assert args.dwell_ms == [5.0, 25.0]
    assert args.reps == 1
    assert args.duration == 2.0
    assert args.scan_interval == pytest.approx(0.037)

    cells = sweep_g2.build_sweep_grid(
        args.variants,
        args.dwell_ms,
        pattern=args.pattern,
        reps=args.reps,
        duration_s=args.duration,
    )
    assert len(cells) == 6

    for bad_argv in [
        ["--scan-interval", "0"],
        ["--scan-interval", "-0.1"],
        ["--dwell-ms", "0.05"],
        ["--touch-interval-ms", "-1"],
        ["--reps", "0"],
        ["--duration", "0"],
        ["--cpu", "-2"],
    ]:
        with pytest.raises(SystemExit):
            sweep_g2.parse_args(bad_argv)


def test_parse_proc_stat_minflt_and_done_line():
    stat = "1234 (my (weird) proc) S 1 2 3 4 5 6 98765 0 0 0"
    assert sweep_g2._parse_proc_stat_minflt(stat) == 98765

    with pytest.raises(ValueError):
        sweep_g2._parse_proc_stat_minflt("1234 no parens")
    with pytest.raises(ValueError):
        sweep_g2._parse_proc_stat_minflt("1234 (v1) S 1 2")

    assert sweep_g2._parse_done_line(
        "[v1] done: accesses=5000000 faults=0 elapsed_s=5.001 faults_per_s=0.0\n",
        "v1",
    ) == (5000000, 0, 5.001)
    assert sweep_g2._parse_done_line(
        "[v2] done: accesses=2500 faults=2500 relocks=2500 (timer=0, swap=2500) elapsed_s=5.000 faults_per_s=500.0\n",
        "v2",
    ) == (2500, 2500, 5.0)
    assert sweep_g2._parse_done_line(
        "[v3] done: accesses=1200 faults=1200 drops=1200 (timer=0, swap=1200) ext_zerofills=3 elapsed_s=4.998 faults_per_s=240.1\n",
        "v3",
    ) == (1200, 1200, 4.998)
    assert sweep_g2._parse_done_line(
        "[v4] done: accesses=4500000 faults=0 elapsed_s=5.000 faults_per_s=0.0\n",
        "v4",
    ) == (4500000, 0, 5.0)

    with pytest.raises(RuntimeError, match="done:"):
        sweep_g2._parse_done_line("no summary here\n", "v1")


def test_run_sweep_writes_g2_pareto_csv_and_zombie_stat_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    bin_dir = tmp_path / "bin"
    out_dir = tmp_path / "results"
    _touch_binaries(bin_dir, ("v1", "v2"))

    events: list[tuple[str, int]] = []
    evasion_procs: list[_FakeEvasionProc] = []
    scanner_cmds: list[list[str]] = []
    stat_readings: dict[int, list[int]] = {
        1001: [120, 125],  # v1 cost pass: delta = 5
        2001: [200, 5200],  # v2 cost pass: delta = 5000
    }

    def _fake_popen(cmd, **kwargs):
        variant = Path(cmd[0]).name
        interval_ms = cmd[cmd.index("--interval-ms") + 1]
        if interval_ms == "0":
            if variant == "v1":
                return _FakeCostProc(
                    pid=1001,
                    banner="[v1] pid=1001 ready\n",
                    done_line="[v1] done: accesses=500000 faults=0 elapsed_s=5.002 faults_per_s=0.0\n",
                    wait_events=events,
                )
            return _FakeCostProc(
                pid=2001,
                banner="[v2] pid=2001 ready\n",
                done_line="[v2] done: accesses=10000 faults=10000 elapsed_s=5.000 faults_per_s=2000.0\n",
                wait_events=events,
            )
        proc = _FakeEvasionProc(
            pid=3001 if variant == "v1" else 3002,
            stdout_lines=[f"[{variant}] pid=3001 ready\n"],
        )
        evasion_procs.append(proc)
        return proc

    def _fake_stat_reader(pid: int) -> int | None:
        events.append(("stat", pid))
        vals = stat_readings[pid]
        return vals.pop(0)

    def _fake_run(cmd, **kwargs):
        scanner_cmds.append(list(cmd))
        summary_path = Path(cmd[cmd.index("--summary-csv") + 1])
        scans_path = Path(cmd[cmd.index("--scans-csv") + 1])
        assert summary_path.parent != out_dir
        assert scans_path.parent != out_dir
        variant = cmd[cmd.index("--variant") + 1]
        _write_fake_summary_csv(
            summary_path,
            cmd,
            catch_rate="1.0" if variant == "v1" else "0.1",
            p95_scan_ms="1.8",
        )
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(sweep_g2.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(sweep_g2.subprocess, "run", _fake_run)
    monkeypatch.setattr(sweep_g2, "_read_proc_stat_minflt", _fake_stat_reader)

    rc = sweep_g2.main(
        [
            "--variants",
            "v2",
            "v1",
            "--dwell-ms",
            "5",
            "--reps",
            "1",
            "--duration",
            "5",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc == 0
    assert all("--no-entropy" in cmd for cmd in scanner_cmds)
    assert all(cmd[cmd.index("--interval") + 1] == "0.037" for cmd in scanner_cmds)
    assert all(p.terminated for p in evasion_procs)
    assert not (out_dir / "scanner_scans.csv").exists()
    assert not (out_dir / "scanner_summary.csv").exists()

    # Verify zombie stat read happened strictly BEFORE wait() for each cost PID.
    for pid in (1001, 2001):
        pid_events = [kind for kind, p in events if p == pid]
        assert pid_events == ["stat", "stat", "wait"]

    out_csv = out_dir / "g2_pareto.csv"
    with out_csv.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        assert reader.fieldnames == sweep_g2.G2_FIELDS
        rows = list(reader)

    assert len(rows) == 2
    assert rows[0]["variant"] == "v1"
    assert rows[0]["dwell_ms"] == ""
    assert rows[0]["duration_s"] == "5"  # requested duration, not 5.002
    assert float(rows[0]["slowdown_vs_v1"]) == pytest.approx(1.0)
    assert float(rows[0]["evasion_rate"]) == pytest.approx(0.0)
    assert rows[0]["minflt"] == "5"

    assert rows[1]["variant"] == "v2"
    assert rows[1]["dwell_ms"] == "5"
    assert rows[1]["duration_s"] == "5"
    expected_v1_rate = 500000 / 5.002
    expected_v2_rate = 10000 / 5.000
    assert float(rows[1]["slowdown_vs_v1"]) == pytest.approx(expected_v1_rate / expected_v2_rate, rel=1e-5)
    assert float(rows[1]["evasion_rate"]) == pytest.approx(0.9)
    assert rows[1]["minflt"] == "5000"
    assert rows[1]["faults"] == "10000"

    # --smoke writes g2_pareto_smoke.csv and --with-entropy omits --no-entropy.
    stat_readings[1001] = [10, 12]
    stat_readings[2001] = [20, 520]
    scanner_cmds.clear()
    rc_smoke = sweep_g2.main(
        [
            "--variants",
            "v1",
            "--smoke",
            "--with-entropy",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc_smoke == 0
    assert "--no-entropy" not in scanner_cmds[0]
    assert (out_dir / "g2_pareto_smoke.csv").exists()


def test_resume_and_non_resume_v1_baseline_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    bin_dir = tmp_path / "bin"
    out_dir = tmp_path / "results"
    _touch_binaries(bin_dir, ("v1", "v2"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out_csv = out_dir / "g2_pareto.csv"

    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=sweep_g2.G2_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                "run_id": "pre-v1",
                "rep": "1",
                "variant": "v1",
                "dwell_ms": "",
                "pattern": "seq",
                "duration_s": "5.0",
                "accesses": "500000",
                "accesses_per_s": "100000",
                "slowdown_vs_v1": "1.0",
                "faults": "0",
                "faults_per_s": "0",
                "minflt": "0",
                "evasion_rate": "0.0",
                "catch_rate": "1.0",
                "p95_scan_ms": "1.5",
            }
        )
        writer.writerow(
            {
                "run_id": "pre-v2",
                "rep": "1",
                "variant": "v2",
                "dwell_ms": "10.0",
                "pattern": "seq",
                "duration_s": "5.0",
                "accesses": "10000",
                "accesses_per_s": "2000",
                "slowdown_vs_v1": "50.0",
                "faults": "10000",
                "faults_per_s": "2000",
                "minflt": "0",
                "evasion_rate": "0.8",
                "catch_rate": "0.2",
                "p95_scan_ms": "1.5",
            }
        )

    launched_cmds: list[list[str]] = []

    def _fake_popen(cmd, **kwargs):
        launched_cmds.append(list(cmd))
        if cmd[cmd.index("--interval-ms") + 1] == "0":
            return _FakeCostProc(
                pid=2222,
                banner="[v2] pid=2222 ready\n",
                done_line="[v2] done: accesses=25000 faults=25000 elapsed_s=5.000 faults_per_s=5000.0\n",
            )
        return _FakeEvasionProc(pid=2223, stdout_lines=["[v2] pid=2223 ready\n"])

    def _fake_run(cmd, **kwargs):
        summary_path = Path(cmd[cmd.index("--summary-csv") + 1])
        _write_fake_summary_csv(summary_path, cmd, catch_rate="0.3")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(sweep_g2.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(sweep_g2.subprocess, "run", _fake_run)
    monkeypatch.setattr(sweep_g2, "_read_proc_stat_minflt", lambda _pid: 10)

    # --resume skips v1 and v2@10ms, reloads v1 baseline (100000/s), runs only v2@25ms,
    # and warns when non-default --scan-interval is given.
    rc = sweep_g2.main(
        [
            "--variants",
            "v1",
            "v2",
            "--dwell-ms",
            "10",
            "25",
            "--scan-interval",
            "0.05",
            "--reps",
            "1",
            "--duration",
            "5",
            "--resume",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc == 0
    assert "--scan-interval" in capsys.readouterr().err
    assert len(launched_cmds) == 2  # Phase A + Phase B for v2@25ms only
    assert launched_cmds[0][launched_cmds[0].index("--dwell-ms") + 1] == "25"

    with out_csv.open("r", newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[-1]["dwell_ms"] == "25"
    assert float(rows[-1]["slowdown_vs_v1"]) == pytest.approx(100000 / 5000)

    # Changing --pattern must NOT falsely skip the pre-existing cell; running --variants v2
    # without v1 for that pattern must fail cleanly with rc=2.
    rc_missing = sweep_g2.main(
        [
            "--variants",
            "v2",
            "--dwell-ms",
            "10",
            "--pattern",
            "random",
            "--reps",
            "1",
            "--duration",
            "5",
            "--resume",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc_missing == 2

    # Without --resume, running --variants v2 against existing v1 baseline reuses it.
    launched_cmds.clear()
    rc_non_resume = sweep_g2.main(
        [
            "--variants",
            "v2",
            "--dwell-ms",
            "10",
            "--reps",
            "1",
            "--duration",
            "5",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc_non_resume == 0
    assert len(launched_cmds) == 2


def test_incomplete_cell_interrupt_timeout_and_v4_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    bin_dir = tmp_path / "bin"
    out_dir = tmp_path / "results"
    out_csv = out_dir / "g2_pareto.csv"
    _touch_binaries(bin_dir, ("v1", "v2", "v4"))

    # Case A: cost pass ended early (elapsed_s=0.5s out of 5.0s).
    monkeypatch.setattr(
        sweep_g2.subprocess,
        "Popen",
        lambda cmd, **kwargs: _FakeCostProc(
            pid=6161,
            banner="[v1] pid=6161 ready\n",
            done_line="[v1] done: accesses=100 faults=0 elapsed_s=0.500 faults_per_s=0.0\n",
        ),
    )
    monkeypatch.setattr(sweep_g2, "_read_proc_stat_minflt", lambda _pid: 0)
    rc_short = sweep_g2.main(
        [
            "--variants",
            "v1",
            "--reps",
            "1",
            "--duration",
            "5",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc_short == 1
    assert not out_csv.exists()

    # Case B: zero accesses raises RuntimeError instead of ZeroDivisionError.
    monkeypatch.setattr(
        sweep_g2.subprocess,
        "Popen",
        lambda cmd, **kwargs: _FakeCostProc(
            pid=6162,
            banner="[v1] pid=6162 ready\n",
            done_line="[v1] done: accesses=0 faults=0 elapsed_s=5.000 faults_per_s=0.0\n",
        ),
    )
    with pytest.raises(RuntimeError, match="0 accesses"):
        sweep_g2.run_cell(
            sweep_g2.SweepCell("v1", None, "seq", 1, 5.0),
            bin_dir=bin_dir,
            out_csv=out_csv,
            scan_interval_s=0.037,
            touch_interval_ms=100.0,
            with_entropy=False,
            pin_fn=None,
        )

    # Case C: should_stop=True interrupts blocked cost pass and terminates payload.
    blocked_proc = _FakeCostProc(pid=6163, block_until_terminated=True)
    monkeypatch.setattr(sweep_g2.subprocess, "Popen", lambda cmd, **kwargs: blocked_proc)
    with pytest.raises(sweep_g2.IncompleteCellError, match="interrupted"):
        sweep_g2.run_cell(
            sweep_g2.SweepCell("v1", None, "seq", 1, 5.0),
            bin_dir=bin_dir,
            out_csv=out_csv,
            scan_interval_s=0.037,
            touch_interval_ms=100.0,
            with_entropy=False,
            pin_fn=None,
            should_stop=lambda: True,
        )
    assert blocked_proc.terminated is True
    assert not out_csv.exists()

    # Case D: cost pass timeout terminates payload and raises IncompleteCellError.
    timeout_proc = _FakeCostProc(pid=6164, block_until_terminated=True)
    with pytest.raises(sweep_g2.IncompleteCellError, match="timed out"):
        sweep_g2._read_remaining_stdout_interruptible(timeout_proc, timeout_s=0.05)  # type: ignore[arg-type]
    assert timeout_proc.terminated is True

    # Case E: scanner failure in Phase B terminates evasion payload.
    evasion_procs: list[_FakeEvasionProc] = []

    def _evasion_fail_popen(cmd, **kwargs):
        if cmd[cmd.index("--interval-ms") + 1] == "0":
            return _FakeCostProc(
                pid=6165,
                banner="[v1] pid=6165 ready\n",
                done_line="[v1] done: accesses=1000 faults=0 elapsed_s=5.000 faults_per_s=0.0\n",
            )
        p = _FakeEvasionProc(pid=6166, stdout_lines=["[v1] pid=6166 ready\n"])
        evasion_procs.append(p)
        return p

    monkeypatch.setattr(sweep_g2.subprocess, "Popen", _evasion_fail_popen)
    monkeypatch.setattr(
        sweep_g2.subprocess,
        "run",
        lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom"),
    )
    with pytest.raises(RuntimeError, match="scanner exited with code 1"):
        sweep_g2.run_cell(
            sweep_g2.SweepCell("v1", None, "seq", 1, 5.0),
            bin_dir=bin_dir,
            out_csv=out_csv,
            scan_interval_s=0.037,
            touch_interval_ms=100.0,
            with_entropy=False,
            pin_fn=None,
        )
    assert evasion_procs[0].terminated is True

    # Case F: v4 graceful skip vs --strict.
    def _v4_skip_popen(cmd, **kwargs):
        name = Path(cmd[0]).name
        if name == "v4":
            return _FakeEvasionProc(
                pid=9999,
                stdout_lines=[],
                stderr_text="memfd_secret: Function not implemented\n",
                exit_code=1,
            )
        if cmd[cmd.index("--interval-ms") + 1] == "0":
            return _FakeCostProc(
                pid=7171,
                banner="[v1] pid=7171 ready\n",
                done_line="[v1] done: accesses=1000 faults=0 elapsed_s=5.000 faults_per_s=0.0\n",
            )
        return _FakeEvasionProc(pid=7172, stdout_lines=["[v1] pid=7172 ready\n"])

    monkeypatch.setattr(sweep_g2.subprocess, "Popen", _v4_skip_popen)
    monkeypatch.setattr(
        sweep_g2.subprocess,
        "run",
        lambda cmd, **kwargs: (
            _write_fake_summary_csv(Path(cmd[cmd.index("--summary-csv") + 1]), cmd)
            or subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        ),
    )
    rc_skip = sweep_g2.main(
        [
            "--variants",
            "v1",
            "v4",
            "--reps",
            "1",
            "--duration",
            "5",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc_skip == 0

    rc_strict = sweep_g2.main(
        [
            "--variants",
            "v4",
            "--reps",
            "1",
            "--duration",
            "5",
            "--strict",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(out_dir),
        ]
    )
    assert rc_strict == 1


def test_g2_csv_compatible_with_make_graphs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    bin_dir = tmp_path / "bin"
    res_dir = tmp_path / "results"
    fig_dir = tmp_path / "figures"
    _touch_binaries(bin_dir, ("v1", "v2", "v3", "v4"))

    monkeypatch.setattr(mg, "RESULTS", res_dir)
    monkeypatch.setattr(mg, "FIGURES", fig_dir)
    monkeypatch.setattr(mg, "CAPTURED", tmp_path / "captured")

    cost_specs = {
        ("v1", None): (1000000, 0, 5, "1.0"),
        ("v2", "1"): (20000, 20000, 100, "0.05"),
        ("v2", "25"): (25000, 25000, 120, "0.4"),
        ("v3", "1"): (10000, 10000, 10000, "0.02"),
        ("v3", "25"): (15000, 15000, 12000, "0.2"),
        ("v4", None): (950000, 0, 4, "0.0"),
    }

    next_pid = 1000

    def _fake_popen(cmd, **kwargs):
        nonlocal next_pid
        next_pid += 1
        variant = Path(cmd[0]).name
        dwell = cmd[cmd.index("--dwell-ms") + 1] if "--dwell-ms" in cmd else None
        if cmd[cmd.index("--interval-ms") + 1] == "0":
            acc, flt, _minflt, _cr = cost_specs[(variant, dwell)]
            return _FakeCostProc(
                pid=next_pid,
                banner=f"[{variant}] pid={next_pid} ready\n",
                done_line=f"[{variant}] done: accesses={acc} faults={flt} elapsed_s=5.000 faults_per_s=0.0\n",
            )
        return _FakeEvasionProc(pid=next_pid, stdout_lines=[f"[{variant}] pid={next_pid} ready\n"])

    stat_calls: dict[int, int] = {}

    def _fake_stat(pid: int) -> int | None:
        count = stat_calls.get(pid, 0)
        stat_calls[pid] = count + 1
        return 10 if count == 0 else 510

    def _fake_run(cmd, **kwargs):
        variant = cmd[cmd.index("--variant") + 1]
        dwell = cmd[cmd.index("--dwell-ms") + 1] if "--dwell-ms" in cmd else None
        _, _, _, cr = cost_specs[(variant, dwell)]
        _write_fake_summary_csv(Path(cmd[cmd.index("--summary-csv") + 1]), cmd, catch_rate=cr)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(sweep_g2.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(sweep_g2.subprocess, "run", _fake_run)
    monkeypatch.setattr(sweep_g2, "_read_proc_stat_minflt", _fake_stat)

    rc = sweep_g2.main(
        [
            "--variants",
            "v1",
            "v2",
            "v3",
            "v4",
            "--dwell-ms",
            "1",
            "25",
            "--reps",
            "1",
            "--duration",
            "5",
            "--no-pin",
            "--bin-dir",
            str(bin_dir),
            "--out-dir",
            str(res_dir),
        ]
    )
    assert rc == 0

    df = pd.read_csv(res_dir / "g2_pareto.csv")
    summary = mg.g2_summary(df)
    front = summary[summary["pareto"]].set_index(["variant", "dwell_ms"])
    assert ("v1", 0.0) in front.index
    assert ("v4", 0.0) in front.index

    assert mg.g2_pareto() is True
    png = fig_dir / "G2_pareto.png"
    assert png.exists() and png.read_bytes()[:4] == b"\x89PNG"
