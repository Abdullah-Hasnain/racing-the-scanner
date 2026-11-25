"""The live coupled run reduces scanner output to scans, catches and latency (#15)."""

import pytest

from detection.coupled_live import summarize

SCANNER_OUT = """\
[scanner] yara not available; using plain byte search
scan    1  found=0  scan_ms=   2.00
scan    2  found=1  scan_ms=   4.00
scan    3  found=0  scan_ms=  10.00
scan    4  found=0  scan_ms=   4.00

catch rate: 1/4 = 25.00%
"""


def test_summarize_counts_scans_and_catches():
    s = summarize(SCANNER_OUT.splitlines(), seconds=2.0)
    assert (s.scans, s.catches) == (4, 1)
    assert s.scans_per_s == pytest.approx(2.0)


def test_summarize_reports_median_and_p95_scan_time():
    # Linear-interpolated percentiles, as the simulation reports them:
    # sorted [2, 4, 4, 10], p95 sits 0.85 of the way from 4 to 10.
    s = summarize(SCANNER_OUT.splitlines(), seconds=2.0)
    assert s.p50_scan_ms == pytest.approx(4.0)
    assert s.p95_scan_ms == pytest.approx(9.1)


def test_summarize_with_no_scans_has_no_latency():
    s = summarize(["[scanner] target process gone"], seconds=1.0)
    assert (s.scans, s.catches, s.scans_per_s) == (0, 0, 0.0)
    assert s.p50_scan_ms is None and s.p95_scan_ms is None


def test_scanner_skips_entropy_and_csv():
    # The entropy pass makes each scan ~40x slower (#47), so a scanner run with it
    # would be starved differently from the captured G3 run. As root, the CSV
    # would also leave root-owned files in results/.
    from detection.coupled_live import scanner_command

    cmd = scanner_command("/repo", pid=42, interval=0.037, duration=25)
    assert cmd[1] == "/repo/memory/scanner/scanner.py"
    assert {"--no-entropy", "--no-csv"} <= set(cmd)
    assert cmd[cmd.index("--pid") + 1] == "42"


# The current scanner's line (#45/#49); the fixture above is the pre-#45 one.
CURRENT_LINE = "scan    3  found=1  scan_ms=   0.30  max_entropy= 0.00  entropy_flag=0"


def test_summarize_reads_the_current_scanner_line():
    s = summarize([CURRENT_LINE], seconds=1.0)
    assert (s.scans, s.catches, s.p50_scan_ms) == (1, 1, 0.30)


# --- run_cell without root: stand-in scanner and V2, no pinning, no cgroups ---

import argparse  # noqa: E402
import os  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from detection import coupled_live  # noqa: E402

FAKE_V2 = """\
import signal, sys, time
def done(*_):
    print("[v2] done: accesses=7 faults=7 relocks=7", flush=True); sys.exit(0)
signal.signal(signal.SIGINT, done)
print("[v2] pid ready", flush=True)
while True: time.sleep(0.05)
"""


def _script(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(f"#!{sys.executable}\n" + body)
    p.chmod(0o755)
    return p


def _gone(pid: int, timeout: float = 3.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        # a zombie still answers kill(0); count it as gone once reaped elsewhere
        if Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z":
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def cell(tmp_path, monkeypatch):
    """Run one cell with the given stand-in scanner body; record every child pid."""
    joined: list[int] = []
    monkeypatch.setattr(coupled_live, "_child_setup", lambda *a, **k: None)
    monkeypatch.setattr(coupled_live, "_make_cgroups", lambda: (Path("m"), Path("a")))
    monkeypatch.setattr(coupled_live, "_join", lambda cg, pid: joined.append(pid))
    monkeypatch.setattr(coupled_live, "_remove_cgroups", lambda: None)
    monkeypatch.setattr(coupled_live.time, "sleep", lambda s: None)  # skip V2's lock wait

    def run(scanner_body: str, condition: str = "coupled", seconds: float = 0.6) -> dict:
        scanner = _script(tmp_path, "scanner.py", scanner_body)
        monkeypatch.setattr(coupled_live, "scanner_command", lambda *a: [str(scanner)])
        args = argparse.Namespace(
            v1_bin=str(_script(tmp_path, "v1", FAKE_V2)), v2_bin=str(_script(tmp_path, "v2", FAKE_V2)),
            cpu=0, hogs=1, attacker_nice=-20, seconds=seconds, interval=0.01, repo=".",
        )
        return coupled_live.run_cell(args, "eevdf", condition)

    run.joined = joined
    return run


def test_window_skips_the_first_scan_and_lines_after_it_ends(cell):
    # First scan misses, scans in the window catch, scans after the window miss.
    row = cell(
        "import time\n"
        "print('scan 1 found=0 scan_ms= 0.30', flush=True)\n"
        "for i in range(10): time.sleep(0.02); print(f'scan {i+2} found=1 scan_ms= 0.30', flush=True)\n"
        "time.sleep(1.0)\n"
        "for i in range(5): print(f'scan {i+20} found=0 scan_ms= 0.30', flush=True)\n"
    )
    assert row["scans"] == 10 and row["catches"] == 10
    assert row["v2_faults"] == 7
    assert all(_gone(p) for p in cell.joined)


def test_scanner_that_crashes_before_scanning_raises_with_its_output(cell):
    with pytest.raises(RuntimeError, match="PermissionError: denied"):
        cell("import sys\nprint('PermissionError: denied', flush=True)\nsys.exit(1)\n")
    assert all(_gone(p) for p in cell.joined)


def test_scanner_that_stops_mid_window_raises(cell):
    # A scanner that quits early would otherwise read as a starved one.
    with pytest.raises(RuntimeError, match="target process gone"):
        cell(
            "print('scan 1 found=0 scan_ms= 0.30', flush=True)\n"
            "for i in range(3): print(f'scan {i+2} found=1 scan_ms= 0.30', flush=True)\n"
            "print('[scanner] target process gone', flush=True)\n"
        )
    assert all(_gone(p) for p in cell.joined), "attacker or hogs outlived a failed cell"


def test_children_die_with_the_harness(tmp_path):
    # SIGKILL skips every finally; PDEATHSIG still takes the children down.
    parent = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess, sys, time\n"
         "from detection.coupled_live import _child_setup\n"
         "c = subprocess.Popen(['sleep', '300'], preexec_fn=_child_setup(0))\n"
         "print(c.pid, flush=True); time.sleep(300)\n"],
        stdout=subprocess.PIPE, text=True,
    )
    child = int(parent.stdout.readline())
    parent.send_signal(signal.SIGKILL)
    parent.wait()
    assert _gone(child), "a child outlived the harness"


def test_out_file_with_other_columns_is_refused_before_any_cell(tmp_path):
    out = tmp_path / "coupled.csv"
    out.write_text("run_id,old_column\n1,2\n")
    with pytest.raises(SystemExit, match="different columns"):
        coupled_live.check_out(out)
    coupled_live.check_out(tmp_path / "new.csv")  # a new file is fine
