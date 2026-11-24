"""The benign suite stops cleanly when the harness ends a live capture (#13).

harness.py --live sends run_benign.py SIGTERM after --seconds. The workload it
launched must not outlive it, and its build directory must be removed.
"""

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

RUN = Path(__file__).resolve().parents[1] / "benign" / "run_benign.py"


def _child_named(pid: int, comm: str, timeout: float = 30.0) -> int:
    """Wait for pid to have a running child process called comm; return its pid."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
        for child in children:
            try:
                if Path(f"/proc/{child}/comm").read_text().strip() == comm:
                    return int(child)
            except FileNotFoundError:
                pass  # the build step's gcc exited between the two reads
        time.sleep(0.05)
    raise AssertionError(f"no '{comm}' child of {pid} within {timeout}s")


@pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("gcc") is None,
    reason="malloc workload and /proc check need Linux + gcc",
)
def test_sigterm_stops_the_workload_and_removes_its_build(tmp_path):
    env = {**os.environ, "TMPDIR": str(tmp_path)}
    driver = subprocess.Popen(
        [sys.executable, str(RUN), "--workload", "malloc", "--seconds", "60"], env=env
    )
    try:
        workload = _child_named(driver.pid, "malloc_churn")
        driver.send_signal(signal.SIGTERM)
        assert driver.wait(timeout=10) == 128 + signal.SIGTERM
        assert not Path(f"/proc/{workload}").exists(), "workload outlived the driver"
        assert list(tmp_path.iterdir()) == [], "build directory left behind"
    finally:
        driver.kill()
