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
