"""Unit tests for the live RAM scanner (memory/scanner/scanner.py)."""

from __future__ import annotations

import csv
import errno
import io
import os
import random
import re
from pathlib import Path

import pytest

from memory.scanner import scanner

COUPLED_LIVE_SCAN_RE = re.compile(r"^scan\s+\d+\s+found=(\d)\s+scan_ms=\s*([\d.]+)")


class _FaultyMemStream:
    """Fake /proc/<pid>/mem stream backed by a sparse byte map and EIO page set."""

    def __init__(self, size: int, pages: dict[int, bytes], eio_pages: set[int]) -> None:
        self.size = size
        self.pages = pages
        self.eio_pages = eio_pages
        self.pos = 0
        self.read_calls = 0

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence != io.SEEK_SET:
            raise ValueError("only SEEK_SET supported")
        self.pos = offset
        return self.pos

    def read(self, n: int = -1) -> bytes:
        self.read_calls += 1
        if n <= 0:
            return b""
        start = self.pos
        end = min(self.size, start + n)
        if start >= end:
            return b""
        first_page = start // scanner.PAGE_SIZE
        last_page = (end - 1) // scanner.PAGE_SIZE
        for p in range(first_page, last_page + 1):
            if p in self.eio_pages:
                raise OSError(errno.EIO, "Input/output error")

        out = bytearray(end - start)
        for p in range(first_page, last_page + 1):
            page_data = self.pages.get(p)
            if page_data is None:
                continue
            p_start = p * scanner.PAGE_SIZE
            lo = max(start, p_start)
            hi = min(end, p_start + scanner.PAGE_SIZE)
            out[lo - start : hi - start] = page_data[lo - p_start : hi - p_start]
        self.pos = end
        return bytes(out)


def _marker_page() -> bytes:
    repeats = (scanner.PAGE_SIZE // len(scanner.MARKER)) + 1
    return (scanner.MARKER * repeats)[: scanner.PAGE_SIZE]


def test_shannon_entropy_known_distributions():
    assert scanner.shannon_entropy(b"") == 0.0
    assert scanner.shannon_entropy(b"\x00" * scanner.PAGE_SIZE) == 0.0
    assert scanner.shannon_entropy(b"A" * 100) == 0.0

    # "RTS_SECRET_MARKER_v1" has 11 distinct symbols -> ~3.2464 bits/byte.
    assert scanner.shannon_entropy(scanner.MARKER) == pytest.approx(3.2464, abs=0.01)

    page = _marker_page()
    xored = bytes(b ^ 0x5A for b in page)
    assert scanner.shannon_entropy(page) == pytest.approx(3.25, abs=0.02)
    assert scanner.shannon_entropy(xored) == pytest.approx(scanner.shannon_entropy(page), abs=1e-9)

    # Both the non-4096 dynamic fallback (256 B) and 4096 B LUT path must yield 8.0.
    assert scanner.shannon_entropy(bytes(range(256))) == pytest.approx(8.0)
    assert scanner.shannon_entropy(bytes(range(256)) * 16) == pytest.approx(8.0)

    prng_page = random.Random(0).randbytes(scanner.PAGE_SIZE)
    assert scanner.shannon_entropy(prng_page) > 7.8


def test_parse_maps_filters_anonymous_rw_and_secretmem():
    maps_text = "\n".join(
        [
            "555555554000-555555556000 r-xp 00000000 08:01 100  /app/v2",
            "555555558000-555555559000 rw-p 00003000 08:01 100  /app/v2",
            "555555600000-555555621000 rw-p 00000000 00:00 0    [heap]",
            "7f1000000000-7f1000100000 ---p 00000000 00:00 0",
            "7f1000100000-7f1000200000 rw-p 00000000 00:00 0",
            "7f1000200000-7f1000300000 r--p 00000000 00:00 0",
            "7f1000300000-7f1000400000 rw-s 00000000 00:0f 200  anon_inode:secretmem",
            "7f1000400000-7f1000410000 rw-s 00000000 00:01 201  /memfd:payload (deleted)",
            "7f1000500000-7f1000504000 rw-p 001e0000 08:01 300  /usr/lib/x86_64-linux-gnu/libc.so.6",
            "7ffffffdd000-7ffffffff000 rw-p 00000000 00:00 0    [stack]",
        ]
    )
    regs = scanner._parse_maps(maps_text)
    pathnames = [r.pathname for r in regs]
    assert pathnames == [
        "[heap]",
        "",
        "anon_inode:secretmem",
        "/memfd:payload (deleted)",
        "[stack]",
    ]
    assert regs[2].is_secretmem is True
    assert regs[0].is_secretmem is False


def test_scan_stream_marker_and_entropy_modes():
    marker_buf = bytearray(scanner.PAGE_SIZE * 2)
    marker_buf[100 : 100 + len(scanner.MARKER)] = scanner.MARKER
    regs = [scanner.Region(0, len(marker_buf), "rw-p", "")]
    res = scanner._scan_stream(regs, io.BytesIO(marker_buf))
    assert res.marker_found is True
    assert res.entropy_flagged is False
    assert res.found is True
    assert res.pages_scanned == 2
    assert res.bytes_scanned == len(marker_buf)

    encrypted = random.Random(42).randbytes(scanner.PAGE_SIZE)
    enc_buf = b"\x00" * scanner.PAGE_SIZE + encrypted
    regs_enc = [scanner.Region(0, len(enc_buf), "rw-p", "")]
    res_catch = scanner._scan_stream(regs_enc, io.BytesIO(enc_buf), catch_on_entropy=True)
    assert res_catch.marker_found is False
    assert res_catch.entropy_flagged is True
    assert res_catch.high_entropy_pages == 1
    assert res_catch.max_entropy > 7.8
    assert res_catch.found is True

    res_nocatch = scanner._scan_stream(regs_enc, io.BytesIO(enc_buf), catch_on_entropy=False)
    assert res_nocatch.entropy_flagged is True
    assert res_nocatch.found is False


def test_scan_stream_chunk_overlap_preserves_page_alignment():
    size = 2 * scanner.CHUNK_SIZE
    buf = bytearray(size)
    # Straddle the 1 MiB chunk boundary with MARKER (not high entropy).
    split_pos = scanner.CHUNK_SIZE - 7
    buf[split_pos : split_pos + len(scanner.MARKER)] = scanner.MARKER
    # Place a single high-entropy 4 KB page at exact start of chunk 2.
    buf[scanner.CHUNK_SIZE + scanner.PAGE_SIZE : scanner.CHUNK_SIZE + 2 * scanner.PAGE_SIZE] = (
        random.Random(7).randbytes(scanner.PAGE_SIZE)
    )

    regs = [scanner.Region(0, size, "rw-p", "")]
    res = scanner._scan_stream(regs, io.BytesIO(buf))
    assert res.marker_found is True
    assert res.bytes_scanned == size
    assert res.pages_scanned == size // scanner.PAGE_SIZE
    assert res.high_entropy_pages == 1
    assert res.max_entropy > 7.9


def test_scan_stream_eio_fallback_and_secretmem_skip():
    # Page 0 raises EIO, page 3 holds MARKER -> fallback recovers page 3.
    size = 4 * scanner.PAGE_SIZE
    stream = _FaultyMemStream(size=size, pages={3: _marker_page()}, eio_pages={0})
    reg = scanner.Region(0, size, "rw-p", "")
    res = scanner._scan_stream([reg], stream)
    assert res.marker_found is True
    assert res.found is True
    assert res.pages_scanned == 3
    assert res.bytes_scanned == 3 * scanner.PAGE_SIZE

    # Discontiguous pages across an EIO gap must NOT concatenate into a false marker hit.
    split = 10
    p0 = bytearray(scanner.PAGE_SIZE)
    p0[-split:] = scanner.MARKER[:split]
    p2 = bytearray(scanner.PAGE_SIZE)
    p2[: len(scanner.MARKER) - split] = scanner.MARKER[split:]
    gap_stream = _FaultyMemStream(size=3 * scanner.PAGE_SIZE, pages={0: bytes(p0), 2: bytes(p2)}, eio_pages={1})
    res_gap = scanner._scan_stream([scanner.Region(0, 3 * scanner.PAGE_SIZE, "rw-p", "")], gap_stream)
    assert res_gap.marker_found is False
    assert res_gap.pages_scanned == 2

    # V4 anon_inode:secretmem must skip per-page fallback after bulk EIO.
    secret_stream = _FaultyMemStream(size=size, pages={}, eio_pages={0, 1, 2, 3})
    secret_reg = scanner.Region(0, size, "rw-s", "anon_inode:secretmem")
    res_secret = scanner._scan_stream([secret_reg], secret_stream)
    assert secret_stream.read_calls == 1
    assert res_secret.found is False
    assert res_secret.pages_scanned == 0


def test_percentiles_linear_interpolation():
    vals = [10.0, 2.0, 4.0, 4.0]
    assert scanner.percentile(vals, 50.0) == pytest.approx(4.0)
    assert scanner.percentile(vals, 95.0) == pytest.approx(9.1)
    assert scanner.percentile(vals, 99.0) == pytest.approx(9.82)
    assert scanner.percentile([5.5], 50.0) == pytest.approx(5.5)
    assert scanner.percentile([5.5], 99.0) == pytest.approx(5.5)
    with pytest.raises(ValueError):
        scanner.percentile([], 50.0)


def test_main_writes_and_appends_csvs_and_matches_stdout(monkeypatch, tmp_path, capsys):
    runs = iter(
        [
            iter(
                [
                    (scanner.ScanResult(True, True, False, 3.25, 0, 10, 40960), 0.002),
                    (scanner.ScanResult(False, False, False, 0.0, 0, 10, 40960), 0.004),
                    (scanner.ScanResult(True, False, True, 7.95, 1, 10, 40960), 0.010),
                    (scanner.ScanResult(False, False, False, 1.5, 0, 10, 40960), 0.004),
                ]
            ),
            iter(
                [
                    (scanner.ScanResult(True, True, False, 3.25, 0, 4, 16384), 0.003),
                ]
            ),
        ]
    )
    current_run = next(runs)
    clock = [0.0]

    def fake_perf_counter() -> float:
        return clock[0]

    def fake_monotonic() -> float:
        return clock[0]

    def fake_scan_once(*_args, **_kwargs) -> scanner.ScanResult:
        try:
            res, dt_s = next(current_run)
        except StopIteration:
            raise FileNotFoundError from None
        clock[0] += dt_s
        return res

    monkeypatch.setattr(scanner, "_scan_once", fake_scan_once)
    monkeypatch.setattr(scanner.time, "perf_counter", fake_perf_counter)
    monkeypatch.setattr(scanner.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(scanner.time, "sleep", lambda _s: None)

    rc1 = scanner.main(
        [
            "--pid",
            "1234",
            "--interval",
            "0.05",
            "--duration",
            "10.0",
            "--variant",
            "v2",
            "--dwell-ms",
            "10",
            "--out-dir",
            str(tmp_path),
        ]
    )
    assert rc1 == 0

    out1 = capsys.readouterr().out
    scan_lines = [line for line in out1.splitlines() if line.startswith("scan ")]
    assert len(scan_lines) == 4
    for line in scan_lines:
        assert COUPLED_LIVE_SCAN_RE.match(line)

    current_run = next(runs)
    rc2 = scanner.main(
        [
            "--pid",
            "5678",
            "--interval",
            "0.05",
            "--duration",
            "10.0",
            "--variant",
            "v1",
            "--out-dir",
            str(tmp_path),
        ]
    )
    assert rc2 == 0
    capsys.readouterr()

    scans_path = tmp_path / "scanner_scans.csv"
    summary_path = tmp_path / "scanner_summary.csv"
    with scans_path.open("r", newline="", encoding="utf-8") as f:
        scan_rows = list(csv.DictReader(f))
    with summary_path.open("r", newline="", encoding="utf-8") as f:
        summary_rows = list(csv.DictReader(f))

    assert len(scan_rows) == 5
    assert list(scan_rows[0].keys()) == scanner.SCANS_FIELDS
    assert scan_rows[3]["p50_scan_ms"] == "4.0"
    assert float(scan_rows[3]["p95_scan_ms"]) == pytest.approx(9.1)
    assert float(scan_rows[3]["p99_scan_ms"]) == pytest.approx(9.82)

    assert len(summary_rows) == 2
    assert list(summary_rows[0].keys()) == scanner.SUMMARY_FIELDS
    assert summary_rows[0]["run_id"] != summary_rows[1]["run_id"]
    assert summary_rows[0]["scans"] == "4"
    assert summary_rows[0]["catches"] == "2"
    assert summary_rows[0]["marker_catches"] == "1"
    assert summary_rows[0]["entropy_catches"] == "1"
    assert float(summary_rows[0]["catch_rate"]) == pytest.approx(0.5)
    assert float(summary_rows[0]["miss_rate"]) == pytest.approx(0.5)
    assert float(summary_rows[0]["p50_scan_ms"]) == pytest.approx(4.0)
    assert float(summary_rows[0]["p95_scan_ms"]) == pytest.approx(9.1)
    assert float(summary_rows[0]["p99_scan_ms"]) == pytest.approx(9.82)


def test_main_zero_scans_no_csv_and_header_mismatch(monkeypatch, tmp_path):
    # Immediate exit -> 0 scans must not raise ZeroDivisionError or create CSVs.
    monkeypatch.setattr(scanner, "_scan_once", lambda *_a, **_kw: (_ for _ in ()).throw(FileNotFoundError()))
    out_zero = tmp_path / "zero"
    rc = scanner.main(["--pid", "9999", "--out-dir", str(out_zero)])
    assert rc == 0
    assert not (out_zero / "scanner_scans.csv").exists()
    assert not (out_zero / "scanner_summary.csv").exists()

    # --no-csv skips CSV creation even when scans occur.
    monkeypatch.setattr(
        scanner,
        "_scan_once",
        lambda *_a, **_kw: scanner.ScanResult(True, True, False, 3.25, 0, 1, 4096),
    )
    calls = [0]

    def adv_mono() -> float:
        calls[0] += 1
        return 0.0 if calls[0] <= 2 else 1.0

    monkeypatch.setattr(scanner.time, "monotonic", adv_mono)
    out_nocsv = tmp_path / "nocsv"
    assert scanner.main(["--pid", "111", "--duration", "0.5", "--no-csv", "--out-dir", str(out_nocsv)]) == 0
    assert not out_nocsv.exists()

    # Mismatched CSV header fails cleanly with exit code 2.
    bad_dir = tmp_path / "bad"
    bad_dir.mkdir()
    (bad_dir / "scanner_scans.csv").write_text("wrong,columns\n1,2\n", encoding="utf-8")
    assert scanner.main(["--pid", "111", "--out-dir", str(bad_dir)]) == 2


def test_ensure_parent_dir_only_chowns_new_dirs(monkeypatch, tmp_path):
    chowned: list[Path] = []
    monkeypatch.setattr(scanner, "_caller_ugid", lambda: (1000, 1000))
    monkeypatch.setattr(os, "chown", lambda p, _u, _g: chowned.append(Path(p)), raising=False)

    nested = tmp_path / "a" / "b" / "file.csv"
    scanner._ensure_parent_dir(nested)
    assert nested.parent.is_dir()
    assert chowned == [tmp_path / "a", tmp_path / "a" / "b"]
    assert tmp_path not in chowned
