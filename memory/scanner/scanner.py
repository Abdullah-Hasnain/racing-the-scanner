"""D1: live RAM scanner.

Reads a target process's writable anonymous regions from /proc/<pid>/maps and
scans /proc/<pid>/mem for the YARA marker, at a configurable interval. Logs,
per scan, whether the marker was found and how long the scan took. The point of
the project is that this catches V1 easily, catches V2/V3 only if it scans
during an exposure window, and never catches V4 (secret memory is unreadable).

Linux only (it reads /proc). Needs permission to read the target's memory
(same user, or root).

Uses yara-python if installed; otherwise falls back to a plain byte search so
the module works with zero extra dependencies.

Usage:
  sudo python scanner.py --pid 12345 --interval 0.1 --duration 30
"""

from __future__ import annotations

import argparse
import re
import time
from pathlib import Path

MARKER = b"RTS_SECRET_MARKER_v1"

try:
    import yara  # type: ignore
    _HAVE_YARA = True
except Exception:
    _HAVE_YARA = False


def _readable_regions(pid: int) -> list[tuple[int, int]]:
    """Return (start, end) of readable, writable, anonymous regions."""
    regions = []
    maps = Path(f"/proc/{pid}/maps").read_text()
    for line in maps.splitlines():
        # e.g. "7f...-7f... rw-p 00000000 00:00 0   [heap]"
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})", line)
        if not m:
            continue
        perms = m.group(3)
        if "r" in perms and "w" in perms:
            regions.append((int(m.group(1), 16), int(m.group(2), 16)))
    return regions


def _scan_once(pid: int, rule) -> bool:
    found = False
    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for start, end in _readable_regions(pid):
            try:
                mem.seek(start)
                chunk = mem.read(end - start)
            except (OSError, ValueError, OverflowError):
                continue  # region vanished or is unreadable right now
            if rule is not None:
                if rule.match(data=chunk):
                    found = True
                    break
            elif MARKER in chunk:
                found = True
                break
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description="Live RAM scanner (D1)")
    ap.add_argument("--pid", type=int, required=True)
    ap.add_argument("--interval", type=float, default=0.1, help="seconds between scans")
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--rule", default=str(Path(__file__).parent / "rules" / "test.yar"))
    args = ap.parse_args()

    rule = None
    if _HAVE_YARA and Path(args.rule).exists():
        rule = yara.compile(filepath=args.rule)
    else:
        print("[scanner] yara not available; using plain byte search")

    hits = total = 0
    t_end = time.time() + args.duration
    while time.time() < t_end:
        t0 = time.perf_counter()
        try:
            found = _scan_once(args.pid, rule)
        except FileNotFoundError:
            print("[scanner] target process gone")
            break
        dt = (time.perf_counter() - t0) * 1000.0
        total += 1
        hits += int(found)
        print(f"scan {total:>4}  found={int(found)}  scan_ms={dt:7.2f}")
        time.sleep(max(0.0, args.interval))

    if total:
        print(f"\ncatch rate: {hits}/{total} = {hits / total:.2%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
