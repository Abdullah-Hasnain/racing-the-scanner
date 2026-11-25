# Captured data

Small scored CSVs for the figures that need root or a real kernel to produce, so
`scripts/run_demo.sh` draws every figure on a fresh clone without root, Tracee or
Ollama (#44). This is the one deliberate exception to "don't commit `results/`".

`analysis/make_graphs.py` reads `results/<name>` first and falls back to
`captured/<name>`, so a fresh run (`scripts/run_demo.sh --live`) always wins.
Only scored CSVs go here, never raw Tracee logs (those are GBs).

| file | figure | how it was made |
|---|---|---|
| `coupled_live.csv` | G3 (real-kernel bars) | `detection/coupled_live.py` (#34) as root on Ibad's desktop, i7-14700F bare metal, kernel 7.0.0-44, everything pinned to CPU 2 (a P-core), attacker at nice -20, 4 hogs, scanner interval 37 ms, 3 reps x 20 s per cell, at commit 0fde0f5 (scanner with `--no-entropy`, harness off the measured core), run `20261125-151359`. It replaces run `20261124-231045`, which lost fewer EEVDF scans; see the note under the table in `detection/README.md` |
| `detection_g5.csv` | G5, G6b | the 5-batch held-out capture from #32: Tracee v0.23.2 on the same desktop, each batch V2 (timing varied), V3 and V4 against node, Go GC, Java GC, malloc churn, sqlite and a JIT stand-in, scored once with llama3.1:8b |
| `g1_scan.csv` | G1 | `sudo .venv/bin/python -m memory.sweep_g1 --strict --intervals 0.037 0.137 0.537 1.537 5.037` (#50; these are now also the defaults) as root on Ibad's desktop, i7-14700F bare metal, kernel 7.0.0-44-generic, payload and scanner pinned to CPU 2, scanner `--no-entropy`, at commit 7b4fdab, 2026-11-26. V2/V3 dwell 1/5/10/25 ms at one touch per 100 ms (`seq`), 3 reps x 10 s per cell (20 s at the 5 s interval), 150 rows. Scan intervals 0.037/0.137/0.537/1.537/5.037 s, not #38's 0.05/0.15/0.5/1.5/5 s: those are multiples of 50 ms, so with V2/V3's 100 ms cycle every scan hit the same phase and per-scan catch rates read 0 to 0.86 for at most 25% exposure. Each new interval is 37 ms past a multiple of 100 ms, as in #34, so scans step through the whole cycle. At 1.537 s and 5.037 s a run gets only 7 and 4 scans, so those points are coarse |
| `g2_pareto.csv` | G2 | `sudo .venv/bin/python -m memory.sweep_g2 --strict` (#52) on the same desktop, pinning and commit, 2026-11-26. Cost pass: 5 s tight loop with no scanner (slowdown vs V1 from the same rep, payload `faults`, `/proc` `minflt`). Evasion pass: 5 s at one touch per 100 ms with the scanner every 37 ms. V2/V3 dwell 1/5/10/25 ms, 3 reps, 30 rows |

To refresh a file: run its producer, check the numbers, and copy the new CSV here
in the same PR that explains the change.
