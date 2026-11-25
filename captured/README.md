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

To refresh a file: run its producer, check the numbers, and copy the new CSV here
in the same PR that explains the change.
