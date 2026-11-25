# Report format reference

`sample-wajid.pdf` is the instructor's own sample (Dr. Bilal Wajid, "The Temporal
Cost of Cognition: Evaluating Agentic LLMs and Cyber Resilience in Local EDR").
It is a FORMAT and RIGOR reference only. Do not copy its wording, its experiments,
or its numbers. Our report is about our own, different system (a live RAM scanner,
a scheduler simulation across ~15 ML policies and reservations, and real-kernel
sched_ext validation against a memory-hiding + mimicry-starvation attack).

## Format to match
- IEEE conference style, two columns, roughly 4 to 5 pages.
- Title, author(s), affiliation (Dhanani School of Science & Engineering, Habib
  University, Karachi).
- Abstract: one dense paragraph (~200 words) that states the headline result in
  numbers, then Keywords.
- Numbered sections: I. Introduction, II. Methods (with lettered subsections),
  III. Results (lettered subsections, each anchored by a figure), IV. Discussion,
  V. Conclusion and Future Work, References (IEEE numbered, ~8-10 entries).
- Figures are small, captioned bar/line/stacked charts referenced by number with
  a one-line takeaway in the text.

## Why it is a useful model (same arc as our result)
The sample's own thesis is strikingly close to ours: a defender daemon isolated by
scheduling, an attacker that camouflages itself to evade detection (100% evasion),
and the conclusion that deterministic isolation, not a smarter detector, is the
fail-safe. So our "reservation beats detection" finding is exactly the kind of
result the sample treats as strong. Use that arc; do not borrow its content.

## Mapping the sample's structure onto OUR work
- Attacker generations (Baseline / Camouflage / Proliferation) -> our V1-V4 hiding
  payloads and the mimicry-starvation attack.
- Isolated Blue Team daemon -> our live RAM scanner protected by a CPU reservation.
- Capability-vs-latency tradeoff -> detection (ML policies) vs its cost (G6 overhead).
- "100% evasion under camouflage" -> all ~15 ML policies miss under mimicry (AUC at
  or below chance), our core negative result.
- "Deterministic sandboxing is the fail-safe" -> a CPU reservation sidesteps the
  detection arms race; the invariant is one standard instance (cgroup cpu.weight,
  SCHED_DEADLINE), validated on a real kernel.
- Their Figs 1-4 -> our G1-G6, built from `main` via `analysis/make_graphs.py`.

## Hard rule
Every number, figure and claim in our report must be traceable to this repository
(the merged code, docs/, captured/ CSVs, and the regenerated G1-G6). The sample
sets the shape; the repo sets the content.
