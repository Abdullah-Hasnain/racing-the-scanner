# Racing the Scanner: the 15-minute presentation

The final-presentation deck for the Operating Systems course project (Habib University,
Fall 2026; instructor Dr. Bilal Wajid). Built with Reveal.js 5.1.0 and Chart.js 4.4.4.
Everything it needs, including the libraries and fonts, is in this folder, so it runs
offline in any modern browser.

## Run it

**Recommended: a local server.** This gives you the full speaker view.

```bash
cd presentation            # from the repo root
python3 -m http.server 8000
# open http://localhost:8000 in Chrome, Edge or Firefox
```

**Quick: double-click `index.html`.** The slides, charts and animations all work from
`file://`. Some browsers restrict the speaker-view popup from `file://`, so use the
server when presenting with notes.

## Presenting

**If a slide looks unstyled** (plain text, no layout), the browser is still using an old
cached `styles.css`. Reload once with Cmd+Shift+R (Ctrl+Shift+R on Windows). The links in
`index.html` carry a content hash, so this happens only with a copy from before the
hash was added. After editing `styles.css`, `script.js` or the data, run
`python3 tools/stamp_assets.py` to update the hashes.

| Key | Action |
|---|---|
| Space, Right or Down arrow | next (steps through every fragment, then every slide) |
| Left or Up arrow | previous |
| `S` | speaker view: notes, timer, the current and next slide (allow the popup) |
| `F` | full screen (`Esc` leaves) |
| `O` or `Esc` | slide overview |
| `B` or `.` | blank the screen |

Three slides build in steps: the research question (the two possible answers), the
race diagram (the starved row, then the punchline) and the conclusions (one takeaway
per click). The `[click]` marks in the notes show when.

**PDF backup.** Open `http://localhost:8000/?print-pdf` in Chrome, then Print, then Save
as PDF (landscape, margins None, background graphics on). That gives one page per slide
with every fragment shown. A ready-made copy is in `Racing-the-Scanner-slides.pdf`.

## What is in here

```
index.html                   the slides and the speaker notes (<aside class="notes">)
styles.css                   layout, typography, palette
script.js                    Reveal.js setup and the eight Chart.js figures
SCRIPT.md                    the full 15-minute script with a timing table (generated)
assets/results.js       every charted number (generated, see below)
assets/vendor/               Reveal.js and Chart.js (with their licences)
assets/fonts/                Inter and Source Serif 4 (SIL Open Font Licence)
tools/extract_data.py        rebuilds assets/results.js from the repo
tools/build_script.py        rebuilds SCRIPT.md from the speaker notes
tools/stamp_assets.py        stamps the CSS/JS links with a content hash (?v=...)
```

## Where the numbers come from

No number on a chart is typed in by hand. `tools/extract_data.py` reads the same sources
as the report: `captured/g1_scan.csv`, `g2_pareto.csv`, `coupled_live.csv` and
`detection_g5.csv`, plus the simulation results `results/aggregate_g3.csv` and
`aggregate_mimicry.csv` that `scripts/run_demo.sh` regenerates. To refresh after a
new run:

```bash
# in the repo: scripts/run_demo.sh   (regenerates results/)
../.venv/bin/python tools/extract_data.py .. ../results   # from presentation/
```

The numbers in slide text and notes (titles, takeaways, the `sched_ext` table) match
the report (`report/main.tex`) and `docs/`. Each slide's footer names its source.

## The script and timing

The speaker notes are the script. Each one opens with a cue line (planned time and
speaker block), then the spoken text with `[click]` marks where a fragment advances, then
the transition to the next slide. `python3 tools/build_script.py` collects them into
`SCRIPT.md`:
- **Planned:** 14:20.
- **Estimated from the words written:** 14:19 at 140 words per minute.

The table at the top of `SCRIPT.md` is the source for both; rerun the tool after
editing the notes.

Q&A and the appendix are extra. The backup answers for likely questions sit in the
conclusions slide's notes.

The talk splits into three speaker blocks, labelled M1, M2 and M3 in the notes; assign
people as you like:
- **M1** (slides 1–5, about 5:15): title, the research question, the race, the two
  defences, hiding.
- **M2** (slides 6–9, about 5:20): the main result, why detection fails, cost, the real
  kernel.
- **M3** (slides 10–12, about 3:45): detection, the evidence map, conclusions.

## Structure and design decisions

- **Twelve main slides, then references and an appendix.** The main slides tell one
  argument: the question in plain words, the race, the two defences, hiding, the main result, why, cost, the real kernel,
  detection, honest scope, conclusions. Supporting material moved to appendix slides A–F,
  ready for Q&A: prior work, method, the system, the simulation slowdown with the ML
  policies (G3), the `sched_ext` table, and future work.
- **Visual first.** Each main slide is a figure plus a few big numbers, not bullets:
  - group labels drawn on the charts ("0% miss", "100% miss", "11 of 14");
  - a sketch of why the mimic looks benign;
  - a rule-to-payload map for detection;
  - a tested / partly / not-tested matrix for limitations.
- **A breadcrumb replaces the roadmap slide.** Problem, Hiding, Simulation, Real kernel,
  Detection and Conclusions run along the top of every content slide, and a badge names
  the testbed behind each result.
- **The real-kernel slide follows the report's G3:** solid bars for the simulation,
  hatched bars for bare metal. `sched_ext` is one line there, with its table in
  Appendix E.
- **Every content title states its takeaway,** so the titles alone tell the argument.
- **Colour carries meaning, consistently:** blue for reservations, orange for the
  detection (ML) policies, gray for stock EEVDF, navy for structure.
- **Typography:** Source Serif 4 for titles and Inter for text and charts. Both are
  bundled, so the deck looks the same on the classroom machine.
- **Charts are drawn live from the data** and animate once when their slide first
  appears.
- **Citations are IEEE numbered**, as the report uses (`report/reference/FORMAT.md`
  sets IEEE). They are numbered in order of first appearance, and each slide names its
  data source in the footer.
- **The conclusions slide stays up during questions,** with the three takeaways and the
  contact line on screen.
