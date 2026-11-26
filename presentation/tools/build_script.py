"""Write SCRIPT.md, the full spoken script, from the speaker notes in index.html.

    python3 tools/build_script.py [--wpm 140]

Each slide's notes open with a cue line ("0:50 · Presenter: ..."), then the script,
then a "Transition:" line. The table adds up the planned times and, separately,
estimates each slide's time from its word count at a normal speaking pace, so the
15-minute limit is checked against what is actually written, not only the plan.
Stage directions in [square brackets] are not counted. Standard library only.
"""
import argparse
import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class Notes(HTMLParser):
    """Collects, per leaf <section>, the kicker, the title and the notes paragraphs."""

    def __init__(self):
        super().__init__()
        self.slides, self.depth, self.cur = [], 0, None
        self.field, self.buf, self.in_notes, self.pclass = None, [], False, None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        cls = a.get("class", "") or ""
        if tag == "section":
            self.depth += 1
            self.cur = {"kicker": "", "crumb": a.get("data-crumb", ""), "title": "", "paras": []}
            self.slides.append(self.cur)
        elif self.cur is None:
            return
        elif tag == "div" and "kicker" in cls.split() and not self.in_notes:
            self.field, self.buf = "kicker", []
        elif tag in ("h1", "h2") and not self.in_notes and not self.cur["title"]:
            self.field, self.buf = "title", []
        elif tag == "aside" and "notes" in cls:
            self.in_notes = True
        elif tag == "p" and self.in_notes:
            self.field, self.buf, self.pclass = "para", [], cls
        elif tag == "br" and self.field:
            self.buf.append(" ")

    def handle_endtag(self, tag):
        if tag == "section":
            self.depth -= 1
        elif tag == "span" and self.field == "kicker":
            self.buf.append(" · ")
        elif tag == "aside" and self.in_notes:
            self.in_notes = False
        elif self.field == "kicker" and tag == "div" or self.field == "title" and tag in ("h1", "h2"):
            self.cur[self.field] = " ".join("".join(self.buf).split())
            self.field = None
        elif self.field == "para" and tag == "p":
            self.cur["paras"].append((self.pclass, " ".join("".join(self.buf).split())))
            self.field = None

    def handle_data(self, data):
        if self.field:
            self.buf.append(data)


def mmss(sec):
    return f"{int(sec // 60)}:{int(round(sec % 60)):02d}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wpm", type=float, default=140.0)
    args = ap.parse_args()

    parser = Notes()
    parser.feed((ROOT / "index.html").read_text(encoding="utf-8"))
    slides = [s for s in parser.slides if s["paras"]]  # leaf slides with notes (the Results stack wrapper has none)

    rows, body, planned_total, est_total = [], [], 0.0, 0.0
    for n, s in enumerate(slides, 1):
        cue = next((t for c, t in s["paras"] if c == "cue"), "")
        m = re.match(r"(\d+):(\d{2})", cue)
        planned = int(m.group(1)) * 60 + int(m.group(2)) if m else 0
        timed = planned > 0  # References (0:00) and Q&A are not part of the talk
        presenter = re.search(r"Presenter: ([^·(]+)", cue)
        presenter = presenter.group(1).strip() if presenter else "-"
        spoken = [t for c, t in s["paras"] if c not in ("cue", "next", "qa-note")]
        qa = [t for c, t in s["paras"] if c == "qa-note"]  # backup answers: not part of the talk
        transition = next((t for c, t in s["paras"] if c == "next"), "")
        words = len(re.sub(r"\[[^\]]*\]", " ", " ".join(spoken + [transition.replace("Transition:", "")])).split()) if timed else 0
        est = words / args.wpm * 60
        planned_total += planned
        est_total += est
        label = s["kicker"] or s["crumb"] or "Title"
        short = s["title"] if len(s["title"]) <= 52 else s["title"][:50].rstrip() + "…"
        rows.append(f"| {n} | {label}: {short} | {presenter} | {mmss(planned) if timed else 'not timed'} | {words or '-'} | {mmss(est) if timed else '-'} | {mmss(est_total) if timed else '-'} |")
        body.append(f"## {n}. {label}: {s['title']}\n\n*{cue}*\n")
        body.extend(f"{t}\n" for t in spoken)
        if transition:
            body.append(f"> {transition}\n")
        if qa:
            body.append("**Q&A backup (not timed)**\n")
            body.extend(f"- {t}\n" for t in qa)

    out = [
        "# Racing the Scanner: the 15-minute script",
        "",
        "Generated from the speaker notes in `index.html` by `tools/build_script.py`; edit the notes, then rerun.",
        f"Planned: **{mmss(planned_total)}**. Estimated from the words at {args.wpm:.0f} words per minute: **{mmss(est_total)}**.",
        "Q&A and the appendix slides are not timed. Stage directions such as [click] are not counted.",
        "",
        "| # | Slide | Presenter | Planned | Words | Est. | Cumulative |",
        "|---|---|---|---|---|---|---|",
        *rows,
        "",
        *body,
    ]
    (ROOT / "SCRIPT.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"SCRIPT.md: {len(slides)} slides, planned {mmss(planned_total)}, estimated {mmss(est_total)} at {args.wpm:.0f} wpm")


if __name__ == "__main__":
    main()
