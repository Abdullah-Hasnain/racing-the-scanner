"""Stamp index.html's own CSS and JS links with a content hash (?v=...).

    python3 tools/stamp_assets.py

A browser that cached an older styles.css or script.js keeps using it even after the
HTML changes, so a new slide can render unstyled. A hash in the URL changes whenever
the file does, which makes the browser fetch it again. Rerun after editing styles.css,
script.js or assets/data/results.js. Standard library only.
"""
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ["styles.css", "script.js", "assets/data/results.js"]

html_path = ROOT / "index.html"
html = html_path.read_text(encoding="utf-8")
for asset in ASSETS:
    digest = hashlib.sha256((ROOT / asset).read_bytes()).hexdigest()[:10]
    html, n = re.subn(rf'(["\']){re.escape(asset)}(?:\?v=[0-9a-f]+)?\1', rf"\g<1>{asset}?v={digest}\g<1>", html)
    if n != 1:
        raise SystemExit(f"expected one link to {asset} in index.html, found {n}")
    print(f"{asset}?v={digest}")
html_path.write_text(html, encoding="utf-8")
