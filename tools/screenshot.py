"""Render docs/demo.png (terminal) and docs/report.png (HTML report) from real runs on the examples.

pip install -e ".[dev]" && playwright install chromium
python tools/screenshot.py
"""

from __future__ import annotations

import contextlib
import html
import io
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mailhdr import cli

EX = ROOT / "examples"
COMMON = ["--zone", str(EX / "zone.json"), "--brands", str(EX / "brands.txt")]


def run(*argv: str) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli.main([*argv, *COMMON])
    return buffer.getvalue()


def colour(text: str) -> str:
    text = html.escape(text)
    text = re.sub(
        r"\[(HIGH  |MEDIUM|LOW   |INFO  )\]",
        lambda m: f'[<span class="{m.group(1).strip().lower()}">{m.group(1)}</span>]',
        text,
    )
    text = re.sub(r"^(VERDICT  )(HIGH.*)$", r'\1<span class="high">\2</span>', text, flags=re.M)
    text = re.sub(r"^(VERDICT  )(MEDIUM.*)$", r'\1<span class="medium">\2</span>', text, flags=re.M)
    text = re.sub(r"^(VERDICT  )(LOW.*)$", r'\1<span class="ok">\2</span>', text, flags=re.M)
    text = re.sub(r"\b(DKIM|SPF|DMARC)(\s+)(pass)\b", r'\1\2<span class="ok">\3</span>', text)
    text = re.sub(r"\b(DKIM|SPF|DMARC)(\s+)(fail)\b", r'\1\2<span class="high">\3</span>', text)
    text = re.sub(r"^([A-Z][A-Z ()a-z,-]+)$", r'<span class="h">\1</span>', text, flags=re.M)
    return re.sub(r"^(\$ .*)$", r'<span class="cmd">\1</span>', text, flags=re.M)


def trim(report: str) -> str:
    """Drop the version line and the long explanation lines so the picture stays readable."""
    lines = [
        ln
        for ln in report.splitlines()[2:]
        if "was taken from" not in ln and "the IP was" not in ln and "checked: ip" not in ln
    ]
    return "\n".join(lines)


def main() -> None:
    cmd = "$ mailhdr analyze 03-lookalike-domain.eml"
    body = colour(cmd + "\n" + trim(run("analyze", str(EX / "03-lookalike-domain.eml"))))
    page = f"""<!doctype html><meta charset="utf-8"><style>
body{{margin:0;background:#0d1117}}
pre{{margin:0;padding:22px 26px;font:14px/1.45 ui-monospace,Menlo,Consolas,monospace;color:#c9d1d9;width:1040px;box-sizing:border-box}}
.high{{color:#ff7b72;font-weight:700}}.medium{{color:#e3b341}}.ok{{color:#7ee787;font-weight:700}}.low,.info{{color:#79c0ff}}.cmd{{color:#79c0ff}}.h{{color:#8b949e;font-weight:700}}
</style><pre>{body}</pre>"""
    html_report = run("analyze", str(EX / "02-spoofed-sender.eml"), "--format", "html")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        shot = browser.new_page(viewport={"width": 1040, "height": 400}, device_scale_factor=2)
        shot.set_content(page)
        shot.locator("pre").screenshot(path=str(ROOT / "docs" / "demo.png"))
        wide = browser.new_page(viewport={"width": 920, "height": 700}, device_scale_factor=2)
        wide.set_content(html_report)
        wide.screenshot(path=str(ROOT / "docs" / "report.png"), full_page=True)
        browser.close()
    print("wrote docs/demo.png and docs/report.png")


if __name__ == "__main__":
    main()
