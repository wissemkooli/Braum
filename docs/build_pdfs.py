#!/usr/bin/env python3
"""Render the submission documents to PDF.

    uv run --with markdown --with pygments python docs/build_pdfs.py

Markdown -> styled HTML -> headless Chromium. Figures are the SVGs in
docs/figures/ (regenerate with docs/figures/make_figures.py). Output: docs/pdf/.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys

import markdown

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "pdf")
WORK = os.path.join(ROOT, ".pdfbuild")

# (source, output name, running title)
DOCUMENTS = [
    ("docs/TECHNICAL_REPORT.md", "SENTINEL_Technical_Report", "SENTINEL · Technical report"),
    ("docs/SAFETY.md", "SENTINEL_Responsible_AI_and_Safety", "SENTINEL · Responsible AI and safety"),
    ("README.md", "SENTINEL_Overview_README", "SENTINEL · Overview"),
    ("docs/QWEN3_AGENT.md", "SENTINEL_Qwen3-8B_Evaluation", "SENTINEL · Qwen3-8B evaluation"),
    ("docs/OFFICIAL_HARNESS.md", "SENTINEL_Official_Harness", "SENTINEL · Official harness"),
    ("docs/ARCHITECTURE.md", "SENTINEL_Architecture", "SENTINEL · Architecture"),
    ("docs/VIDEO_SCRIPT.md", "SENTINEL_Video_Shot_List", "SENTINEL · Video shot list"),
]
PDF_NAMES = {os.path.basename(src): name + ".pdf" for src, name, _ in DOCUMENTS}

CSS = """
@page { size: A4; margin: 19mm 17mm 20mm 17mm;
        @bottom-center { content: counter(page) " / " counter(pages); font: 8.5pt Helvetica, Arial, sans-serif; color: #8a8983; }
        @top-right { content: "%(running)s"; font: 8.5pt Helvetica, Arial, sans-serif; color: #8a8983; } }
@page :first { @top-right { content: ""; } }
html { font: 10.2pt/1.5 Georgia, 'DejaVu Serif', 'Liberation Serif', serif; color: #0b0b0b; }
body { margin: 0; }
h1, h2, h3, h4, th, .meta { font-family: Helvetica, Arial, 'Liberation Sans', 'DejaVu Sans', sans-serif; }
h1 { font-size: 21pt; line-height: 1.2; margin: 0 0 4pt; letter-spacing: -0.2pt; }
h1 + p em:only-child, h1 + p > em { color: #52514e; }
h2 { font-size: 14pt; margin: 22pt 0 7pt; padding-top: 9pt; border-top: 1.2pt solid #0b0b0b; break-after: avoid; }
h3 { font-size: 11.5pt; margin: 16pt 0 5pt; break-after: avoid; }
h4 { font-size: 10.2pt; margin: 13pt 0 4pt; color: #2a2a28; break-after: avoid; }
p, ul, ol { margin: 0 0 7.5pt; } li { margin-bottom: 2.5pt; } ul, ol { padding-left: 17pt; }
p { orphans: 3; widows: 3; }
a { color: #1f5fae; text-decoration: none; }
hr { display: none; }   /* h2 already draws the section rule */
code { font: 8.7pt/1.4 'DejaVu Sans Mono', 'Liberation Mono', Menlo, monospace; background: #f3f2ee; padding: 0.5pt 2.5pt; border-radius: 2pt; overflow-wrap: break-word; }
pre { background: #f6f5f2; border: 0.6pt solid #e2e1dc; border-radius: 4pt; padding: 7pt 9pt; margin: 0 0 9pt; white-space: pre-wrap; overflow-wrap: anywhere; break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 8.1pt; }
blockquote { margin: 0 0 9pt; padding: 3pt 0 3pt 11pt; border-left: 2.2pt solid #2a78d6; color: #2a2a28; }
blockquote p:last-child { margin-bottom: 0; }
blockquote h2 { border: 0; padding: 0; margin: 2pt 0; font-size: 15pt; }
table { border-collapse: collapse; width: 100%%; margin: 3pt 0 11pt; font-size: 8.6pt; line-height: 1.35; }
th { text-align: left; font-size: 8.2pt; color: #52514e; border-bottom: 1pt solid #0b0b0b; padding: 3.5pt 5pt; vertical-align: bottom; }
td { border-bottom: 0.5pt solid #e2e1dc; padding: 3.5pt 5pt; vertical-align: top; }
tr { break-inside: avoid; } thead { display: table-header-group; }
td code, th code { font-size: 7.8pt; }
td code { overflow-wrap: break-word; }
img { display: block; max-width: 100%%; height: auto; margin: 9pt auto 11pt; break-inside: avoid; }
p:has(> img) { break-inside: avoid; }
"""


def link_to_pdf(match: re.Match) -> str:
    target, anchor = match.group(1), match.group(2) or ""
    name = PDF_NAMES.get(os.path.basename(target))
    return f'href="{name}{anchor}"' if name else match.group(0)


def render(src: str, name: str, running: str, chromium: str) -> str:
    with open(os.path.join(ROOT, src), "r", encoding="utf-8") as fh:
        text = fh.read()
    body = markdown.markdown(text, extensions=["tables", "fenced_code", "sane_lists", "toc", "attr_list"])
    body = re.sub(r'href="([^"#:]+\.md)(#[^"]*)?"', link_to_pdf, body)
    # Images resolve against the source file's directory.
    base = "file://" + os.path.dirname(os.path.join(ROOT, src)) + "/"
    html = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{running}</title>'
            f'<base href="{base}"><style>{CSS % {"running": running}}</style></head><body>{body}</body></html>')
    page = os.path.join(WORK, name + ".html")
    with open(page, "w", encoding="utf-8") as fh:
        fh.write(html)
    pdf = os.path.join(OUT, name + ".pdf")
    subprocess.run([chromium, "--headless", "--no-sandbox", "--disable-gpu", "--no-pdf-header-footer",
                    f"--print-to-pdf={pdf}", "file://" + page],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
    return pdf


def main() -> int:
    chromium = next((c for c in ("chromium", "chromium-browser", "google-chrome") if shutil.which(c)), None)
    if not chromium:
        print("no chromium found", file=sys.stderr)
        return 1
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(WORK, exist_ok=True)
    for src, name, running in DOCUMENTS:
        print(" ", os.path.relpath(render(src, name, running, chromium), ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
