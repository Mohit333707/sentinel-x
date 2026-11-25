#!/usr/bin/env python3
"""Render docs/submission/02-Sample-Run-Transcript.md (and .txt) to PDF.

Same method as the other submission PDFs: matplotlib PdfPages, plain
wrapped text, one header line and a page footer. No extra dependencies.
Run from the project root: python docs/submission/make_transcript_pdf.py
"""
import os, re, textwrap
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SUB = os.path.join(BASE, "docs", "submission")
MD = os.path.join(SUB, "02-Sample-Run-Transcript.md")
TXT = os.path.join(SUB, "02-Sample-Run-Transcript.txt")
PDF = os.path.join(SUB, "02-Sample-Run-Transcript.pdf")

def to_plain(md: str) -> str:
    out = []
    for line in md.splitlines():
        line = re.sub(r"^#{1,4}\s*", "", line)
        line = line.replace("**", "").replace("`", "")
        out.append(line)
    return "\n".join(out)

md = open(MD, encoding="utf-8").read()
plain = to_plain(md)
open(TXT, "w", encoding="utf-8").write(plain + "\n")

# Wrap to ~100 chars; keep blank lines as paragraph breaks.
wrapped = []
for line in plain.splitlines():
    if not line.strip():
        wrapped.append("")
    elif line.startswith(("| ", "---")):
        wrapped.append(line)
    else:
        wrapped.extend(textwrap.wrap(line, width=100, replace_whitespace=False,
                                     drop_whitespace=False) or [""])

LINES_PER_PAGE = 52
pages = [wrapped[i:i + LINES_PER_PAGE] for i in range(0, len(wrapped), LINES_PER_PAGE)]
with PdfPages(PDF) as pdf:
    for n, page in enumerate(pages, 1):
        fig = plt.figure(figsize=(8.5, 11))
        ax = fig.add_axes([0.07, 0.05, 0.86, 0.88])
        ax.axis("off")
        ax.set_title("SENTINEL-X Sample Run Transcript — 3 runs (synthetic, offline)",
                     fontsize=11, weight="bold", pad=10, loc="left")
        body = "\n".join(page)
        ax.text(0, 1, body, transform=ax.transAxes, fontsize=8.5,
                family="DejaVu Sans", va="top", ha="left")
        fig.text(0.5, 0.02, f"SENTINEL-X | Synthetic data only | Offline mode, live Gemini run pending a free key | Page {n} of {len(pages)}",
                 ha="center", fontsize=7.5, style="italic")
        pdf.savefig(fig)
        plt.close(fig)
print(f"wrote {PDF} ({len(pages)} pages) and {TXT}")
