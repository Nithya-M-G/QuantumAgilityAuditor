"""
Quantum-Agility Auditor - architecture diagrams (Figs. 1-5 + colour key)
------------------------------------------------------------------------
Run in VS Code:   pip install matplotlib
                  python generate_diagrams.py

Design rules (greyscale first, colour second)
  * Colour encodes the ROLE of a block, never decoration.
  * Six muted fills, spaced in LIGHTNESS (L*) as well as hue, so each role
    stays distinguishable when the paper is printed in greyscale.
  * Text is pure black or pure white only (auto-chosen per fill).
  * Every fill is contrast-checked (WCAG >= 4.5:1) when the script runs.
  * Box borders and arrows are dark.

Output (folder ./diagrams):
  QuantumAgilityAuditor_Diagrams.pdf   all pages, vector
  fig1..fig5.pdf / .png (600 dpi), legend.pdf / .png
  greyscale_preview.png                what a greyscale print will look like
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Polygon

# ----------------------------------------------------------------------
# PALETTE - one colour per ROLE, ordered dark -> light (L* 18 ... 96)
# ----------------------------------------------------------------------
ROLES = {
    #  role key      hex        what it means in the figures
    "terminator": ("#242D34", "Start / End of the pipeline"),
    "process":    ("#2C6A86", "Deterministic processing (scanners, parser, dashboard)"),
    "reasoning":  ("#8C7CAB", "Risk scoring, migration reasoning, roadmap views"),
    "ai":         ("#7BBDB0", "AI / ML detection and explainability"),
    "decision":   ("#F5C1AA", "Decision point"),
    "data":       ("#FBF3E2", "Data artefacts (inputs, findings, SBOM, outputs)"),
}
TERMINATOR, PROCESS, REASONING, AI, DECISION, DATA = (ROLES[k][0] for k in
    ("terminator", "process", "reasoning", "ai", "decision", "data"))

INK, BLACK, WHITE = "#14212E", "#000000", "#FFFFFF"   # border/arrow, text, text

plt.rcParams.update({
    "font.family": "DejaVu Sans",   # swap for "Times New Roman" if installed
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})

OUT = Path("diagrams")
OUT.mkdir(exist_ok=True)


# ----------------------------------------------------------------------
# Colour maths: contrast + greyscale check
# ----------------------------------------------------------------------
def _rgb(h):
    return [int(h[i:i + 2], 16) for i in (1, 3, 5)]


def _lin(c):
    c /= 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def luminance(h):
    r, g, b = (_lin(v) for v in _rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(h1, h2):
    a, b = sorted((luminance(h1), luminance(h2)), reverse=True)
    return (a + 0.05) / (b + 0.05)


def grey(h):                       # ITU-R BT.601 luma, as used by most printers
    r, g, b = _rgb(h)
    return round(0.299 * r + 0.587 * g + 0.114 * b)


def text_on(fill):                 # pure black or pure white, whichever is clearer
    return WHITE if contrast(fill, WHITE) >= contrast(fill, BLACK) else BLACK


def check_palette(min_contrast=4.5, min_grey_gap=20):
    print(f"{'role':<11}{'fill':<9}{'text':<7}{'contrast':>9}{'grey(0-255)':>13}")
    greys = []
    for role, (hx, _) in ROLES.items():
        t = text_on(hx)
        cr = contrast(hx, t)
        greys.append(grey(hx))
        print(f"{role:<11}{hx:<9}{'white' if t == WHITE else 'black':<7}"
              f"{cr:>8.1f}:1{grey(hx):>11}")
        assert cr >= min_contrast, f"{role}: contrast {cr:.1f} < {min_contrast}"
    greys.sort()
    gaps = [b - a for a, b in zip(greys, greys[1:])]
    print("smallest grey-level gap between roles:", min(gaps))
    assert min(gaps) >= min_grey_gap, "roles too close in greyscale"
    print()


# ----------------------------------------------------------------------
# Drawing helpers
# ----------------------------------------------------------------------
def canvas(w, h, title):
    fig = plt.figure(figsize=(w, h))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.axis("off")
    ax.text(w / 2, h - 0.35, title, ha="center", va="center",
            fontsize=22, fontweight="bold", color=BLACK)
    return fig, ax


def node(ax, cx, cy, w, h, text, fill, fs=20, shape="round"):
    kw = dict(fc=fill, ec=INK, lw=2.5, joinstyle="round")
    if shape == "round":
        p = FancyBboxPatch((cx - w / 2, cy - h / 2), w, h,
                           boxstyle="round,pad=0,rounding_size=0.12", **kw)
    elif shape == "pill":
        p = FancyBboxPatch((cx - w / 2, cy - h / 2), w, h,
                           boxstyle=f"round,pad=0,rounding_size={h / 2}", **kw)
    elif shape == "io":
        s = 0.25
        p = Polygon([(cx - w / 2 + s, cy + h / 2), (cx + w / 2, cy + h / 2),
                     (cx + w / 2 - s, cy - h / 2), (cx - w / 2, cy - h / 2)], **kw)
    elif shape == "decision":
        p = Polygon([(cx, cy + h / 2), (cx + w / 2, cy),
                     (cx, cy - h / 2), (cx - w / 2, cy)], **kw)
    else:
        raise ValueError(shape)
    ax.add_patch(p)
    ax.text(cx, cy, text, ha="center", va="center", fontsize=fs,
            fontweight="bold", color=text_on(fill), linespacing=1.2)


def arrow(ax, p1, p2, lw=3):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle="-|>", mutation_scale=28,
                                 lw=lw, color=INK, shrinkA=0, shrinkB=0))


def line(ax, pts, lw=3):
    xs, ys = zip(*pts)
    ax.plot(xs, ys, color=INK, lw=lw, solid_capstyle="round",
            solid_joinstyle="round")


def fan_out(ax, src, targets, y_bus, y_top):
    sx, sy = src
    line(ax, [(sx, sy), (sx, y_bus)])
    line(ax, [(min(targets + [sx]), y_bus), (max(targets + [sx]), y_bus)])
    for x in targets:
        arrow(ax, (x, y_bus), (x, y_top))


def fan_in(ax, sources, y_bottoms, dst, y_bus, y_top):
    for x, yb in zip(sources, y_bottoms):
        line(ax, [(x, yb), (x, y_bus)])
    line(ax, [(min(sources + [dst]), y_bus), (max(sources + [dst]), y_bus)])
    arrow(ax, (dst, y_bus), (dst, y_top))


# ----------------------------------------------------------------------
# Fig. 1 - End-to-end operation
# ----------------------------------------------------------------------
def fig1():
    W, H = 9, 14.4
    fig, ax = canvas(W, H, "Fig. 1  End-to-End Operation")
    cx = 4.0
    y = [13.0, 11.5, 9.9, 7.9, 5.5, 3.9, 2.4, 1.0]

    node(ax, cx, y[0], 3.4, 0.9, "START", TERMINATOR, 22, "pill")
    node(ax, cx, y[1], 5.6, 1.0, "INPUT\nCode / Config / Deps / PCAP", DATA, 18, "io")
    node(ax, cx, y[2], 5.0, 1.1, "Scan & Classify\nModules 1\u20132", PROCESS)
    node(ax, cx, y[3], 5.2, 2.2, "Crypto\ndetected?", DECISION, 21, "decision")
    node(ax, cx, y[4], 5.0, 1.1, "Risk Score + Roadmap\nModule 3", REASONING, 19)
    node(ax, cx, y[5], 5.0, 1.1, "Dashboard + PDF\nModule 4", PROCESS)
    node(ax, cx, y[6], 5.6, 1.0, "OUTPUT\nRoadmap to user", DATA, 18, "io")
    node(ax, cx, y[7], 3.4, 0.9, "END", TERMINATOR, 22, "pill")

    half = [0.45, 0.5, 0.55, 1.1, 0.55, 0.55, 0.5, 0.45]
    for i in range(7):
        arrow(ax, (cx, y[i] - half[i]), (cx, y[i + 1] + half[i + 1]))

    ax.text(cx + 0.2, y[3] - 1.35, "Yes", fontsize=19, fontweight="bold",
            color=BLACK, va="center")
    ax.text(cx + 3.3, y[3] + 0.35, "No", fontsize=19, fontweight="bold",
            color=BLACK, ha="center")
    line(ax, [(cx + 2.6, y[3]), (7.9, y[3]), (7.9, y[5])])
    arrow(ax, (7.9, y[5]), (cx + 2.5, y[5]))
    ax.text(8.2, (y[3] + y[5]) / 2, "Skip scoring", fontsize=17,
            fontweight="bold", color=BLACK, rotation=90, ha="center", va="center")
    return fig


# ----------------------------------------------------------------------
# Fig. 2 - Module 1 data flow
# ----------------------------------------------------------------------
def fig2():
    W, H = 14, 8.6
    fig, ax = canvas(W, H, "Fig. 2  Data Flow inside Module 1")
    cx = W / 2
    node(ax, cx, 7.2, 4.6, 1.0, "USER INPUT\nFiles / Folder / PCAP", DATA, 19, "io")

    labels = ["Source Code\nScanner", "Config\nScanner", "Dependency\nScanner", "Network\nScanner"]
    xs = [2.2, 5.4, 8.6, 11.8]
    fan_out(ax, (cx, 6.7), xs, 6.15, 5.55)
    for x, t in zip(xs, labels):
        node(ax, x, 4.8, 2.9, 1.5, t, PROCESS, 20)

    fan_in(ax, xs, [4.05] * 4, cx, 3.45, 2.95)
    node(ax, cx, 2.35, 6.4, 1.2, "UNIFIED FILE PARSER\nAST + Regex + YAML / JSON", PROCESS, 19)
    arrow(ax, (cx, 1.75), (cx, 1.25))
    node(ax, cx, 0.7, 6.4, 1.0, "RAW FINDINGS LIST", DATA, 20)
    return fig


# ----------------------------------------------------------------------
# Fig. 3 - Module 2 (AI detection layer)
# ----------------------------------------------------------------------
def fig3():
    W, H = 11, 9.2
    fig, ax = canvas(W, H, "Fig. 3  Data Flow inside AI Detection Layer")
    cx = W / 2
    node(ax, cx, 7.9, 5.6, 1.0, "RAW FINDINGS LIST", DATA, 20)

    xs = [2.9, 8.1]
    fan_out(ax, (cx, 7.4), xs, 6.9, 6.4)
    node(ax, xs[0], 5.45, 4.6, 1.9, "NLP TEXT\nCLASSIFIER\nTF-IDF + SVM", AI)
    node(ax, xs[1], 5.45, 4.6, 1.9, "CIPHERTEXT\nFINGERPRINTING\nRandom Forest", AI)

    fan_in(ax, xs, [4.5, 4.5], cx, 3.8, 3.4)
    node(ax, cx, 2.9, 5.6, 1.0, "LIME EXPLAINABILITY", AI, 20)
    arrow(ax, (cx, 2.4), (cx, 1.9))
    node(ax, cx, 1.4, 6.4, 1.0, "CRYPTOGRAPHIC SBOM", DATA, 20)
    return fig


# ----------------------------------------------------------------------
# Fig. 4 - Module 3 (Quantum Migration Reasoner)
# ----------------------------------------------------------------------
def fig4():
    W, H = 15, 8.6
    fig, ax = canvas(W, H, "Fig. 4  Data Flow inside Module 3")
    cx = W / 2
    node(ax, cx, 7.2, 6.2, 1.0, "CRYPTOGRAPHIC SBOM", DATA, 20)

    labels = ["RISK SCORING\nENGINE", "CONTEXT-AWARE\nRECOMMENDER", "PERFORMANCE\nPENALTY"]
    xs = [2.6, cx, W - 2.6]
    fan_out(ax, (cx, 6.7), xs, 6.1, 5.5)
    for x, t in zip(xs, labels):
        node(ax, x, 4.55, 4.2, 1.9, t, REASONING, 23)

    fan_in(ax, xs, [3.6] * 3, cx, 2.9, 2.4)
    node(ax, cx, 1.85, 6.8, 1.0, "MIGRATION ROADMAP OUTPUT", DATA, 20)
    return fig


# ----------------------------------------------------------------------
# Fig. 5 - Module 4 (Dashboard & output)
# ----------------------------------------------------------------------
def fig5():
    W, H = 15, 7.6
    fig, ax = canvas(W, H, "Fig. 5  Data Flow inside Module 4")
    cx = W / 2
    node(ax, cx, 6.2, 7.6, 1.0, "MIGRATION ROADMAP + LIME OUTPUT", DATA, 19)
    arrow(ax, (cx, 5.7), (cx, 4.9))
    node(ax, cx, 4.3, 6.4, 1.2, "STREAMLIT DASHBOARD", PROCESS, 21)

    labels = ["RISK\nHEATMAP", "MIGRATION\nROADMAP", "LIME\nPANEL", "ONE-CLICK\nPDF EXPORT"]
    xs = [2.1, 5.7, 9.3, 12.9]
    fan_out(ax, (cx, 3.7), xs, 3.1, 2.5)
    for x, t in zip(xs, labels):                  # same level -> same colour
        node(ax, x, 1.5, 3.2, 2.0, t, DATA, 20)
    return fig


# ----------------------------------------------------------------------
# Colour key (use as a caption aid or a small inset figure)
# ----------------------------------------------------------------------
def legend_fig():
    W, H = 13, 7.4
    fig, ax = canvas(W, H, "Colour Key")
    y = H - 1.4
    for role, (hx, meaning) in ROLES.items():
        node(ax, 2.0, y, 2.6, 0.75, role.upper(), hx, 15)
        ax.text(3.7, y, meaning, fontsize=17, fontweight="bold",
                color=BLACK, va="center")
        y -= 1.0
    return fig


# ----------------------------------------------------------------------
# Export
# ----------------------------------------------------------------------
def main():
    check_palette()
    builders = [("fig1", fig1), ("fig2", fig2), ("fig3", fig3),
                ("fig4", fig4), ("fig5", fig5), ("legend", legend_fig)]
    kw = dict(bbox_inches="tight", pad_inches=0.35, facecolor="white")
    pngs = []
    with PdfPages(OUT / "QuantumAgilityAuditor_Diagrams.pdf") as pdf:
        for name, build in builders:
            fig = build()
            pdf.savefig(fig, **kw)
            fig.savefig(OUT / f"{name}.pdf", **kw)
            fig.savefig(OUT / f"{name}.png", dpi=600, **kw)
            plt.close(fig)
            pngs.append(OUT / f"{name}.png")
            print("saved", name)

    # Greyscale preview (what a B/W print will look like)
    try:
        from PIL import Image
        Image.MAX_IMAGE_PIXELS = None
        tiles = []
        for p in pngs:
            im = Image.open(p).convert("L")
            im.thumbnail((900, 900))
            tiles.append(im)
        sheet = Image.new("L", (sum(t.width for t in tiles) + 20 * len(tiles),
                                max(t.height for t in tiles)), 255)
        x = 0
        for t in tiles:
            sheet.paste(t, (x, 0))
            x += t.width + 20
        sheet.save(OUT / "greyscale_preview.png")
        print("saved greyscale_preview")
    except ImportError:
        print("(install pillow for greyscale_preview.png:  pip install pillow)")

    print(f"\nDone. Files are in: {OUT.resolve()}")


if __name__ == "__main__":
    main()