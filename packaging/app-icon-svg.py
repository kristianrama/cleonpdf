#!/usr/bin/env python3
"""Draw the CleonPDF app icon as SVG, after the artwork the project owner supplied.

Writes assets/app-icon/cleonpdf.svg (the full tile with the "Cleon PDF" wordmark) and
assets/app-icon/cleonpdf-small.svg (the emblem alone, for sizes below 64 px). The text is outlined
with usvg and the repository's Inter fonts, so the SVGs need no fonts. Then run packaging/icons.sh.

Needs python3 and usvg (cargo install usvg).

    python3 packaging/app-icon-svg.py
"""
import math
import os
import subprocess
import sys
import tempfile

N = 4.9  # the tile's superellipse exponent, fitted to the artwork
S = 1024


def squircle(cx=512, cy=512, a=512, n=N, steps=720):
    pts = []
    for i in range(steps):
        t = 2 * math.pi * i / steps
        c, s = math.cos(t), math.sin(t)
        x = cx + a * math.copysign(abs(c) ** (2 / n), c)
        y = cy + a * math.copysign(abs(s) ** (2 / n), s)
        pts.append(f"{x:.2f},{y:.2f}")
    return "M" + " L".join(pts) + " Z"


def pol(cx, cy, r, deg):
    t = math.radians(deg)
    return cx + r * math.cos(t), cy + r * math.sin(t)


def emblem(cx, cy, k=1.0):
    """The C, its lattice, the globe and the book, centred on the C at (cx, cy), scaled by k."""
    R, r = 268 * k, 176 * k          # outer and inner edge of the C's band
    w = 17 * k                        # outline width
    top_out, top_in = -50, -38        # the C's top terminal (degrees, y down)
    bot_in, bot_out = 38, 45          # its bottom terminal
    o = []

    # The C as one closed outline: the outer arc the long way round the left, the bottom
    # terminal, the inner arc back, and the top terminal.
    x1, y1 = pol(cx, cy, R, top_out)
    x2, y2 = pol(cx, cy, R, bot_out)
    x3, y3 = pol(cx, cy, r, bot_in)
    x4, y4 = pol(cx, cy, r, top_in)
    c_path = (f"M{x1:.1f},{y1:.1f} A{R:.1f},{R:.1f} 0 1 0 {x2:.1f},{y2:.1f} L{x3:.1f},{y3:.1f} "
              f"A{r:.1f},{r:.1f} 0 1 1 {x4:.1f},{y4:.1f} Z")

    # The band's lattice: a truss of chords and zigzags between the two edges, clipped to the C.
    lines = []
    ro, ri = R - w * 0.6, r + w * 0.6
    step = 40
    angles = [top_in - step * i for i in range(0, 9)]
    outer = [pol(cx, cy, ro, a) for a in angles]
    inner = [pol(cx, cy, ri, a - step / 2) for a in angles]
    for i in range(len(angles) - 1):
        (ax, ay), (bx, by), (ix, iy) = outer[i], outer[i + 1], inner[i]
        lines.append(f"M{ax:.1f},{ay:.1f} L{ix:.1f},{iy:.1f} L{bx:.1f},{by:.1f}")
    for i in range(0, len(angles) - 1):
        (ax, ay), (bx, by) = outer[i], outer[i + 1]
        lines.append(f"M{ax:.1f},{ay:.1f} L{bx:.1f},{by:.1f}")
    for i in range(len(inner) - 1):
        (ax, ay), (bx, by) = inner[i], inner[i + 1]
        lines.append(f"M{ax:.1f},{ay:.1f} L{bx:.1f},{by:.1f}")

    # The thin ring that closes the circle across the C's opening.
    rx1, ry1 = pol(cx, cy, R - w / 2, top_out)
    rx2, ry2 = pol(cx, cy, R - w / 2, bot_out)
    ring = f"M{rx1:.1f},{ry1:.1f} A{R - w / 2:.1f},{R - w / 2:.1f} 0 0 1 {rx2:.1f},{ry2:.1f}"

    # The globe inside the C.
    gx, gy, gr = cx + 14 * k, cy + 10 * k, 128 * k
    globe = [f'<circle cx="{gx:.1f}" cy="{gy:.1f}" r="{gr:.1f}"/>']
    for rx in (0.36, 0.72):
        globe.append(f'<ellipse cx="{gx:.1f}" cy="{gy:.1f}" rx="{gr * rx:.1f}" ry="{gr:.1f}"/>')
    for ry in (0.38, 0.0):
        globe.append(f'<ellipse cx="{gx:.1f}" cy="{gy:.1f}" rx="{gr:.1f}" ry="{max(gr * ry, 0.1):.1f}"/>')
    for a in range(0, 180, 30):
        ax, ay = pol(gx, gy, gr, a)
        bx, by = pol(gx, gy, gr, a + 180)
        globe.append(f'<line x1="{ax:.1f}" y1="{ay:.1f}" x2="{bx:.1f}" y2="{by:.1f}"/>')

    o.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{R * 1.22:.1f}" fill="url(#halo)"/>')
    o.append(f'<g fill="none" stroke="#9fc3f2" stroke-width="{2.6 * k:.1f}" opacity="0.32">{"".join(globe)}</g>')
    o.append(f'<clipPath id="band{int(k*100)}"><path d="{c_path}"/></clipPath>')
    o.append(f'<path d="{" ".join(lines)}" fill="none" stroke="#a9cdf6" stroke-width="{3.6 * k:.1f}" '
             f'stroke-linecap="round" opacity="0.5" clip-path="url(#band{int(k*100)})" filter="url(#soft)"/>')
    o.append(f'<path d="{ring}" fill="none" stroke="#9db4ea" stroke-width="{4 * k:.1f}" opacity="0.45"/>')
    o.append(f'<path d="{c_path}" fill="none" stroke="#5f9dff" stroke-width="{w * 3:.1f}" stroke-linejoin="round" opacity="0.8" filter="url(#bloom)"/>')
    o.append(f'<path d="{c_path}" fill="none" stroke="url(#cstroke)" stroke-width="{w:.1f}" stroke-linejoin="round" filter="url(#glow)"/>')

    # The book: open, seen from above at an angle, "PDF" on its pages.
    bx, by = cx + 104 * k, cy - 2 * k
    top_l = "M-160,-58 C-108,-82 -44,-82 0,-58 L0,52 C-44,30 -108,30 -160,52 Z"
    top_r = "M0,-58 C44,-82 108,-82 160,-58 L160,52 C108,30 44,30 0,52 Z"
    under = "M-160,52 C-108,30 -44,30 0,52 C44,30 108,30 160,52 L160,{d} C108,{e} 44,{e} 0,{d} C-44,{e} -108,{e} -160,{d} Z"
    book = f'''<g transform="translate({bx:.1f},{by:.1f}) rotate(-22) scale({0.9 * k:.3f})">
  <path d="{top_l}" transform="translate(0,6)" fill="#5f9dff" opacity="0.5" filter="url(#bloom)"/>
  <path d="{under.format(d=86, e=64)}" fill="#c3d6f7" stroke="#f1f7ff" stroke-width="6" stroke-linejoin="round" filter="url(#glow)"/>
  <path d="M-160,66 C-108,44 -44,44 0,66 C44,44 108,44 160,66" fill="none" stroke="#8fa9d8" stroke-width="3"/>
  <path d="{top_l}" fill="url(#page)" stroke="#eef6ff" stroke-width="7" stroke-linejoin="round" filter="url(#glow)"/>
  <path d="{top_r}" fill="url(#page)" stroke="#eef6ff" stroke-width="7" stroke-linejoin="round" filter="url(#glow)"/>
  <path d="M0,-58 L0,52" stroke="#cfe0fb" stroke-width="4"/>
  <text x="-78" y="20" text-anchor="middle" font-family="Inter" font-weight="600" font-size="78" fill="#f6faff">PDF</text>
</g>'''
    o.append(book)
    return "\n".join(o)


DEFS = '''<defs>
  <linearGradient id="field" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#1f4a6e"/>
    <stop offset="0.5" stop-color="#172a52"/>
    <stop offset="1" stop-color="#26123d"/>
  </linearGradient>
  <radialGradient id="halo">
    <stop offset="0" stop-color="#4a7cc4" stop-opacity="0.42"/>
    <stop offset="0.6" stop-color="#3a5aa0" stop-opacity="0.18"/>
    <stop offset="1" stop-color="#2a3f80" stop-opacity="0"/>
  </radialGradient>
  <linearGradient id="cstroke" gradientUnits="userSpaceOnUse" x1="250" y1="160" x2="700" y2="720">
    <stop offset="0" stop-color="#f4fbff"/>
    <stop offset="0.55" stop-color="#d7e6ff"/>
    <stop offset="1" stop-color="#b9a5f3"/>
  </linearGradient>
  <linearGradient id="page" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#7393cf"/>
    <stop offset="1" stop-color="#4a68a6"/>
  </linearGradient>
  <linearGradient id="rim" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#6f86b8"/>
    <stop offset="1" stop-color="#6a5a9c"/>
  </linearGradient>
  <filter id="glow" x="-25%" y="-25%" width="150%" height="150%" color-interpolation-filters="sRGB">
    <feGaussianBlur in="SourceGraphic" stdDeviation="14" result="wide"/>
    <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="near"/>
    <feMerge><feMergeNode in="wide"/><feMergeNode in="near"/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
  <filter id="bloom" x="-40%" y="-40%" width="180%" height="180%" color-interpolation-filters="sRGB">
    <feGaussianBlur in="SourceGraphic" stdDeviation="22"/>
  </filter>
  <filter id="soft" x="-10%" y="-10%" width="120%" height="120%" color-interpolation-filters="sRGB">
    <feGaussianBlur in="SourceGraphic" stdDeviation="2.5" result="b"/>
    <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
  </filter>
  <clipPath id="tile"><path d="{TILE}"/></clipPath>
</defs>'''


def svg(body, comment):
    tile = squircle()
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{S}" height="{S}" viewBox="0 0 {S} {S}">\n'
            f'<!-- {comment} -->\n'
            + DEFS.replace("{TILE}", tile) + "\n"
            f'<g clip-path="url(#tile)">\n<rect width="{S}" height="{S}" fill="url(#field)"/>\n{body}\n</g>\n'
            f'<path d="{squircle(a=509)}" fill="none" stroke="url(#rim)" stroke-width="6" opacity="0.9"/>\n'
            '</svg>\n')


full_body = emblem(490, 440, 0.94) + '''
<text x="512" y="905" text-anchor="middle" font-family="Inter" fill="#f5f7fc"><tspan font-weight="600" font-size="140">Cleon</tspan><tspan font-weight="400" font-size="108" fill="#a8a6c8" dx="24">PDF</tspan></text>'''
small_body = emblem(484, 512, 1.22)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FONTS = os.path.join(ROOT, "assets", "fonts")
NOTE = ("Drawn by packaging/app-icon-svg.py after the artwork supplied by the project owner; text outlined "
        "with usvg (Inter). MIT OR Apache-2.0, see assets/app-icon/LICENSE.txt.")

for name, body, label in (("cleonpdf.svg", full_body, "CleonPDF app icon"),
                          ("cleonpdf-small.svg", small_body, "CleonPDF app icon, emblem only (sizes below 64 px)")):
    with tempfile.TemporaryDirectory() as tmp:
        raw, out = os.path.join(tmp, "raw.svg"), os.path.join(tmp, "out.svg")
        with open(raw, "w") as f:
            f.write(svg(body, label))
        subprocess.run(["usvg", "--skip-system-fonts",
                        "--use-font-file", os.path.join(FONTS, "Inter-SemiBold.ttf"),
                        "--use-font-file", os.path.join(FONTS, "Inter-Regular.ttf"), raw, out], check=True)
        text = open(out).read()
    if "<text" in text:
        sys.exit("error: usvg left text unoutlined (are the Inter fonts in assets/fonts?)")
    # usvg drops the viewBox; keep it, so the icon scales when another SVG embeds it.
    text = text.replace(f'<svg width="{S}" height="{S}"', f'<svg width="{S}" height="{S}" viewBox="0 0 {S} {S}"', 1)
    head = text.index(">") + 1
    text = text[:head] + f"\n<!-- {label}. {NOTE} -->" + text[head:]
    with open(os.path.join(ROOT, "assets", "app-icon", name), "w") as f:
        f.write(text)
    print(f"wrote assets/app-icon/{name}")
