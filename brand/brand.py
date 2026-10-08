"""GnB-SMH brand generator.

Derived from the Bloch Inc wordmark: white geometric letters whose curved strokes
turn into luminous ribbons. Bloch Inc paints them lime; GnB-SMH paints them
fluorescent orange, on black.

    * "GnB-SMH" set in Poppins Bold, letterforms converted to outlines.
    * Ribbon on the n: the arch and right leg turn orange, with a highlight on the
      crest and a dark fold where the ribbon leaves the stem; the stem picks up the
      colour at the top and fades to white.
    * Ribbon on the B: the upper bowl turns orange; a translucent tail sweeps from
      the foot of the stem up to the waist, like the loop in the Bloch Inc B.
    * The hyphen is a solid fluorescent bar.
    * The n is the "and" in Gödel and Bell: it is also the monogram.

All geometry is in Poppins font units (1000/em, y up) inside each glyph group.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from pathlib import Path

import uharfbuzz as hb
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont

ROOT = Path(__file__).resolve().parent
FONTS = ROOT / "fonts"

# ------------------------------------------------------------------ palette
BLACK = "#000000"
WHITE = "#FFFFFF"
FLUOR = "#FF5F15"       # GnB Fluor: fluorescent orange, the brand colour
FLUOR_HI = "#FFB547"    # ribbon highlight (crest)
FLUOR_DEEP = "#F04A00"  # ribbon body in shade
FOLD = "#7A1E00"        # underside of the ribbon where it turns


@dataclass
class Face:
    tt: TTFont
    hbfont: hb.Font
    upem: int
    cap: int
    xh: int


_FACES: dict[str, Face] = {}


def face(name: str) -> Face:
    if name not in _FACES:
        data = (FONTS / name).read_bytes()
        tt = TTFont(io.BytesIO(data))
        _FACES[name] = Face(tt, hb.Font(hb.Face(data)), tt["head"].unitsPerEm,
                            tt["OS/2"].sCapHeight, tt["OS/2"].sxHeight)
    return _FACES[name]


def glyph_path(fc: Face, gname: str) -> str:
    pen = SVGPathPen(fc.tt.getGlyphSet())
    fc.tt.getGlyphSet()[gname].draw(pen)
    return pen.getCommands()


def f(x: float) -> str:
    s = f"{x:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


# ------------------------------------------------------------------ ribbons (font units)
def ribbon_n(p: str, d: str, ink: str, flat: bool = False) -> tuple[str, str]:
    """Defs and layers for a Poppins-Bold 'n' (stem 62-233, leg 447-617, crest 564)."""
    if flat:
        defs = f'<clipPath id="{p}a"><rect x="233" y="-20" width="420" height="620"/></clipPath>'
        layers = (f'<path d="{d}" fill="{ink}"/>'
                  f'<path d="{d}" fill="{FLUOR}" clip-path="url(#{p}a)"/>')
        return defs, layers
    defs = (
        f'<clipPath id="{p}a"><rect x="233" y="-20" width="420" height="620"/></clipPath>'
        f'<clipPath id="{p}s"><rect x="40" y="-20" width="193" height="620"/></clipPath>'
        f'<clipPath id="{p}g"><path d="{d}"/></clipPath>'
        f'<linearGradient id="{p}st" gradientUnits="userSpaceOnUse" x1="0" y1="558" x2="0" y2="250">'
        f'<stop offset="0" stop-color="{FLUOR}" stop-opacity="0.9"/>'
        f'<stop offset="0.45" stop-color="{FLUOR}" stop-opacity="0.35"/>'
        f'<stop offset="1" stop-color="{FLUOR}" stop-opacity="0"/></linearGradient>'
        f'<linearGradient id="{p}ar" gradientUnits="userSpaceOnUse" x1="233" y1="0" x2="617" y2="0">'
        f'<stop offset="0" stop-color="{FLUOR}"/>'
        f'<stop offset="0.62" stop-color="{FLUOR}"/>'
        f'<stop offset="1" stop-color="{FLUOR_DEEP}"/></linearGradient>'
        f'<radialGradient id="{p}hi" gradientUnits="userSpaceOnUse" cx="455" cy="600" r="250">'
        f'<stop offset="0" stop-color="{FLUOR_HI}" stop-opacity="0.95"/>'
        f'<stop offset="1" stop-color="{FLUOR_HI}" stop-opacity="0"/></radialGradient>'
        f'<linearGradient id="{p}fo" gradientUnits="userSpaceOnUse" x1="233" y1="0" x2="345" y2="0">'
        f'<stop offset="0" stop-color="{FOLD}" stop-opacity="0.85"/>'
        f'<stop offset="1" stop-color="{FOLD}" stop-opacity="0"/></linearGradient>'
        f'<linearGradient id="{p}lg" gradientUnits="userSpaceOnUse" x1="0" y1="330" x2="0" y2="0">'
        f'<stop offset="0" stop-color="{FLUOR_DEEP}" stop-opacity="0"/>'
        f'<stop offset="1" stop-color="{FLUOR_DEEP}" stop-opacity="0.55"/></linearGradient>'
    )
    layers = (
        f'<path d="{d}" fill="{ink}"/>'
        f'<path d="{d}" fill="url(#{p}st)" clip-path="url(#{p}s)"/>'
        f'<path d="{d}" fill="url(#{p}ar)" clip-path="url(#{p}a)"/>'
        f'<g clip-path="url(#{p}g)">'
        f'<rect x="233" y="300" width="420" height="300" fill="url(#{p}hi)"/>'
        f'<path d="M233 290 L233 560 L360 566 L330 400 Z" fill="url(#{p}fo)"/>'
        f'<rect x="440" y="0" width="200" height="330" fill="url(#{p}lg)"/>'
        f'</g>'
    )
    return defs, layers


def ribbon_B(p: str, d: str, ink: str, flat: bool = False) -> tuple[str, str]:
    """Defs and layers for a Poppins-Bold 'B' (stem 62-233, waist ~360, top 702).

    Upper bowl: solid ribbon. Its clip follows the upper counter's floor (y 418) and
    then the waist, so no clip edge crosses the white middle bar.
    Tail: a tapering quarter-elliptic band from the foot of the stem up into the
    waist, translucent at the foot, drawn under the bowl so its end is hidden."""
    bowl = 'M233 418 L432 418 L478 360 L700 360 L700 740 L233 740 Z'
    bowl_clip = f'<clipPath id="{p}u"><path d="{bowl}"/></clipPath>'
    if flat:
        return bowl_clip, (f'<path d="{d}" fill="{ink}"/>'
                           f'<path d="{d}" fill="{FLUOR}" clip-path="url(#{p}u)"/>')
    cx, cy = 520.0, 0.0
    rxo, ryo = 458.0, 445.0   # outer edge: foot of the stem (x 62) to the top of the waist
    rxi, ryi = 287.0, 360.0   # inner edge: inner side of the stem (x 233) to the waist
    # y is up inside the glyph group, so the visual sweep direction is mirrored
    tail = (f'M{f(cx - rxo)} {f(cy)} A{f(rxo)} {f(ryo)} 0 0 0 {f(cx)} {f(cy + ryo)} '
            f'L{f(cx)} {f(cy + ryi)} A{f(rxi)} {f(ryi)} 0 0 1 {f(cx - rxi)} {f(cy)} Z')
    defs = (
        bowl_clip +
        f'<clipPath id="{p}g"><path d="{d}"/></clipPath>'
        f'<linearGradient id="{p}bw" gradientUnits="userSpaceOnUse" x1="300" y1="702" x2="560" y2="372">'
        f'<stop offset="0" stop-color="{FLUOR}"/>'
        f'<stop offset="1" stop-color="{FLUOR_DEEP}"/></linearGradient>'
        f'<radialGradient id="{p}hi" gradientUnits="userSpaceOnUse" cx="520" cy="690" r="230">'
        f'<stop offset="0" stop-color="{FLUOR_HI}" stop-opacity="0.95"/>'
        f'<stop offset="1" stop-color="{FLUOR_HI}" stop-opacity="0"/></radialGradient>'
        f'<linearGradient id="{p}tl" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="0" y2="420">'
        f'<stop offset="0" stop-color="{FLUOR}" stop-opacity="0"/>'
        f'<stop offset="0.5" stop-color="{FLUOR}" stop-opacity="0.32"/>'
        f'<stop offset="1" stop-color="{FLUOR}" stop-opacity="0.85"/></linearGradient>'
        f'<linearGradient id="{p}fo" gradientUnits="userSpaceOnUse" x1="0" y1="360" x2="0" y2="470">'
        f'<stop offset="0" stop-color="{FOLD}" stop-opacity="0.65"/>'
        f'<stop offset="1" stop-color="{FOLD}" stop-opacity="0"/></linearGradient>'
    )
    layers = (
        f'<path d="{d}" fill="{ink}"/>'
        f'<path d="{tail}" fill="url(#{p}tl)"/>'
        f'<path d="{d}" fill="url(#{p}bw)" clip-path="url(#{p}u)"/>'
        f'<g clip-path="url(#{p}u)"><g clip-path="url(#{p}g)">'
        f'<rect x="233" y="360" width="470" height="380" fill="url(#{p}hi)"/>'
        f'<rect x="420" y="360" width="280" height="110" fill="url(#{p}fo)"/>'
        f'</g></g>'
    )
    return defs, layers


# ------------------------------------------------------------------ composition
def shape(fc: Face, text: str) -> list[tuple[str, float]]:
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(fc.hbfont, buf, {"kern": True, "liga": False})
    order = fc.tt.getGlyphOrder()
    out, x = [], 0.0
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        out.append((order[info.codepoint], x + pos.x_offset))
        x += pos.x_advance
    out.append(("", x))  # sentinel carries total advance
    return out


def wordmark(prefix: str, text: str = "GnB-SMH", cap_h: float = 100.0, x: float = 0.0,
             baseline: float = 100.0, ink: str = WHITE, ribbons: bool = True, flat: bool = False,
             tracking: float = 8.0, font: str = "Poppins-Bold.ttf") -> tuple[str, str, float]:
    """Return (defs, body, width) for the wordmark at the given cap height."""
    fc = face(font)
    s = cap_h / fc.cap
    glyphs = shape(fc, text)
    defs, body = [], []
    pen_extra = 0.0
    for i, (g, gx) in enumerate(glyphs[:-1]):
        gx += pen_extra
        tx = x + gx * s
        tr = f'translate({f(tx)},{f(baseline)}) scale({f(s)},{f(-s)})'
        d = glyph_path(fc, g)
        pid = f"{prefix}{i}"
        if g == "hyphen":
            # shorter, heavier bar than the font's hyphen: 0.34 em wide, sits on the x-height middle
            w, h = 230.0, 136.0
            y0 = fc.xh / 2 - h / 2
            colour = FLUOR if ribbons else ink
            body.append(f'<g transform="{tr}"><rect x="{f(70)}" y="{f(y0)}" width="{f(w)}" height="{f(h)}" fill="{colour}"/></g>')
            pen_extra += (70 + w + 70) - fc.tt["hmtx"]["hyphen"][0]
        elif ribbons and g == "n":
            dd, ll = ribbon_n(pid, d, ink, flat)
            defs.append(dd)
            body.append(f'<g transform="{tr}">{ll}</g>')
        elif ribbons and g == "B":
            dd, ll = ribbon_B(pid, d, ink, flat)
            defs.append(dd)
            body.append(f'<g transform="{tr}">{ll}</g>')
        else:
            body.append(f'<g transform="{tr}"><path d="{d}" fill="{ink}"/></g>')
        pen_extra += tracking
    total = (glyphs[-1][1] + pen_extra - tracking) * s
    return "".join(defs), "".join(body), total


def monogram(prefix: str, size: float = 512.0, flat: bool = False, shape_: str = "square",
             bg: str = BLACK, fill: float = 0.62) -> str:
    """The ribbon n on a black tile (app icon, favicon, token icon).
    `fill` is the n's width as a share of the tile."""
    fc = face("Poppins-Bold.ttf")
    d = glyph_path(fc, "n")
    dd, ll = ribbon_n(prefix, d, WHITE, flat)
    # n spans x 62..617 (w 555), y 0..564; centre it optically
    s = size * fill / 555.0
    tx = size / 2 - (62 + 555 / 2) * s
    ty = size / 2 + 564 * s / 2
    if shape_ == "circle":
        tile = f'<circle cx="{f(size/2)}" cy="{f(size/2)}" r="{f(size/2)}" fill="{bg}"/>'
    elif shape_ == "square":
        tile = f'<rect width="{f(size)}" height="{f(size)}" rx="{f(size*0.22)}" fill="{bg}"/>'
    else:
        tile = ""
    return svg_doc(size, size, f'<defs>{dd}</defs>{tile}<g transform="translate({f(tx)},{f(ty)}) scale({f(s)},{f(-s)})">{ll}</g>', "GnB-SMH")


def svg_doc(w: float, h: float, inner: str, title: str = "GnB-SMH", bg: str | None = None) -> str:
    back = f'<rect width="{f(w)}" height="{f(h)}" fill="{bg}"/>' if bg else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {f(w)} {f(h)}" width="{f(w)}" '
            f'height="{f(h)}" role="img" aria-label="{title}"><title>{title}</title>{back}{inner}</svg>\n')


def side_bearings(fc: Face, text: str) -> tuple[float, float]:
    """Left bearing of the first glyph and right bearing of the last, in font units."""
    from fontTools.pens.boundsPen import BoundsPen
    gs = fc.tt.getGlyphSet()
    cmap = fc.tt.getBestCmap()
    first, last = cmap[ord(text[0])], cmap[ord(text[-1])]
    b1, b2 = BoundsPen(gs), BoundsPen(gs)
    gs[first].draw(b1)
    gs[last].draw(b2)
    return b1.bounds[0], fc.tt["hmtx"][last][0] - b2.bounds[2]


def wordmark_svg(prefix: str, text: str = "GnB-SMH", cap_h: float = 100.0, ink: str = WHITE,
                 ribbons: bool = True, flat: bool = False, bg: str | None = None, pad: float = 0.0) -> str:
    fc = face("Poppins-Bold.ttf")
    s = cap_h / fc.cap
    lsb, rsb = side_bearings(fc, text)
    top_over = (712 - fc.cap) * s           # overshoot of round capitals above cap height
    bottom = 7 * s                          # overshoot below the baseline
    base = pad + cap_h + top_over
    defs, body, w = wordmark(prefix, text, cap_h, x=pad - lsb * s, baseline=base, ink=ink,
                             ribbons=ribbons, flat=flat)
    width = pad + w - (lsb + rsb) * s + pad
    return svg_doc(width, base + bottom + pad, f'<defs>{defs}</defs>{body}', text, bg)


# ------------------------------------------------------------------ kit
def text_outline(text: str, font: str, size: float, x: float, baseline: float, fill: str,
                 tracking: float = 0.0) -> tuple[str, float]:
    """Plain text as outlines (for the social card). Returns (svg, width)."""
    fc = face(font)
    s = size / fc.upem
    out, pen = [], 0.0
    for g, gx in shape(fc, text)[:-1]:
        d = glyph_path(fc, g)
        if d:
            out.append(f'<path transform="translate({f(x + (gx + pen) * s)},{f(baseline)}) scale({f(s)},{f(-s)})" d="{d}" fill="{fill}"/>')
        pen += tracking
    total = (shape(fc, text)[-1][1] + pen) * s
    return "".join(out), total


def og_card() -> str:
    W, H = 1200, 630
    defs, body, w = wordmark("og", "GnB-SMH", cap_h=118, x=0, baseline=0)
    lsb, _ = side_bearings(face("Poppins-Bold.ttf"), "GnB-SMH")
    s = 118 / face("Poppins-Bold.ttf").cap
    x0 = (W - (w - lsb * s)) / 2 - lsb * s
    defs, body, _ = wordmark("og", "GnB-SMH", cap_h=118, x=x0, baseline=300)
    l1, l2 = "Gödel and Bell Sequential Memory-Hard", "Post-quantum proof-of-work of GnB, a hard fork of Bloch"
    _, w1 = text_outline(l1, "Poppins-Medium.ttf", 34, 0, 0, WHITE, tracking=-14)
    t1, _ = text_outline(l1, "Poppins-Medium.ttf", 34, (W - w1) / 2, 392, WHITE, tracking=-14)
    _, w2 = text_outline(l2, "Poppins-Medium.ttf", 24, 0, 0, "#9C918A", tracking=-10)
    t2, _ = text_outline(l2, "Poppins-Medium.ttf", 24, (W - w2) / 2, 446, "#9C918A", tracking=-10)
    rule = f'<rect x="{f(W/2 - 36)}" y="500" width="72" height="6" fill="{FLUOR}"/>'
    return svg_doc(W, H, f'<defs>{defs}</defs><rect width="{W}" height="{H}" fill="{BLACK}"/>{body}{t1}{t2}{rule}', "GnB-SMH")


def build_kit(out: Path) -> list[Path]:
    files: list[Path] = []

    def put(rel: str, text: str) -> None:
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        files.append(p)

    put("svg/gnb-smh-wordmark.svg", wordmark_svg("a", cap_h=100))
    put("svg/gnb-smh-wordmark-on-black.svg", wordmark_svg("b", cap_h=100, bg=BLACK, pad=48))
    put("svg/gnb-smh-wordmark-flat.svg", wordmark_svg("c", cap_h=100, flat=True))
    put("svg/gnb-smh-wordmark-mono-white.svg", wordmark_svg("d", cap_h=100, ribbons=False))
    put("svg/gnb-smh-wordmark-mono-black.svg", wordmark_svg("e", cap_h=100, ink=BLACK, ribbons=False))
    put("svg/gnb-smh-wordmark-on-white.svg", wordmark_svg("f", cap_h=100, ink=BLACK, flat=True, bg=WHITE, pad=48))
    put("svg/gnb-wordmark.svg", wordmark_svg("g", text="GnB", cap_h=100))
    put("svg/gnb-wordmark-on-black.svg", wordmark_svg("h", text="GnB", cap_h=100, bg=BLACK, pad=48))
    put("svg/gnb-wordmark-flat.svg", wordmark_svg("i", text="GnB", cap_h=100, flat=True))
    put("svg/gnb-monogram.svg", monogram("j"))
    put("svg/gnb-monogram-flat.svg", monogram("k", flat=True))
    put("svg/gnb-token.svg", monogram("l", shape_="circle"))
    put("favicon/favicon.svg", monogram("m", size=64, flat=True, fill=0.74))
    put("social/og-image.svg", og_card())
    return files


def export_rasters(out: Path) -> None:
    import cairosvg
    from PIL import Image

    png, fav = out / "png", out / "favicon"
    png.mkdir(parents=True, exist_ok=True)

    def r(src: Path, dst: Path, w: int) -> None:
        cairosvg.svg2png(url=str(src), write_to=str(dst), output_width=w)

    r(out / "svg/gnb-smh-wordmark-on-black.svg", png / "gnb-smh-wordmark-on-black-1200.png", 1200)
    r(out / "svg/gnb-smh-wordmark-on-black.svg", png / "gnb-smh-wordmark-on-black-2400.png", 2400)
    r(out / "svg/gnb-smh-wordmark.svg", png / "gnb-smh-wordmark-transparent-2400.png", 2400)
    r(out / "svg/gnb-smh-wordmark-on-white.svg", png / "gnb-smh-wordmark-on-white-1200.png", 1200)
    r(out / "svg/gnb-wordmark-on-black.svg", png / "gnb-wordmark-on-black-1200.png", 1200)
    for sz in (512, 1024):
        r(out / "svg/gnb-monogram.svg", png / f"gnb-monogram-{sz}.png", sz)
    for sz in (256, 512):
        r(out / "svg/gnb-token.svg", png / f"gnb-token-{sz}.png", sz)
    r(out / "svg/gnb-monogram.svg", fav / "apple-touch-icon.png", 180)
    r(out / "svg/gnb-monogram.svg", fav / "icon-192.png", 192)
    r(out / "svg/gnb-monogram.svg", fav / "icon-512.png", 512)
    for sz in (16, 32, 48):
        r(fav / "favicon.svg", fav / f"favicon-{sz}.png", sz)
    ims = [Image.open(fav / f"favicon-{sz}.png") for sz in (16, 32, 48)]
    ims[2].save(fav / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)], append_images=ims[:2])
    r(out / "social/og-image.svg", out / "social/og-image.png", 1200)


if __name__ == "__main__":
    import shutil
    kit = ROOT / "kit"
    shutil.rmtree(kit, ignore_errors=True)
    for p in build_kit(kit):
        print(p.relative_to(ROOT))
    export_rasters(kit)
    print("rasters ok")
