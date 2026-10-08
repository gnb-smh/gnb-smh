# GnB-SMH brand kit, v0.1

GnB-SMH (Gödel and Bell Sequential Memory-Hard) is the proof-of-work of GnB, a hard fork of Bloch.
The identity is derived from the Bloch Inc wordmark: the same geometric letters, and the same
gesture of curved strokes turning into ribbons. Bloch paints them lime; GnB-SMH paints them
fluorescent orange, on black.

All marks are outlines. No font is needed to render any file in this kit.

## Files

| Path | Use |
| --- | --- |
| `svg/gnb-smh-wordmark.svg` | Primary wordmark, transparent ground, for black backgrounds |
| `svg/gnb-smh-wordmark-on-black.svg` | Primary wordmark with its black ground and clear space |
| `svg/gnb-smh-wordmark-flat.svg` | Solid ribbons, no gradients: below 160 px, print, embroidery |
| `svg/gnb-smh-wordmark-on-white.svg` | Black letters, flat ribbons: the colour version for light grounds |
| `svg/gnb-smh-wordmark-mono-white.svg`, `-mono-black.svg` | One-colour versions |
| `svg/gnb-wordmark*.svg` | Short form "GnB" for the coin and ticker |
| `svg/gnb-monogram.svg`, `-flat.svg` | The ribbon n on a black tile: app icon, avatar |
| `svg/gnb-token.svg` | The ribbon n in a circle: wallets, explorers, exchanges |
| `png/` | Raster exports (1200 and 2400 px wordmarks, 512/1024 monogram, 256/512 token) |
| `favicon/` | favicon.svg, favicon.ico (16/32/48), apple-touch-icon, 192 and 512 icons |
| `social/og-image.png` | 1200 x 630 link-preview card |

## Colour

| Name | Value | Use |
| --- | --- | --- |
| GnB Black | `#000000` | The ground |
| White | `#FFFFFF` | Letters and text |
| GnB Fluor | `#FF5F15` | Ribbons and one accent per view (6.9:1 on black) |
| Ash | `#A0958D` | Secondary text (7.2:1 on black) |
| Ribbon highlight | `#FFB547` | Crest of the n, top of the B bowl |
| Ribbon shade | `#F04A00` | Lower legs, waist of the B |
| Ribbon fold | `#7A1E00` | Underside of the ribbon |

Screen value only: for print, use a fluorescent orange spot ink. CMYK cannot reproduce it.

## Type

Poppins (wordmark and headings, 600/700), Figtree (running text), JetBrains Mono (parameters,
code, data). All three are under the SIL Open Font License 1.1.

## Rules

- Clear space around the wordmark: the height of its G.
- Ribbon wordmark from 160 px wide; flat wordmark below that.
- Monogram down to 48 px; flat favicon below 48 px.
- Only the n and the B carry ribbons. Never recolour them, and never use the Bloch lime.
- The gradient wordmark goes on black. On light grounds use the "on white" version.

## Regenerating

`brand.py` (Python 3, fontTools, uharfbuzz, cairosvg) rebuilds every file from the Poppins font
files: `python3 brand.py`.
