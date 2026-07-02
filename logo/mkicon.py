#!/usr/bin/env python3
"""Generate ../vordr.ico from the shield/keyhole design (mirrors vordr.svg).

Dev-only tooling (not part of the app build).  Requires Pillow + numpy:
    python -m pip install pillow numpy
    python logo/mkicon.py
"""
import os
import numpy as np
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
OUT  = os.path.join(HERE, "..", "vordr.ico")

R = 1024                      # render resolution (supersample for the 256 icon)
S = R / 512.0                 # design (512) -> render scale

# The bare shield (#v-shape) spans y in [127,398] (top Bezier bulge -> bottom
# tip) and x in [148,364].  Scale it up about the canvas centre so it fills the
# tile top-to-bottom (y 0..512) with no room above/below, aspect ratio kept.
SH_S = 512.0 / 271.0          # 271 = 398 - 127
def T(x, y):
    return (256 + SH_S*(x-256), SH_S*(y-127))

def hx(c):
    return tuple(int(c[i:i+2], 16) for i in (0, 2, 4))

def quad(p0, c, p1, n=24):
    return [((1-t)**2*p0[0]+2*(1-t)*t*c[0]+t*t*p1[0],
             (1-t)**2*p0[1]+2*(1-t)*t*c[1]+t*t*p1[1]) for t in np.linspace(0, 1, n)]

def cubic(p0, c1, c2, p1, n=40):
    return [((1-t)**3*p0[0]+3*(1-t)**2*t*c1[0]+3*(1-t)*t*t*c2[0]+t**3*p1[0],
             (1-t)**3*p0[1]+3*(1-t)**2*t*c1[1]+3*(1-t)*t*t*c2[1]+t**3*p1[1]) for t in np.linspace(0, 1, n)]

def sc(pts):
    return [(x*S, y*S) for (x, y) in pts]

# shield outline (matches the SVG #v-shape path), scaled to fill the tile
shield  = quad(T(148,158),T(148,140),T(166,136))
shield += cubic(T(166,136),T(210,124),T(302,124),T(346,136))
shield += quad(T(346,136),T(364,140),T(364,158))
shield += [T(364,250)]
shield += cubic(T(364,250),T(364,318),T(322,364),T(256,398))
shield += cubic(T(256,398),T(190,364),T(148,318),T(148,250))
# top sheen outline
sheen  = cubic(T(166,136),T(210,124),T(302,124),T(346,136))
sheen += quad(T(346,136),T(360,140),T(360,156))
sheen += cubic(T(360,156),T(300,142),T(212,142),T(152,156))
sheen += quad(T(152,156),T(152,140),T(166,136))

# transparent canvas: only the shield is drawn (no tile / background)
base = Image.new("RGBA", (R, R), (0, 0, 0, 0))

# gold shield with keyhole punched through
shield_mask = Image.new("L", (R, R), 0)
md = ImageDraw.Draw(shield_mask)
md.polygon(sc(shield), fill=255)
kcx, kcy = T(256, 231); kr = 33*SH_S
md.ellipse([(kcx-kr)*S, (kcy-kr)*S, (kcx+kr)*S, (kcy+kr)*S], fill=0)
md.polygon(sc([T(239,255),T(273,255),T(288,324),T(224,324)]), fill=0)

gstops = [(T(0,124)[1], hx("ffd96b")), (T(0,275)[1], hx("f6b22e")), (T(0,398)[1], hx("e8920a"))]
col = np.zeros((R, 3), np.float64)
ys = np.arange(R) / S
for i in range(len(gstops)-1):
    a, ca = gstops[i]; b, cb = gstops[i+1]
    f = np.clip((ys - a) / (b - a), 0, 1)
    seg = (ys >= a) if i == len(gstops)-2 else ((ys >= a) & (ys <= b))
    for k in range(3):
        col[seg, k] = ca[k] + (cb[k]-ca[k]) * f[seg]
col[ys < gstops[0][0]] = gstops[0][1]
gold = Image.fromarray(np.repeat(col[:, None, :], R, axis=1).astype(np.uint8), "RGB")
base.paste(gold.convert("RGBA"), (0, 0), shield_mask)

# top sheen, confined to the shield
sheen_mask = Image.new("L", (R, R), 0)
ImageDraw.Draw(sheen_mask).polygon(sc(sheen), fill=41)
base = Image.alpha_composite(base, Image.composite(
    Image.new("RGBA", (R, R), (255, 255, 255, 255)),
    Image.new("RGBA", (R, R), (0, 0, 0, 0)), sheen_mask))

# shield only -> export straight to the .ico (alpha already carries the shape)
base.save(OUT, format="ICO",
          sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)])
print("wrote", os.path.normpath(OUT))
