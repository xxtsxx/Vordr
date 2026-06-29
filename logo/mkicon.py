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

# shield outline (matches the SVG #v-shape path)
shield  = quad((148,158),(148,140),(166,136))
shield += cubic((166,136),(210,124),(302,124),(346,136))
shield += quad((346,136),(364,140),(364,158))
shield += [(364,250)]
shield += cubic((364,250),(364,318),(322,364),(256,398))
shield += cubic((256,398),(190,364),(148,318),(148,250))
# top sheen outline
sheen  = cubic((166,136),(210,124),(302,124),(346,136))
sheen += quad((346,136),(360,140),(360,156))
sheen += cubic((360,156),(300,142),(212,142),(152,156))
sheen += quad((152,156),(152,140),(166,136))

# background: warm-charcoal radial gradient
cx, cy, rad = 0.5*R, 0.32*R, 0.85*R
stops = [(0.00, hx("2b2620")), (0.58, hx("15110c")), (1.00, hx("050403"))]
yy, xx = np.mgrid[0:R, 0:R]
t = np.clip(np.sqrt((xx-cx)**2 + (yy-cy)**2) / rad, 0, 1)
bg = np.zeros((R, R, 3), np.float64)
for i in range(len(stops)-1):
    a, ca = stops[i]; b, cb = stops[i+1]
    m = (t >= a) if i == len(stops)-2 else ((t >= a) & (t <= b))
    f = np.clip((t - a) / (b - a), 0, 1)
    for k in range(3):
        bg[..., k] = np.where(m, ca[k] + (cb[k]-ca[k])*f, bg[..., k])
base = Image.fromarray(bg.astype(np.uint8), "RGB").convert("RGBA")

def overlay(draw_fn):
    lay = Image.new("RGBA", (R, R), (0, 0, 0, 0))
    draw_fn(ImageDraw.Draw(lay))
    return Image.alpha_composite(base, lay)

# scanning shine
base = overlay(lambda d: d.polygon(sc([(120,-40),(250,-40),(-40,250),(-40,120)]),
                                   fill=(255, 255, 255, 13)))

# gold shield with keyhole punched through
shield_mask = Image.new("L", (R, R), 0)
md = ImageDraw.Draw(shield_mask)
md.polygon(sc(shield), fill=255)
md.ellipse([(256-33)*S, (231-33)*S, (256+33)*S, (231+33)*S], fill=0)
md.polygon(sc([(239,255),(273,255),(288,324),(224,324)]), fill=0)

gstops = [(124, hx("ffd96b")), (275, hx("f6b22e")), (398, hx("e8920a"))]
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

# faint border
base = overlay(lambda d: d.rounded_rectangle(
    [2.5*S, 2.5*S, R-2.5*S, R-2.5*S], radius=109.5*S,
    outline=(255, 255, 255, 15), width=max(2, int(round(3*S)))))

# rounded-tile alpha + export
tile = Image.new("L", (R, R), 0)
ImageDraw.Draw(tile).rounded_rectangle([0, 0, R-1, R-1], radius=112*S, fill=255)
base.putalpha(tile)
base.save(OUT, format="ICO",
          sizes=[(256,256),(128,128),(64,64),(48,48),(32,32),(16,16)])
print("wrote", os.path.normpath(OUT))
