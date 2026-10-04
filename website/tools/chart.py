#!/usr/bin/env python3
"""Writes layouts/_partials/chart.html, the home page's chart of Juist, from
data/juist_outline.json (OpenStreetMap, ODbL)."""
import json, math, os

here = os.path.dirname(os.path.abspath(__file__))
o = json.load(open(os.path.join(here, '..', 'data', 'juist_outline.json')))
W, H = 1680, 860
ox, oy = 620, 300  # where the outline's origin sits in the scene
lon0, lon1 = o['lon']; lat0, lat1 = o['lat']
sx = o['W'] / (lon1 - lon0)                         # units per degree of longitude
sy = sx / math.cos(math.radians((lat0 + lat1) / 2))  # and of latitude
X = lambda lon: ox + (lon - lon0) * sx
Y = lambda lat: oy + (lat1 - lat) * sy
km = sx / (111.32 * math.cos(math.radians((lat0 + lat1) / 2)))
isl = f'<path id="isl" transform="translate({ox} {oy})" d="{o["path"]}"/>'

out = [f'<svg class="chart" viewBox="0 0 {W} {H}" preserveAspectRatio="xMaxYMid meet" '
       'xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" aria-hidden="true">',
       f'<defs>{isl}</defs>']
# Depth contours: a wide stroke in the contour colour under a slightly narrower
# one in the water's, so that a thin line remains at half the width's offset.
for off, fill in [(170, 'water'), (125, 'water'), (80, 'shallow')]:
    out.append(f'<use href="#isl" class="c-line" stroke-width="{2*off+1.4}"/>')
    out.append(f'<use href="#isl" class="c-{fill}" stroke-width="{2*off}"/>')
out.append('<use href="#isl" class="c-watt" stroke-width="46"/>')
out.append('<use href="#isl" class="c-land"/>')

# Graticule, every 2′ of longitude and 1′ of latitude.
g = ['<g class="grid">']
lab = ['<g class="glabel">']
m = math.ceil(lon0 * 60 / 2 - 4) * 2
while m / 60 < lon1 + 0.06:
    x = X(m / 60)
    if 0 < x < W:
        g.append(f'<line x1="{x:.1f}" y1="0" x2="{x:.1f}" y2="{H}"/>')
        d, mm = divmod(m, 60)
        lab.append(f'<text x="{x+4:.1f}" y="{H-10}">{d}°{mm:02d}′E</text>')
    m += 2
m = math.floor(lat0 * 60 - 3)
while m / 60 < lat1 + 0.05:
    y = Y(m / 60)
    if 0 < y < H:
        g.append(f'<line x1="0" y1="{y:.1f}" x2="{W}" y2="{y:.1f}"/>')
        d, mm = divmod(m, 60)
        lab.append(f'<text x="{W-8}" y="{y-5:.1f}" text-anchor="end">{d}°{mm:02d}′N</text>')
    m += 1
out += g + ['</g>'] + lab + ['</g>']

# A compass rose, true north up.
cx, cy, r = 1560, 720, 58
rose = [f'<g class="rose"><circle cx="{cx}" cy="{cy}" r="{r}"/><circle cx="{cx}" cy="{cy}" r="{r-14}"/>']
for deg in range(0, 360, 5):
    a = math.radians(deg)
    l = 10 if deg % 30 == 0 else 5 if deg % 10 == 0 else 2.5
    x1, y1 = cx + r * math.sin(a), cy - r * math.cos(a)
    x2, y2 = cx + (r - l) * math.sin(a), cy - (r - l) * math.cos(a)
    rose.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}"/>')
rose.append(f'<path class="needle" d="M{cx},{cy-r+16} L{cx+6},{cy} L{cx},{cy+r-16} L{cx-6},{cy}Z"/>')
rose.append(f'<text x="{cx}" y="{cy-r-6}" text-anchor="middle">N</text></g>')
out += rose

# A scale bar of 3 km.
bx, by = 760, 800
out.append('<g class="scale">')
for i in range(3):
    out.append(f'<rect x="{bx+i*km:.1f}" y="{by}" width="{km:.1f}" height="5" class="{"on" if i % 2 == 0 else "off"}"/>')
    out.append(f'<text x="{bx+i*km:.1f}" y="{by-6}">{i}</text>')
out.append(f'<text x="{bx+3*km:.1f}" y="{by-6}">3 km</text></g>')

# Devices: a node, its light's flare, its name and its address.
nodes = {'laptop': (1150, 368), 'nas': (840, 600), 'vps': (1480, 190), 'phone': (1420, 560), 'pi': (1130, 680)}
addr = {'laptop': '.1', 'nas': '.2', 'vps': '.3', 'phone': '.4', 'pi': '.5'}
names = list(nodes)
out.append('<g class="mesh">')
k = 0
for i, a in enumerate(names):
    for b in names[i + 1:]:
        (x1, y1), (x2, y2) = nodes[a], nodes[b]
        out.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}"/>')
out.append('</g><g class="packets">')
# Each packet's speed is its class's, in main.css: no inline style, for the CSP.
for i, (a, b) in enumerate([('laptop', 'vps'), ('nas', 'laptop'), ('phone', 'pi'), ('vps', 'phone'), ('nas', 'pi')], 1):
    (x1, y1), (x2, y2) = nodes[a], nodes[b]
    out.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" class="p{i}"/>')
out.append('</g><g class="nodes">')
for n, (x, y) in nodes.items():
    out.append(f'<g transform="translate({x} {y})"><path class="flare" d="M0,0 C4,-5 11,-16 9,-20 C6,-22 1,-14 0,0Z"/>'
               f'<circle r="9" class="halo"/><circle r="4.2"/>'
               f'<text x="14" y="18">{n}</text><text x="14" y="31" class="ip">198.18.36{addr[n]}</text></g>')
out.append('</g>')
out.append(f'<g class="cartouche"><text x="{X(6.995):.0f}" y="{Y(lat0)+64:.0f}" text-anchor="middle">JUIST</text></g>')
out.append('</svg>')
dst = os.path.join(here, '..', 'layouts', '_partials', 'chart.html')
open(dst, 'w').write('\n'.join(out) + '\n')
print(dst, f'{km:.1f} units/km')
