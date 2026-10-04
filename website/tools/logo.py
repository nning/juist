#!/usr/bin/env python3
"""Writes design/logo/*.svg from IBM Plex Mono SemiBold's glyphs:

    go run ./tools/glyphs IBMPlexMono-SemiBold.ttf 'ȷuıstji' > /tmp/mono.txt
    python3 tools/logo.py /tmp/mono.txt
"""
import os, re, sys

here = os.path.dirname(os.path.abspath(__file__))
g = {}
for l in open(sys.argv[1]).read().splitlines():
    m = re.match(r"glyph '(.)' adv ([\d.]+) d (.*)", l)
    if m:
        g[m.group(1)] = m.group(3)
word = ''.join(g[c] for c in 'ȷuıst')
# The icon: dotless j and i side by side, their tittles linked.
ji = g['ȷ'] + re.sub(r'(-?\d+\.?\d*),', lambda m: f'{float(m.group(1))-1298+600:.1f},', g['ı'])
d=os.path.join(here, '..', '..', 'design', 'logo') + '/'
src='<!-- Glyphs of IBM Plex Mono SemiBold (OFL), dotless; the tittles are two linked nodes. -->\n'
link=lambda x1,x2,c,sw=26,r=82: f'<line x1="{x1}" y1="-673" x2="{x2}" y2="-673" stroke="{c}" stroke-width="{sw}" stroke-linecap="round"/><circle cx="{x1}" cy="-673" r="{r}" fill="{c}"/><circle cx="{x2}" cy="-673" r="{r}" fill="{c}"/>'
# The wordmark takes currentColor and --mark-link, so a page colours it.
open(d+'wordmark.svg','w').write(src+f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="80 -770 2860 980"><path d="{word}" fill="currentColor"/><g class="link">{link(373,1532,"var(--mark-link, #46d1bf)")}</g></svg>\n')
# The glyphs span x 91..1054, y -750..200; 560 of 1000 keeps them in the adaptive icon's safe zone.
s=560/963; tx,ty=500-572*s,500+275*s
body=lambda ink,c: f'<g transform="translate({tx:.1f} {ty:.1f}) scale({s:.4f})"><path d="{ji}" fill="{ink}"/>{link(373,932,c,30,90)}</g>'
open(d+'icon.svg','w').write(src+f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000"><rect width="1000" height="1000" rx="220" fill="#0a1317"/>{body("#e4dccb","#46d1bf")}</svg>\n')
open(d+'icon-day.svg','w').write(src+f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000"><rect width="1000" height="1000" rx="220" fill="#f6f0e1"/>{body("#17262b","#0b7268")}</svg>\n')
open(d+'icon-mono.svg','w').write(src+f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000">{body("#000","#000")}</svg>\n')
