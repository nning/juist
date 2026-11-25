package tray

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"sync"
)

// The icon is the logo (website/static/favicon.svg): "ji" on a dark rounded
// square, the tittles two linked nodes. Its coordinates are the logo's, on
// a side of 1000.
var (
	ground = color.NRGBA{0x0a, 0x13, 0x17, 0xff}
	cream  = color.NRGBA{0xe4, 0xdc, 0xcb, 0xff}
	teal   = color.NRGBA{0x46, 0xd1, 0xbf, 0xff}
	dimmed = color.NRGBA{0x7d, 0x7a, 0x72, 0xff}
	grey   = color.NRGBA{0x5c, 0x61, 0x66, 0xff}
	amber  = color.NRGBA{0xf2, 0xa9, 0x00, 0xff}
	red    = color.NRGBA{0xe0, 0x36, 0x36, 0xff}
)

const iconSize = 64

// A shape covers the points inside reports, in the logo's coordinates.
type shape struct {
	inside func(x, y float64) bool
	c      color.NRGBA
}

func circle(cx, cy, r float64, c color.NRGBA) shape {
	return shape{func(x, y float64) bool { return math.Hypot(x-cx, y-cy) <= r }, c}
}

func segment(ax, ay, bx, by, w float64, c color.NRGBA) shape {
	return shape{func(x, y float64) bool {
		dx, dy := bx-ax, by-ay
		t := math.Max(0, math.Min(1, ((x-ax)*dx+(y-ay)*dy)/(dx*dx+dy*dy)))
		return math.Hypot(x-ax-t*dx, y-ay-t*dy) <= w/2
	}, c}
}

func roundedSquare(side, r float64, c color.NRGBA) shape {
	return shape{func(x, y float64) bool {
		qx, qy := math.Max(math.Abs(x-side/2)-(side/2-r), 0), math.Max(math.Abs(y-side/2)-(side/2-r), 0)
		return math.Hypot(qx, qy) <= r
	}, c}
}

// polygon is the even-odd fill of pts.
func polygon(pts [][2]float64, c color.NRGBA) shape {
	return shape{func(x, y float64) bool {
		in := false
		for i, j := 0, len(pts)-1; i < len(pts); j, i = i, i+1 {
			a, b := pts[i], pts[j]
			if (a[1] > y) != (b[1] > y) && x < (b[0]-a[0])*(y-a[1])/(b[1]-a[1])+a[0] {
				in = !in
			}
		}
		return in
	}, c}
}

// glyph places the logo's glyph coordinates, which its SVG translates by
// (167.4, 659.9) and scales by 0.5815; a point of four numbers is a
// quadratic curve's control point and end, drawn in eight steps.
func glyph(path [][]float64) [][2]float64 {
	at := func(x, y float64) [2]float64 { return [2]float64{167.4 + 0.5815*x, 659.9 + 0.5815*y} }
	var out [][2]float64
	for _, p := range path {
		if len(p) == 2 {
			out = append(out, at(p[0], p[1]))
			continue
		}
		last := out[len(out)-1]
		c, e := at(p[0], p[1]), at(p[2], p[3])
		for i := 1; i <= 8; i++ {
			t := float64(i) / 8
			out = append(out, [2]float64{
				(1-t)*(1-t)*last[0] + 2*(1-t)*t*c[0] + t*t*e[0],
				(1-t)*(1-t)*last[1] + 2*(1-t)*t*c[1] + t*t*e[1],
			})
		}
	}
	return out
}

var (
	glyphJ = glyph([][]float64{{95, 99}, {308, 99}, {308, -415}, {91, -415}, {91, -516}, {436, -516}, {436, 60},
		{436, 122, 401, 161}, {366, 200, 292, 200}, {95, 200}})
	glyphI = glyph([][]float64{{600, -101}, {770, -101}, {770, -415}, {600, -415}, {600, -516}, {898, -516},
		{898, -101}, {1056, -101}, {1056, 0}, {600, 0}})
	nodeA, nodeB = glyph([][]float64{{373, -673}})[0], glyph([][]float64{{932, -673}})[0]
)

func shapes(ic icon) []shape {
	letters, link := cream, teal
	if ic.base == baseOff {
		letters, link = dimmed, grey
	}
	s := []shape{
		roundedSquare(1000, 220, ground),
		polygon(glyphJ, letters),
		polygon(glyphI, letters),
		segment(nodeA[0], nodeA[1], nodeB[0], nodeB[1], 0.5815*30, link),
		circle(nodeA[0], nodeA[1], 0.5815*90, link),
		circle(nodeB[0], nodeB[1], 0.5815*90, link),
	}
	if ic.base == baseExit {
		// An arrow out of the top right corner: traffic leaves by another.
		s = append(s, circle(840, 160, 175, ground), circle(840, 160, 140, teal),
			segment(780, 220, 885, 115, 50, ground),
			polygon([][2]float64{{915, 85}, {915, 195}, {805, 85}}, ground))
	}
	if ic.badge != badgeNone {
		b := amber
		if ic.badge == badgeAlarm {
			b = red
		}
		s = append(s, circle(840, 840, 175, ground), circle(840, 840, 140, b))
	}
	return s
}

var (
	iconsMu sync.Mutex
	icons   = map[icon][]byte{}
)

// iconPNG is the icon for ic, drawn once.
func iconPNG(ic icon) []byte {
	iconsMu.Lock()
	defer iconsMu.Unlock()
	if b, ok := icons[ic]; ok {
		return b
	}
	b := drawIcon(ic)
	icons[ic] = b
	return b
}

// drawIcon draws the icon, each pixel sampled 4×4 times for smooth edges.
func drawIcon(ic icon) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))
	sh := shapes(ic)
	const k = 4
	scale := 1000.0 / iconSize
	for py := range iconSize {
		for px := range iconSize {
			var r, g, b, a float64
			for sy := range k {
				for sx := range k {
					x := (float64(px) + (float64(sx)+0.5)/k) * scale
					y := (float64(py) + (float64(sy)+0.5)/k) * scale
					for i := len(sh) - 1; i >= 0; i-- {
						if sh[i].inside(x, y) {
							c := sh[i].c
							r, g, b, a = r+float64(c.R), g+float64(c.G), b+float64(c.B), a+1
							break
						}
					}
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(px, py, color.NRGBA{uint8(r / a), uint8(g / a), uint8(b / a), uint8(255 * a / (k * k))})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
