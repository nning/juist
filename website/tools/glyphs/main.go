// glyphs FONT TEXT prints each rune's outline as an SVG path, in font units
// with y down, and its advance.
package main

import (
	"fmt"
	"os"

	"golang.org/x/image/font"
	"golang.org/x/image/font/sfnt"
	"golang.org/x/image/math/fixed"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	f, err := sfnt.Parse(b)
	if err != nil {
		panic(err)
	}
	var buf sfnt.Buffer
	ppem := fixed.I(int(f.UnitsPerEm()))
	x := fixed.Int26_6(0)
	fmt.Printf("upem %d\n", f.UnitsPerEm())
	for _, r := range os.Args[2] {
		gi, err := f.GlyphIndex(&buf, r)
		if err != nil || gi == 0 {
			panic(fmt.Sprintf("no glyph for %q", r))
		}
		segs, err := f.LoadGlyph(&buf, gi, ppem, nil)
		if err != nil {
			panic(err)
		}
		adv, _ := f.GlyphAdvance(&buf, gi, ppem, font.HintingNone)
		p := func(q fixed.Point26_6) string {
			return fmt.Sprintf("%.1f,%.1f", float64(q.X+x)/64, float64(q.Y)/64)
		}
		fmt.Printf("glyph %q adv %.1f d ", r, float64(adv)/64)
		for _, s := range segs {
			switch s.Op {
			case sfnt.SegmentOpMoveTo:
				fmt.Printf("M%s", p(s.Args[0]))
			case sfnt.SegmentOpLineTo:
				fmt.Printf("L%s", p(s.Args[0]))
			case sfnt.SegmentOpQuadTo:
				fmt.Printf("Q%s %s", p(s.Args[0]), p(s.Args[1]))
			case sfnt.SegmentOpCubeTo:
				fmt.Printf("C%s %s %s", p(s.Args[0]), p(s.Args[1]), p(s.Args[2]))
			}
		}
		fmt.Println("Z")
		x += adv
	}
	m, _ := f.Metrics(&buf, ppem, font.HintingNone)
	fmt.Printf("ascent %.1f descent %.1f xheight %.1f\n", float64(m.Ascent)/64, float64(m.Descent)/64, float64(m.XHeight)/64)
}
