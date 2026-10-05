package main

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// qrQuiet is the margin of light modules the QR standard asks for.
const qrQuiet = 4

// qrBlocks renders text as a QR code, two module rows to a line, light
// modules drawn and dark ones left blank: the right way round on a dark
// terminal, and on any once colours pin the two.
func qrBlocks(text string) ([]string, error) {
	// L: a screen does not smudge, and a smaller code scans from further away.
	c, err := qr.Encode(text, qr.L)
	if err != nil {
		return nil, err
	}
	n := c.Size + 2*qrQuiet
	light := func(x, y int) bool { return y < n && !c.Black(x-qrQuiet, y-qrQuiet) }
	lines := make([]string, 0, (n+1)/2)
	for y := 0; y < n; y += 2 {
		var b strings.Builder
		for x := range n {
			top, bottom := light(x, y), light(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteByte(' ')
			}
		}
		lines = append(lines, b.String())
	}
	return lines, nil
}

// showQR prints text as a QR code where out is a terminal wide enough for it.
func (a *app) showQR(text string) {
	if !a.terminal {
		return
	}
	lines, err := qrBlocks(text)
	if err != nil {
		return
	}
	if w := 2 + len([]rune(lines[0])); a.width > 0 && w > a.width {
		a.printf("%s\n\n", a.dim(fmt.Sprintf("no qr code: the terminal is narrower than %d columns", w)))
		return
	}
	for i, l := range lines {
		colours := "97;40"
		// A code's side is odd: the last line's lower half is outside it.
		if i == len(lines)-1 {
			colours = "97;49"
		}
		a.printf("  %s\n", a.paint(colours, l))
	}
	a.printf("\n")
}
