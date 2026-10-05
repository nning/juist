package main

import (
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"rsc.io/qr"

	"github.com/nning/juist/trust/enroll"
)

var sgrRE = regexp.MustCompile("\x1b\\[[0-9;]*m")

// readQR reads back the modules of the QR code drawn in out, true for dark,
// quiet zone included.
func readQR(t *testing.T, out string) [][]bool {
	t.Helper()
	var rows [][]bool
	for l := range strings.Lines(sgrRE.ReplaceAllString(out, "")) {
		l = strings.TrimSuffix(strings.TrimPrefix(l, "  "), "\n")
		if !strings.ContainsAny(l, "█▀▄") || strings.Trim(l, "█▀▄ ") != "" {
			if rows != nil {
				break
			}
			continue
		}
		var top, bottom []bool
		for _, r := range l {
			top = append(top, r != '█' && r != '▀')
			bottom = append(bottom, r != '█' && r != '▄')
		}
		rows = append(rows, top, bottom)
	}
	if rows == nil {
		t.Fatalf("no qr code drawn:\n%s", out)
	}
	if n := len(rows[0]); len(rows) == n+1 {
		rows = rows[:n]
	}
	return rows
}

// checkQR fails unless out draws text as a QR code, inside a quiet zone.
func checkQR(t *testing.T, out, text string) {
	t.Helper()
	got := readQR(t, out)
	want, err := qr.Encode(text, qr.L)
	if err != nil {
		t.Fatal(err)
	}
	n := want.Size + 2*qrQuiet
	if len(got) != n {
		t.Fatalf("drawn %d modules high, want %d:\n%s", len(got), n, out)
	}
	for y, row := range got {
		if len(row) != n {
			t.Fatalf("row %d is %d modules wide, want %d", y, len(row), n)
		}
		for x, dark := range row {
			if dark != want.Black(x-qrQuiet, y-qrQuiet) {
				t.Fatalf("module %d,%d drawn dark=%v, the code's is not:\n%s", x, y, dark, out)
			}
		}
	}
}

// The code an invite draws holds the link a device joins with.
func TestTheInviteDrawsItsLinkAsAQRCode(t *testing.T) {
	t.Parallel()
	admin := newCLI(t)
	admin.mustRun("create", "home", "--device", "laptop")
	admin.terminal = true
	inv, link := startInvite(t, admin)
	checkQR(t, inv.out.String(), link)

	newCLI(t).mustRun("join", link, "--name", "phone")
	if out, err := inv.wait(t); err != nil {
		t.Fatalf("invite: %v\n%s", err, out)
	}
}

func TestQRCodeOnlyOnATerminal(t *testing.T) {
	t.Parallel()
	link, err := enroll.NewLink([]netip.AddrPort{
		netip.MustParseAddrPort("[fd00::1]:41642"), netip.MustParseAddrPort("192.168.1.20:41642")})
	if err != nil {
		t.Fatal(err)
	}
	o := inviteOptions{expires: time.Hour}
	c := newCLI(t)

	var piped syncBuffer
	c.app(&piped, "").announceInvite("home", "", link, DefaultInvitePort, o)
	if strings.ContainsAny(piped.String(), "█▀▄") || strings.Contains(piped.String(), "qr code") {
		t.Fatalf("a qr code piped:\n%s", piped.String())
	}

	c.terminal = true
	var term syncBuffer
	c.app(&term, "").announceInvite("home", "", link, DefaultInvitePort, o)
	checkQR(t, term.String(), link.String())

	var narrow syncBuffer
	a := c.app(&narrow, "")
	a.width = 40
	a.announceInvite("home", "", link, DefaultInvitePort, o)
	if strings.ContainsAny(narrow.String(), "█▀▄") {
		t.Fatalf("a qr code wider than the terminal:\n%s", narrow.String())
	}
	mustContain(t, narrow.String(), "no qr code: the terminal is narrower than")
}
