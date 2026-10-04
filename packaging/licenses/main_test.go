package main

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestThirdPartyLicensesAreCurrent(t *testing.T) {
	want, err := render()
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../THIRD_PARTY_LICENSES")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("THIRD_PARTY_LICENSES is out of date; run make licenses")
	}
}

// The fonts juist embeds come under the OFL, which has to travel with them.
func TestEmbeddedFontsCarryTheirLicense(t *testing.T) {
	b, err := render()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("SIL OPEN FONT LICENSE Version 1.1")) {
		t.Fatal("THIRD_PARTY_LICENSES lacks the OFL of the embedded IBM Plex fonts")
	}
}

func TestPlatformsAreTheMakefiles(t *testing.T) {
	b, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^CROSS_PLATFORMS \?= (.*)$`).FindSubmatch(b)
	if m == nil {
		t.Fatal("the Makefile sets no CROSS_PLATFORMS")
	}
	if got, want := strings.Join(platforms, " "), string(m[1]); got != want {
		t.Fatalf("platforms %q, Makefile's CROSS_PLATFORMS %q", got, want)
	}
}
