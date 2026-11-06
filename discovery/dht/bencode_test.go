package dht

import (
	"strings"
	"testing"

	"github.com/anacrolix/torrent/bencode"
)

// Every DHT message and item is decoded by bencode, from anyone on the DHT:
// a value nested past its bound is refused rather than recursed into until
// the stack overflows, which no recover catches (GO-2026-6894).
func TestTheDHTsDecoderBoundsHowDeepItGoes(t *testing.T) {
	deep := strings.Repeat("l", 10_000) + strings.Repeat("e", 10_000)
	var v any
	if err := bencode.Unmarshal([]byte(deep), &v); err == nil {
		t.Fatal("a list nested 10 000 deep was decoded")
	}
	shallow := strings.Repeat("l", 8) + strings.Repeat("e", 8)
	if err := bencode.Unmarshal([]byte(shallow), &v); err != nil {
		t.Errorf("a list nested 8 deep: %v", err)
	}
}
