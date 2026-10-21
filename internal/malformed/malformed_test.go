package malformed

import (
	"strings"
	"testing"
)

func index(b []byte, i int) (v byte, err error) {
	defer Recover(&err)
	return b[i], nil
}

func deref(p *[1]byte) (ok bool) {
	defer RecoverOK(&ok)
	return p[0] == 0
}

func answer(b []byte) (v []byte) {
	defer RecoverWith(&v, func() []byte { return []byte("fallback") })
	return b[:1]
}

func TestAPanicIsAnError(t *testing.T) {
	if got := string(answer(nil)); got != "fallback" {
		t.Fatalf("a panicking answer gave %q, want the fallback", got)
	}
	if got := string(answer([]byte("ab"))); got != "a" {
		t.Fatalf("an answer that does not panic gave %q", got)
	}
	if _, err := index([]byte{1}, 3); err == nil || !strings.Contains(err.Error(), "malformed_test.go:") {
		t.Fatalf("an index out of range gave %v, want an error naming where", err)
	}
	if v, err := index([]byte{7}, 0); err != nil || v != 7 {
		t.Fatalf("a decoder that does not panic gave %v, %v", v, err)
	}
	if deref(nil) {
		t.Fatal("a nil dereference was reported ok")
	}
	if !deref(&[1]byte{}) {
		t.Fatal("a decoder that does not panic was reported not ok")
	}
}
