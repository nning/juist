package backupline

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestALineReadsBackAndACutOneDoesNot(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, 32)
	line := Line(AdminKey, secret)
	got, err := Parse(line, AdminKey)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Parse = %x, %v", got, err)
	}
	if _, err := Parse(line[:len(line)-3], AdminKey); !errors.Is(err, ErrDamaged) {
		t.Errorf("a cut line: %v", err)
	}
	if _, err := Parse(line, BreakGlass); err == nil || !strings.Contains(err.Error(), "holds an admin key") {
		t.Errorf("an admin key read as a break-glass secret: %v", err)
	}
	if Tag(line) != AdminKey || Tag("hello") != "" {
		t.Errorf("Tag(%q) = %q", line, Tag(line))
	}
}

// A sealed line opens under its password alone, and is no line of the key
// in the clear.
func TestASealedLineOpensUnderItsPasswordAlone(t *testing.T) {
	secret := bytes.Repeat([]byte{9}, 32)
	if _, err := Seal(secret, "short"); err == nil {
		t.Error("a short password sealed")
	}
	line, err := Seal(secret, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if Tag(line) != SealedAdminKey {
		t.Errorf("tag %q", Tag(line))
	}
	if _, err := Parse(line, AdminKey); err == nil {
		t.Error("a sealed line reads as a key in the clear")
	}
	got, err := Open(line, "correct horse battery")
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open = %x, %v", got, err)
	}
	if _, err := Open(line, "correct horse batterY"); !errors.Is(err, ErrPassword) {
		t.Errorf("another password: %v", err)
	}
	other, _ := Seal(secret, "correct horse battery")
	if other == line {
		t.Error("two seals of one key are the same line")
	}
}

// A password opens its line typed composed or decomposed, as a phone's
// keyboard and a computer's may type it.
func TestAPasswordOpensItsLineHoweverItIsComposed(t *testing.T) {
	secret := bytes.Repeat([]byte{3}, 32)
	composed, decomposed := "gr\u00fc\u00dfe aus juist", "gru\u0308\u00dfe aus juist"
	line, err := Seal(secret, composed)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := Open(line, decomposed); err != nil || !bytes.Equal(got, secret) {
		t.Errorf("decomposed: %x, %v", got, err)
	}
}
