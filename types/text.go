package types

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FoldName maps a name to the one form of every name strings.EqualFold holds
// equal to it: each rune to the smallest in its case-folding orbit. Two
// holders whose names fold alike are refused, since a person reading them
// could not tell them apart.
func FoldName(s string) string {
	var b strings.Builder
	for _, r := range s {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		b.WriteRune(least)
	}
	return b.String()
}

// ValidateName checks a human label — on a node record or an admin key: valid
// UTF-8, no control characters, no surrounding whitespace, within [MaxNameLen].
// Names are attacker-supplied strings that reach operator-facing output, so
// control characters are rejected here rather than escaped at every print site.
// Exported so tooling can ask before it persists a name.
func ValidateName(s string) error { return ValidateText("name", s, MaxNameLen) }

// ValidateText applies [ValidateName]'s rules to any attacker-supplied string
// bound for operator-facing output, with its own length limit. what names the
// string in the error.
func ValidateText(what, s string, limit int) error {
	if len(s) > limit {
		return fmt.Errorf("%s is %d bytes, over the %d limit", what, len(s), limit)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%s is not valid UTF-8", what)
	}
	for _, r := range s {
		// Unicode Cc, plus DEL, plus the bidi and zero-width formatting
		// characters (Cf) that make one string display as another.
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			(r >= 0x200b && r <= 0x200f) || (r >= 0x202a && r <= 0x202e) ||
			(r >= 0x2066 && r <= 0x2069) || r == 0xfeff {
			return fmt.Errorf("%s contains the control or formatting character U+%04X", what, r)
		}
	}
	if trimmed := trimSpace(s); trimmed != s {
		return fmt.Errorf("%s has leading or trailing whitespace", what)
	}
	return nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
