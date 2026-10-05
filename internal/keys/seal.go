package keys

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// SealedTag is the one line of a key file sealed by a [Sealer].
const SealedTag = "juist-sealed-v1"

// A Sealer encrypts key files at rest under a key the platform holds and will
// not hand out, as Android's Keystore does.
type Sealer interface {
	Seal(plain []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

var sealer atomic.Pointer[Sealer]

// SealWith has s seal every key file written from now on and open every
// sealed one read, for the whole process; nil seals none.
func SealWith(s Sealer) {
	if s == nil {
		sealer.Store(nil)
		return
	}
	sealer.Store(&s)
}

// sealLines is lines as written: sealed where a [Sealer] is set.
func sealLines(lines []string) ([]string, error) {
	plain := strings.Join(lines, "\n") + "\n"
	s := sealer.Load()
	if s == nil {
		return lines, nil
	}
	sealed, err := (*s).Seal([]byte(plain))
	if err != nil {
		return nil, fmt.Errorf("sealing key material: %w", err)
	}
	return []string{"# juist key material, sealed by this device's keystore", SealedTag + " " + B64.EncodeToString(sealed)}, nil
}

// SealText is a secret file's text as written: sealed where a [Sealer] is
// set, as key files are.
func SealText(text string) (string, error) {
	lines, err := sealLines(strings.Split(strings.TrimSuffix(text, "\n"), "\n"))
	if err != nil {
		return "", err
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// OpenText is the text of the secret file at path, read as text, opened
// where it is sealed.
func OpenText(path, text string) (string, error) { return unseal(path, text) }

// unseal is a key file's text, opened where it is sealed.
func unseal(path string, text string) (string, error) {
	var sealed string
	for line := range strings.Lines(text) {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, SealedTag+" "); ok {
			sealed = rest
			break
		}
	}
	if sealed == "" {
		return text, nil
	}
	s := sealer.Load()
	if s == nil {
		return "", fmt.Errorf("%s is sealed by a device keystore, which only the app that wrote it can open", path)
	}
	b, err := B64.DecodeString(sealed)
	if err != nil {
		return "", fmt.Errorf("%s: decoding the sealed key material: %w", path, err)
	}
	plain, err := (*s).Open(b)
	if err != nil {
		return "", fmt.Errorf("%s: opening the sealed key material: %w", path, err)
	}
	if strings.Contains(string(plain), SealedTag) {
		return "", errors.New(path + ": sealed key material sealed again")
	}
	return string(plain), nil
}
