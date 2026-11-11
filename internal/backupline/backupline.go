// Package backupline writes a secret as one line a person keeps, in a
// password manager or a file, and reads it back.
package backupline

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/text/unicode/norm"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/types"
)

// Tags of the lines: what a line holds, and in which version of the line.
const (
	AdminKey   = "juist-admin-key-1"
	BreakGlass = "juist-break-glass-1"

	// SealedAdminKey is an admin key sealed by a password.
	SealedAdminKey = "juist-admin-sealed-1"
)

var b64 = keys.B64

// Line is payload as one line: tag.payload.checksum, the checksum covering
// the rest so that a line cut short fails to read.
func Line(tag string, payload []byte) string {
	body := tag + "." + b64.EncodeToString(payload)
	return body + "." + checksum(body)
}

func checksum(body string) string {
	sum := sha256.Sum256([]byte(body))
	return b64.EncodeToString(sum[:4])
}

// Tag is the tag line carries, "" where it is no line juist wrote.
func Tag(line string) string {
	parts := strings.Split(strings.TrimSpace(line), ".")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "juist-") {
		return ""
	}
	return parts[0]
}

// ErrDamaged says a line was cut short or changed.
var ErrDamaged = errors.New("the line is damaged or cut short; paste it whole")

// Parse returns the payload of a line Line wrote under tag.
func Parse(line, tag string) ([]byte, error) {
	line = strings.TrimSpace(line)
	parts := strings.Split(line, ".")
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "juist-") {
		return nil, errors.New("not a line juist exported")
	}
	if parts[0] != tag {
		for _, l := range []struct{ tag, what, cmd string }{
			{AdminKey, "an admin key", "juist admins import NAME"},
			{SealedAdminKey, "an admin key sealed by a password", "juist admins import NAME"},
			{BreakGlass, "a break-glass secret", "juist network disable"},
		} {
			if parts[0] == l.tag {
				return nil, fmt.Errorf("the line holds %s\nhint: %s", l.what, l.cmd)
			}
		}
		return nil, fmt.Errorf("the line is %s, which this juist does not read", parts[0])
	}
	if checksum(parts[0]+"."+parts[1]) != parts[2] {
		return nil, ErrDamaged
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, ErrDamaged
	}
	return payload, nil
}

// The password's key: Argon2id at a cost a phone pays in about a second.
const (
	saltSize   = 16
	kdfTime    = 3
	kdfMemory  = 64 * 1024
	kdfThreads = 4
	// MinPassword is the shortest password Seal takes.
	MinPassword = 12
)

var sealAD = []byte(types.LabelSealedAdminKey)

// Seal is secret as a [SealedAdminKey] line, which only password opens.
func Seal(secret []byte, password string) (string, error) {
	if len([]rune(norm.NFC.String(password))) < MinPassword {
		return "", fmt.Errorf("the password needs at least %d characters", MinPassword)
	}
	salt := make([]byte, saltSize)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	aead, err := chacha20poly1305.NewX(passwordKey(password, salt))
	if err != nil {
		return "", err
	}
	payload := append(append(salt, nonce...), aead.Seal(nil, nonce, secret, sealAD)...)
	return Line(SealedAdminKey, payload), nil
}

// ErrPassword says a sealed line did not open under the password given.
var ErrPassword = errors.New("wrong password, or the line was changed")

// Open is the secret a [SealedAdminKey] line holds, under password.
func Open(line, password string) ([]byte, error) {
	payload, err := Parse(line, SealedAdminKey)
	if err != nil {
		return nil, err
	}
	if len(payload) < saltSize+chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, ErrDamaged
	}
	salt, rest := payload[:saltSize], payload[saltSize:]
	nonce, sealed := rest[:chacha20poly1305.NonceSizeX], rest[chacha20poly1305.NonceSizeX:]
	aead, err := chacha20poly1305.NewX(passwordKey(password, salt))
	if err != nil {
		return nil, err
	}
	secret, err := aead.Open(nil, nonce, sealed, sealAD)
	if err != nil {
		return nil, ErrPassword
	}
	return secret, nil
}

// passwordKey is the key password opens, typed composed or decomposed alike.
func passwordKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(norm.NFC.String(password)), salt, kdfTime, kdfMemory, kdfThreads, chacha20poly1305.KeySize)
}
