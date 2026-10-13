package enroll

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/nning/juist/types"
)

// A Secret is what a guest knows about an invite: a typed [Code] or a
// [Link]. Either runs the same key exchange; they differ in entropy and in
// how the guest finds the host.
type Secret interface {
	mode() mode
	password() []byte
	nameplate() uint16
}

type mode uint8

const (
	modeInvalid mode = 0
	modeCode    mode = 1
	modeLink    mode = 2
)

// Limits on the typed code.
const (
	// MaxNameplate bounds the number a code starts with. It only has to tell
	// concurrent invites on one network apart.
	MaxNameplate = 999

	// CodeWords is how many words a code carries: 24 bits, against an
	// attacker who gets one guess per invite.
	CodeWords = 3
)

// A Code is an invite in the form a person reads aloud or types:
// "42-drumbeat-tolerance-glucose". The nameplate says which invite it is and
// is not secret; the words are the password.
type Code struct {
	Nameplate uint16
	Words     [CodeWords]byte
}

// NetworkName draws a name for a network nobody named: two words of the PGP
// word list, one of each half, such as "belfast-hazardous", which is easier
// to say and to recall than a number and tells two networks apart.
func NetworkName() (string, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("enroll: drawing a network name: %w", err)
	}
	return wordAt(0, b[0]) + "-" + wordAt(1, b[1]), nil
}

// NewCode draws a code.
func NewCode() (Code, error) {
	var b [2 + CodeWords]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Code{}, fmt.Errorf("enroll: drawing an invite code: %w", err)
	}
	c := Code{Nameplate: binary.BigEndian.Uint16(b[:2])%MaxNameplate + 1}
	copy(c.Words[:], b[2:])
	return c, nil
}

func (c Code) String() string {
	parts := []string{strconv.Itoa(int(c.Nameplate))}
	for i, w := range c.Words {
		parts = append(parts, wordAt(i, w))
	}
	return strings.Join(parts, "-")
}

// ParseCode reads a typed code. It forgives what people do when typing one:
// capitals, and spaces instead of hyphens.
func ParseCode(s string) (Code, error) {
	fields := strings.FieldsFunc(strings.ToLower(strings.TrimSpace(s)), func(r rune) bool {
		return r == '-' || r == ' ' || r == '\t'
	})
	if len(fields) != 1+CodeWords {
		return Code{}, fmt.Errorf("an invite code is a number and %d words, like 42-%s-%s-%s",
			CodeWords, evenWords[0], oddWords[1], evenWords[2])
	}
	n, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil || n == 0 || n > MaxNameplate {
		return Code{}, fmt.Errorf("an invite code starts with a number from 1 to %d, not %q",
			MaxNameplate, fields[0])
	}
	c := Code{Nameplate: uint16(n)}
	for i, w := range fields[1:] {
		b, ok := wordIndex(i, w)
		if !ok {
			return Code{}, unknownWord(i, w)
		}
		c.Words[i] = b
	}
	return c, nil
}

func (Code) mode() mode          { return modeCode }
func (c Code) nameplate() uint16 { return c.Nameplate }
func (c Code) password() []byte {
	b := []byte("code\x00")
	b = binary.BigEndian.AppendUint16(b, c.Nameplate)
	return append(b, c.Words[:]...)
}

// Fingerprint names a joining device in four words of the PGP word list, for
// a person to compare between its screen and the inviting admin's. The device
// that runs the invite runs the session too, and could put a device of its
// own in the guest's place, or the guest's identity with keys of its own; the
// words cover the identity and every key, so either shows as other words.
//
// Four words are 32 bits, enough only if nobody can search them, and the
// device in the middle carries both the admin's salt and the guest's nonce.
// So each is fixed before the other is known: the guest commits to its nonce
// in the join request, before the admin draws the salt, and reveals it only
// once it holds the salt. A device in the middle has to fix its own request's
// nonce before it sees the admin's salt, and hand the guest a salt before it
// sees the guest's nonce: one try at 32 bits on either screen, not a search.
func Fingerprint(salt Salt, nonce Nonce, id types.Identity, keys types.NodeKeys) string {
	h := sha256.New()
	h.Write([]byte("juist device words v2\x00"))
	h.Write(salt[:])
	h.Write(nonce[:])
	h.Write(id[:])
	h.Write(keys.WireGuard[:])
	h.Write(keys.X25519[:])
	h.Write(keys.MLKEM[:])
	sum := h.Sum(nil)
	words := make([]string, 4)
	for i := range words {
		words[i] = wordAt(i, sum[i])
	}
	return strings.Join(words, "-")
}

// WordsAt lists, in order, the words a code may hold at position i of its
// three, counted from 0 after the nameplate.
func WordsAt(i int) []string {
	if i%2 == 0 {
		return slices.Clone(evenWords[:])
	}
	return slices.Clone(oddWords[:])
}

// wordAt alternates the two lists, so a swapped pair reads as a wrong word
// instead of a wrong code.
func wordAt(i int, b byte) string {
	if i%2 == 0 {
		return evenWords[b]
	}
	return oddWords[b]
}

var wordIndexes = func() [2]map[string]byte {
	var m [2]map[string]byte
	for j, list := range [2]*[256]string{&evenWords, &oddWords} {
		m[j] = make(map[string]byte, len(list))
		for i, w := range list {
			m[j][w] = byte(i)
		}
	}
	return m
}()

func wordIndex(i int, w string) (byte, bool) {
	b, ok := wordIndexes[i%2][w]
	return b, ok
}

func unknownWord(i int, w string) error {
	if _, other := wordIndexes[(i+1)%2][w]; other {
		return fmt.Errorf("%q is in the wrong place in the code; check the order of the words", w)
	}
	return fmt.Errorf("%q is not a word invite codes use; check the spelling", w)
}

// LinkPrefix starts every invite link.
const LinkPrefix = "juist:"

// Limits on a link.
const (
	linkSecretLen = 16

	// MaxLinkAddrs bounds how many host addresses a link carries,
	// MaxLinkRelays how many relays by address, and MaxLinkNamed how many by
	// name.
	MaxLinkAddrs  = 8
	MaxLinkRelays = 4
	MaxLinkNamed  = 4

	// relayPrefix marks a relay's address among a link's addresses.
	relayPrefix = "r="
)

// A Link is an invite in the form one copies and pastes: a full-entropy
// secret, and the addresses the inviting host listens on, so a guest can
// reach it from any network that can route to one of them.
type Link struct {
	secret [linkSecretLen]byte
	Addrs  []netip.AddrPort

	// Admin, where set, is the admin key the guest requires the admission to
	// be signed by ([Admission]), and AdminSigning its signing key's
	// fingerprint; the inviting device never touches either.
	Admin        *types.Identity
	AdminSigning *[fingerprintLen]byte

	// Relays are member relays the inviting host waits at for a guest that
	// cannot reach it directly ([Link.ForwardID]). A relay passes bytes and
	// learns nothing that would let it answer in the host's place. Named are
	// relays by their public names, on 443.
	Relays []netip.AddrPort
	Named  []string
}

// WithRelays returns the link naming relays the host waits at, by address
// and by name.
func (l Link) WithRelays(relays []netip.AddrPort, named []string) Link {
	l.Addrs = slices.Clone(l.Addrs)
	l.Relays = slices.Clone(relays[:min(len(relays), MaxLinkRelays)])
	l.Named = slices.Clone(named[:min(len(named), MaxLinkNamed)])
	return l
}

// ForwardID names the invite at a relay: what the host registers there and
// the guest asks for. It is derived from the secret one way, so the relay,
// which sees it, learns nothing it could use against the handshake.
func (l Link) ForwardID() [16]byte {
	k, err := hkdf.Key(sha256.New, l.secret[:], nil, "juist invite forward v1", 16)
	if err != nil {
		panic(err) // a 16-byte SHA-256 HKDF output cannot fail
	}
	return [16]byte(k)
}

// WithAdmin returns the link naming admin, with its signing key, as the one
// who admits.
func (l Link) WithAdmin(admin types.Identity, signing *types.SigningKey) Link {
	l.Addrs = slices.Clone(l.Addrs)
	l.Relays = slices.Clone(l.Relays)
	l.Named = slices.Clone(l.Named)
	fp := SigningFingerprint(signing)
	l.Admin, l.AdminSigning = &admin, &fp
	return l
}

const fingerprintLen = 16

// SigningFingerprint names a signing key in a link: long enough that no
// other key is found to match it, short enough to copy.
func SigningFingerprint(k *types.SigningKey) [fingerprintLen]byte {
	sum := sha256.Sum256(append([]byte("juist link signing key v1\x00"), k[:]...))
	return [fingerprintLen]byte(sum[:fingerprintLen])
}

// NewLink draws a link secret for a host at addrs.
func NewLink(addrs []netip.AddrPort) (Link, error) {
	if len(addrs) > MaxLinkAddrs {
		addrs = addrs[:MaxLinkAddrs]
	}
	l := Link{Addrs: append([]netip.AddrPort(nil), addrs...)}
	if _, err := rand.Read(l.secret[:]); err != nil {
		return Link{}, fmt.Errorf("enroll: drawing an invite secret: %w", err)
	}
	return l, nil
}

var linkEncoding = base64.RawURLEncoding

func (l Link) String() string {
	addrs := make([]string, 0, len(l.Addrs)+len(l.Relays))
	for _, a := range l.Addrs {
		addrs = append(addrs, a.String())
	}
	for _, r := range l.Relays {
		addrs = append(addrs, relayPrefix+r.String())
	}
	for _, n := range l.Named {
		addrs = append(addrs, relayPrefix+n)
	}
	secret := linkEncoding.EncodeToString(l.secret[:])
	if l.Admin != nil && l.AdminSigning != nil {
		secret += "." + linkEncoding.EncodeToString(l.Admin[:]) + "." + linkEncoding.EncodeToString(l.AdminSigning[:])
	}
	return LinkPrefix + secret + "@" + strings.Join(addrs, ",")
}

// IsLink reports whether s is meant as a link rather than a typed code.
func IsLink(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), LinkPrefix) }

// ParseLink reads an invite link.
func ParseLink(s string) (Link, error) {
	s = strings.TrimSpace(s)
	body, ok := strings.CutPrefix(s, LinkPrefix)
	if !ok {
		return Link{}, fmt.Errorf("an invite link starts with %q", LinkPrefix)
	}
	secretText, addrText, ok := strings.Cut(body, "@")
	if !ok || addrText == "" {
		return Link{}, errors.New("the invite link names no address to reach the inviting device at; " +
			"it may have been cut off when it was copied")
	}
	secretText, adminText, hasAdmin := strings.Cut(secretText, ".")
	adminText, fpText, hasFingerprint := strings.Cut(adminText, ".")
	secret, err := linkEncoding.DecodeString(secretText)
	if err != nil || len(secret) != linkSecretLen {
		return Link{}, errors.New("the invite link is damaged; copy it again")
	}
	var l Link
	copy(l.secret[:], secret)
	if hasAdmin {
		raw, err := linkEncoding.DecodeString(adminText)
		var admin types.Identity
		if err != nil || len(raw) != len(admin) {
			return Link{}, errors.New("the invite link is damaged; copy it again")
		}
		copy(admin[:], raw)
		if err := admin.Validate(); err != nil {
			return Link{}, errors.New("the invite link is damaged; copy it again")
		}
		if !hasFingerprint {
			return Link{}, errors.New("the invite link is from an older juist; ask for a new one")
		}
		fp, err := linkEncoding.DecodeString(fpText)
		if err != nil || len(fp) != fingerprintLen {
			return Link{}, errors.New("the invite link is damaged; copy it again")
		}
		l.Admin, l.AdminSigning = &admin, (*[fingerprintLen]byte)(fp)
	}
	for part := range strings.SplitSeq(addrText, ",") {
		text, isRelay := strings.CutPrefix(part, relayPrefix)
		if isRelay && types.ValidateHostName(text) == nil {
			if slices.Contains(l.Named, text) {
				continue
			}
			if len(l.Named) == MaxLinkNamed {
				return Link{}, fmt.Errorf("the invite link names more than %d relays by name", MaxLinkNamed)
			}
			l.Named = append(l.Named, text)
			continue
		}
		a, err := netip.ParseAddrPort(text)
		if err != nil || a.Port() == 0 || !a.Addr().IsValid() || a.Addr().Zone() != "" ||
			a.Addr().IsUnspecified() || a.Addr().IsMulticast() {
			return Link{}, fmt.Errorf("the invite link names %q, which is not an address and port", part)
		}
		list, limit := &l.Addrs, MaxLinkAddrs
		if isRelay {
			list, limit = &l.Relays, MaxLinkRelays
		}
		if slices.Contains(*list, a) {
			continue
		}
		if len(*list) == limit {
			return Link{}, fmt.Errorf("the invite link names more than %d addresses", limit)
		}
		*list = append(*list, a)
	}
	return l, nil
}

// RendezvousKeys derives what the two sides of a link need to meet through the
// DHT when the link's addresses do not reach: where each publishes, and the key
// that seals what they publish. Only a holder of the link can compute them,
// and none of them is the password.
func (l Link) RendezvousKeys() (host, guest, seal [32]byte) {
	derive := func(label string) (out [32]byte) {
		k, err := hkdf.Key(sha256.New, l.secret[:], nil, "juist invite rendezvous v1 "+label, 32)
		if err != nil {
			panic(err) // a 32-byte SHA-256 HKDF output cannot fail
		}
		copy(out[:], k)
		return out
	}
	return derive("host"), derive("guest"), derive("seal")
}

func (Link) mode() mode         { return modeLink }
func (Link) nameplate() uint16  { return 0 }
func (l Link) password() []byte { return append([]byte("link\x00"), l.secret[:]...) }
