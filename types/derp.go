package types

// PublicDERP names the public DERP servers a network's members meet through
// where no member relay serves a pair: untrusted helpers, as STUN servers
// are, which see WireGuard's ciphertext alone. The zero value names none.
type PublicDERP struct {
	// Tailscale is Tailscale's public regions, as the build embeds them.
	Tailscale bool `cbor:"1,keyasint,omitempty"`
}
