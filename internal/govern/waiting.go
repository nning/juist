package govern

import (
	"time"

	"github.com/nning/juist/internal/waiting"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/secrets"
	"github.com/nning/juist/types"
)

// AdminRecipient is an admin key's encryption key, which follows from it.
func AdminRecipient(priv types.PrivateIdentity) (types.RecipientKey, error) {
	keys, err := secrets.AdminRecipient(priv.Seed())
	if err != nil {
		return types.RecipientKey{}, err
	}
	return keys.Recipient()
}

// Seal is aum as a change waiting for votes, sealed to every admin of state's
// network that has an encryption key, signed by signer and expiring after
// ttl from now; proposer is who proposed it, zero for signer. held are the
// copies the device holds: one that replaces signer's last copy of aum says
// so by a later time, and is held a second at least.
func Seal(state *log.State, aum *types.AUM, signer types.PrivateIdentity, proposer types.Identity, held [][]byte,
	now time.Time, ttl time.Duration) (*waiting.Change, error) {
	for _, b := range held {
		if c, err := waiting.Decode(b); err == nil && c.ID == aum.SigHash() && c.Signer == signer.Public() &&
			c.Issued >= now.Unix() {
			next := time.Unix(c.Issued+1, 0)
			ttl = max(ttl-next.Sub(now), time.Second)
			now = next
		}
	}
	return waiting.Seal(state.GenesisHash(), aum, state.Admins(), state.SigningKey, signer, proposer, now, ttl)
}
