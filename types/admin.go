package types

import (
	"fmt"
)

// An AdminKey is one member of the admin quorum: a signing key and the vote
// weight its signature carries.
type AdminKey struct {
	Public Identity `cbor:"1,keyasint"`

	// Votes is the weight a signature by Public contributes toward
	// [Snapshot.Quorum], so that long-lived organizational keys can outweigh
	// laptop keys.
	Votes uint32 `cbor:"2,keyasint"`

	// Name is a human label.
	Name string `cbor:"3,keyasint,omitempty"`

	// Holder names the person the key belongs to.
	// The keys of one holder are one voter: they carry the holder's Votes and
	// Needed alike, and the holder's votes count once, when at least Needed
	// of its keys signed. So a person with a key on each of two devices
	// casts one vote with either, and can be made to need both. Without a
	// holder a key is a voter of its own.
	Holder string `cbor:"4,keyasint,omitempty"`

	// Needed is how many of the holder's keys must sign for its votes to
	// count. Zero is one, and one is always written as zero, so that a state
	// has one encoding.
	Needed uint32 `cbor:"5,keyasint,omitempty"`

	// Recipient is the key's encryption key, which only the key itself
	// sets: a genesis naming one is signed by the key, and so is a
	// [KindSetAdminRecipient].
	Recipient *RecipientKey `cbor:"6,keyasint,omitempty"`

	// Signing is the key's ML-DSA key, which every admin key has, and
	// Endorsement the key's Ed25519 endorsement of it, which binds it to
	// Public as the key's holder made them.
	Signing     *SigningKey `cbor:"7,keyasint,omitempty"`
	Endorsement *Sig        `cbor:"8,keyasint,omitempty"`
}

// Clone returns a deep copy of k.
func (k *AdminKey) Clone() *AdminKey {
	out := *k
	if k.Recipient != nil {
		r := *k.Recipient
		out.Recipient = &r
	}
	if k.Signing != nil {
		s := *k.Signing
		out.Signing = &s
	}
	if k.Endorsement != nil {
		e := *k.Endorsement
		out.Endorsement = &e
	}
	return &out
}

// NeededKeys is how many of a key's holder's keys must sign.
func (a *AdminKey) NeededKeys() uint32 { return max(a.Needed, 1) }

// voter names the voter a key belongs to: its holder, or the key itself.
func (a *AdminKey) voter() string {
	if a.Holder != "" {
		return "holder\x00" + a.Holder
	}
	return "key\x00" + string(a.Public[:])
}

// AchievableVotes is the vote weight the admin keys can cast between them:
// every voter's, counted once, except a holder's that has fewer keys than it
// needs, which can cast none.
func AchievableVotes(keys []AdminKey) uint32 {
	return CountVotes(keys, func(Identity) bool { return true })
}

// CountVotes is the vote weight the keys in signed cast: each voter's once,
// if at least as many of its keys signed as it needs.
func CountVotes(keys []AdminKey, signed func(Identity) bool) uint32 {
	type voter struct{ votes, needed, signed uint32 }
	voters := map[string]*voter{}
	for i := range keys {
		v := voters[keys[i].voter()]
		if v == nil {
			v = &voter{votes: keys[i].Votes, needed: keys[i].NeededKeys()}
			voters[keys[i].voter()] = v
		}
		if signed(keys[i].Public) {
			v.signed++
		}
	}
	var total uint32
	for _, v := range voters {
		if v.signed >= v.needed {
			total += v.votes
		}
	}
	return total
}

// ValidateAdmins checks what the keys say about their holders: one holder's
// keys agree on its votes and the keys it needs.
func ValidateAdmins(keys []AdminKey) error {
	type policy struct {
		name          string
		votes, needed uint32
	}
	holders := map[string]policy{}
	for i := range keys {
		k := &keys[i]
		if k.Holder == "" {
			if k.Needed != 0 {
				return fmt.Errorf("admin key %v needs %d keys and belongs to no holder", k.Public.ShortString(), k.Needed)
			}
			continue
		}
		p := policy{k.Holder, k.Votes, k.Needed}
		seen, ok := holders[FoldName(k.Holder)]
		switch {
		case ok && seen.name != k.Holder:
			return fmt.Errorf("the holders %q and %q differ only in case", seen.name, k.Holder)
		case ok && seen != p:
			return fmt.Errorf("the keys of %q disagree on its votes or the keys it needs", k.Holder)
		}
		holders[FoldName(k.Holder)] = p
	}
	return nil
}

// StaticValidate checks an admin key entry.
func (a *AdminKey) StaticValidate() error {
	if err := a.Public.Validate(); err != nil {
		return fmt.Errorf("admin key: %w", err)
	}
	if a.Votes == 0 {
		return fmt.Errorf("admin key %v has zero votes", a.Public.ShortString())
	}
	if a.Votes > MaxVotes {
		return fmt.Errorf("admin key %v has %d votes, over the %d limit",
			a.Public.ShortString(), a.Votes, MaxVotes)
	}
	if a.Needed > MaxAdmins {
		return fmt.Errorf("admin key %v needs %d keys, over the %d-key limit", a.Public.ShortString(), a.Needed, MaxAdmins)
	}
	if a.Needed == 1 {
		return fmt.Errorf("admin key %v needs one key, which is written as zero", a.Public.ShortString())
	}
	if err := ValidateName(a.Holder); err != nil {
		return fmt.Errorf("admin key %v's holder: %w", a.Public.ShortString(), err)
	}
	if a.Recipient != nil {
		if err := a.Recipient.validate(); err != nil {
			return fmt.Errorf("admin key %v: %w", a.Public.ShortString(), err)
		}
	}
	if (a.Signing == nil) != (a.Endorsement == nil) {
		return fmt.Errorf("admin key %v has a signing key without its endorsement, or one without the other",
			a.Public.ShortString())
	}
	if a.Signing != nil {
		if err := a.Signing.Validate(); err != nil {
			return fmt.Errorf("admin key %v: %w", a.Public.ShortString(), err)
		}
		if !a.Public.VerifyEndorsement(a.Signing, *a.Endorsement) {
			return fmt.Errorf("admin key %v did not endorse its signing key", a.Public.ShortString())
		}
	}
	return ValidateName(a.Name)
}

// ValidateSigningKeys checks that no signing key is named by two identities,
// and that an identity both an admin key and a member names one.
func ValidateSigningKeys(admins []AdminKey, nodes []NodeRecord) error {
	by := make(map[SigningKey]Identity, len(admins)+len(nodes))
	named := make(map[Identity]*SigningKey, len(admins)+len(nodes))
	check := func(id Identity, k *SigningKey) error {
		if k == nil {
			return nil
		}
		if other, ok := by[*k]; ok && other != id {
			return fmt.Errorf("%v and %v name one signing key", other.ShortString(), id.ShortString())
		}
		if prev, ok := named[id]; ok && *prev != *k {
			return fmt.Errorf("%v names two signing keys", id.ShortString())
		}
		by[*k], named[id] = id, k
		return nil
	}
	for i := range admins {
		if err := check(admins[i].Public, admins[i].Signing); err != nil {
			return err
		}
	}
	for i := range nodes {
		if err := check(nodes[i].Identity, nodes[i].Signing); err != nil {
			return err
		}
	}
	return nil
}

// ValidateVouchers checks a vouching threshold against the admin devices
// among nodes: more than there are would leave no node ever fresh.
func ValidateVouchers(vouchers uint32, nodes []NodeRecord) error {
	devices := 0
	for i := range nodes {
		if nodes[i].HasRole(RoleAdmin) {
			devices++
		}
	}
	if int(vouchers) > devices {
		return fmt.Errorf("%d admin devices cannot meet a vouching threshold of %d", devices, vouchers)
	}
	return nil
}
