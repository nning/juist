package types

// Domain-separation labels, every one juist hashes, signs, derives or seals
// under, so that no digest, signature or key can be taken for one of another
// kind. A label is never redefined: what changes under it takes a new one.
// Labels are wire format, kept byte for byte as first written.
const (
	// Records, signatures and addresses.
	LabelAUM            = "juist/aum/v1"
	LabelAUMSig         = "juist/aum-sig/v1"
	LabelAddr6          = "juist/addr6/v1"
	LabelULA            = "juist/ula/v1"
	LabelDisablement    = "juist/disablement/v1"
	LabelEpochCommit    = "juist/epoch-commit/v1"
	LabelLease          = "juist/lease/v1"
	LabelSigningSeed    = "juist/mldsa44-seed/v1"
	LabelEndorsement    = "juist/signing-key/v1"
	LabelEndpoint       = "juist/endpoint/v1"
	LabelCatchUpProof   = "juist/catch-up-proof/v1"
	LabelCatchUpGrant   = "juist/catch-up-grant/v1"
	LabelCatchUpRefusal = "juist/catch-up-refusal/v1"
	LabelPairMsg        = "juist/pair-msg/v1"
	LabelWaitingChange  = "juist/waiting-change/v1"
	LabelRotationProof  = "juist rotation proof v1"

	// The epoch secret's derivations.
	LabelEpochSeal    = "juist/epoch-seal/v1"
	LabelCatchUp      = "juist/catch-up/v1"
	LabelDHTTopic     = "juist/dht-topic/v1"
	LabelDiscoveryKey = "juist/discovery-aead/v1"
	LabelMDNS         = "juist/mdns-beacon/v1"
	LabelGossipKey    = "juist/gossip-aead/v1"
	LabelAdminX25519  = "juist/admin-recipient-x25519/v1"
	LabelAdminMLKEM   = "juist/admin-recipient-mlkem/v1"
	LabelWaitingKey   = "juist/waiting-key/v1"
	LabelPeerSeal     = "juist/peer-seal/v1"
	LabelPSK          = "juist/wg-psk/v1"

	// Keys between members. LabelAddrKey is an address key record's signature
	// label and its key's derivation alike.
	LabelAddrKey     = "juist/addr-key/v1"
	LabelAddrKeyID   = "juist/addr-key-id/v1"
	LabelAddrNonce   = "juist/addr-nonce/v1"
	LabelAddrWrap    = "juist/addr-wrap/v1"
	LabelPairKey     = "juist/pair-key/v1"
	LabelPairKeyPSK  = "juist/pair-key-psk/v1"
	LabelPSKGroup    = "juist/wg-psk-group/v1"
	LabelPSKPair     = "juist/wg-psk-pair/v1"
	LabelPSKCheck    = "juist/wg-psk-check/v1"
	LabelPadded      = "juist/padded/v1"
	LabelWaitingBody = "juist/waiting-body/v1"

	// Enrollment, invites and relays.
	LabelDeviceWords      = "juist device words v3"
	LabelWordsCommit      = "juist words commit v1"
	LabelLinkSigningKey   = "juist link signing key v1"
	LabelInviteForward    = "juist invite forward v1"
	LabelInviteRendezvous = "juist invite rendezvous v1 "
	LabelEnrollV1         = "juist enroll v1 "
	LabelEnrollV3         = "juist enroll v3 "
	LabelEnrollBinding    = "juist enroll binding v3"
	LabelEnrollSPAKE2W    = "juist enroll spake2 w v1"
	LabelEnrollAdmission  = "juist enroll admission v2"
	LabelEnrollProof      = "juist enroll proof v1"
	LabelRelayForward     = "juist relay forward v1"
	LabelRelayRendezvous  = "juist relay rendezvous v1"
	LabelRelayRegion      = "juist/relay-region/v1"
	LabelPolicyDetached   = "juist/policy-detached/v1"
)
