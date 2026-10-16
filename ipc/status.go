package ipc

import (
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/nning/juist/internal/rendezvous"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

// Status is what the daemon reports about itself, over IPC and to tests. Times
// are Unix seconds: canonical CBOR admits one spelling per value, and
// time.Time carries a monotonic reading and a location.
//
// The embedded parts travel flattened, as if their fields were Status's own.
type Status struct {
	// Self is this node's identity, and Addrs its overlay addresses.
	Self  types.Identity `cbor:"1,keyasint"`
	Addrs []netip.Prefix `cbor:"2,keyasint,omitempty"`

	// Network is the genesis hash.
	Network types.Hash `cbor:"3,keyasint"`

	Derived
	Tunnels

	// SyncInTunnel says log sync runs through the tunnel alone.
	SyncInTunnel bool `cbor:"47,keyasint,omitempty"`

	// Waiting is how many copies of changes waiting for votes the daemon
	// holds, which [CmdWaiting] hands over.
	Waiting int `cbor:"62,keyasint,omitempty"`

	// Rendezvous names the public services invites may meet through when
	// neither device can reach the other; nil when the daemon is told to
	// use none (--no-dht or --no-stun).
	Rendezvous *rendezvous.Helpers `cbor:"34,keyasint,omitempty"`

	// InNetwork is set once this device holds a network's log; NotMember
	// then says whether the log still lists it. Joining is set while an
	// invite is being redeemed.
	InNetwork bool `cbor:"29,keyasint,omitempty"`

	// StartError is why the mesh could not start over a log that lists this
	// device; the daemon keeps retrying.
	StartError string `cbor:"33,keyasint,omitempty"`
	Joining    bool   `cbor:"32,keyasint,omitempty"`

	// CanOperate says whether the caller may do more than ask for status, and
	// Operator names the local user appointed to, if any.
	CanOperate bool   `cbor:"30,keyasint,omitempty"`
	Operator   string `cbor:"31,keyasint,omitempty"`

	// EpochError is set when this node could not open its wrap of the
	// current group secret, which costs it discovery and gossip but not the
	// data plane.
	EpochError string `cbor:"11,keyasint,omitempty"`

	// SchemaAlarm is set when a quorum has moved the network to a record
	// schema this build does not implement. The state below the upgrade is
	// still held and still acted on — see [log.SchemaTooNewError] — but
	// nothing after it will apply until the binary is newer.
	SchemaAlarm string `cbor:"20,keyasint,omitempty"`

	// ListenPort is the data plane's UDP port and GossipPort the sync
	// layer's TCP port.
	ListenPort uint16 `cbor:"13,keyasint,omitempty"`
	GossipPort uint16 `cbor:"14,keyasint,omitempty"`

	// Instance is this daemon's number among the juist instances on the
	// host, 0 for the default. HostConflict is set while a lower instance
	// holds what this network claims: the mesh runs without IPv4 then, or,
	// where it is this very network, does not start; see [HostConflict].
	Instance     int           `cbor:"58,keyasint,omitempty"`
	HostConflict *HostConflict `cbor:"59,keyasint,omitempty"`

	// Device is the TUN device, empty for none.
	Device string `cbor:"60,keyasint,omitempty"`

	// V4Claims is the IPv4 the network claims on a host: its prefix and the
	// ranges it is moving away from, or where it has no prefix of its own,
	// its members' addresses. The host's other instances yield to it, and a
	// network founded here keeps out of it. A reader who may not operate the
	// device sees members' addresses only as the /22s they are in.
	V4Claims []netip.Prefix `cbor:"61,keyasint,omitempty"`
}

// A HostConflict is another juist instance on this host holding an address
// this device's network claims, or this very network. A host routes an
// address into one tunnel only — the lower instance's — so the higher of the
// two runs without IPv4 until one of the networks renumbers, and does not
// start at all where both are in one network.
type HostConflict struct {
	// Instance is the other instance's number and Device its TUN device.
	Instance int    `cbor:"1,keyasint"`
	Device   string `cbor:"2,keyasint,omitempty"`

	// SameNetwork says the other instance is in this network too.
	SameNetwork bool `cbor:"3,keyasint,omitempty"`

	// Held is the other's address or route, and Claim what of this network's
	// it falls in: its prefix, or one member's address.
	Held  netip.Prefix `cbor:"4,keyasint"`
	Claim netip.Prefix `cbor:"5,keyasint"`

	// Unanswered says the other holds a network but did not answer when this
	// instance started, as while both start at once: IPv4 waits for it.
	Unanswered bool `cbor:"6,keyasint,omitempty"`
}

// Derived is the part of a [Status] a reconcile derives from the log. The
// daemon replaces it whole, so no field outlives the state it came from.
type Derived struct {
	// NetworkName is the network's human-readable name.
	NetworkName string `cbor:"4,keyasint,omitempty"`

	// Head and Epoch are where this node's chain is: the same beacon it
	// puts on every gossip frame.
	Head  types.Hash `cbor:"5,keyasint"`
	Epoch uint64     `cbor:"6,keyasint"`

	// Schema is the network's record schema.
	Schema types.SchemaVersion `cbor:"70,keyasint,omitempty"`

	// Members is how many the log carries, Peers how many are installed in the
	// data plane, Unreachable how many have no announcement yet, and Expired
	// how many are past their expiry and treated as former members.
	Members     int `cbor:"7,keyasint"`
	Peers       int `cbor:"8,keyasint"`
	Unreachable int `cbor:"9,keyasint"`
	Expired     int `cbor:"15,keyasint,omitempty"`

	// Silent names the members counted in Unreachable, by their names in
	// the log, so a person is told which devices are not heard from, not
	// only how many. Status is anyone's to read, and the log is not.
	Silent []string `cbor:"37,keyasint,omitempty"`

	// Unrevoked names the revocations that lost fork choice to a concurrent
	// change and are not in effect until reissued, as "remove-node of phone".
	Unrevoked []string `cbor:"38,keyasint,omitempty"`

	// Lost names the other changes that lost fork choice and can be started
	// again, as "the admission of phone".
	Lost []string `cbor:"48,keyasint,omitempty"`

	// Devices are the members as the log lists them, for a caller who may
	// read the status but not the log.
	Devices []Device `cbor:"45,keyasint,omitempty"`

	// Refused is set when a member's log refused this device a catch-up and
	// no member it tried has answered since: most likely it was removed.
	Refused bool `cbor:"52,keyasint,omitempty"`

	// Overtaken is set when peers have long answered this device only from a
	// checkpoint past all its log holds: it is invited again.
	Overtaken bool `cbor:"80,keyasint,omitempty"`

	// Unmoved names the other members not yet seen holding the newest
	// renumbering, while an old address is still recorded.
	Unmoved []string `cbor:"49,keyasint,omitempty"`

	// Exit is what this device does with exit nodes.
	Exit *Exit `cbor:"63,keyasint,omitempty"`

	// Subnets is what this device makes of subnet routes; nil where the
	// network grants none and this device neither routes nor refuses them.
	Subnets *Subnets `cbor:"64,keyasint,omitempty"`

	// Names is how the host resolves the network's names; nil where it is
	// not meant to, as on a device that is no member.
	Names *Names `cbor:"65,keyasint,omitempty"`

	// Publish is what this device makes of the names published on it; nil
	// where none is and its operator did not agree to serve them.
	Publish *Publish `cbor:"66,keyasint,omitempty"`

	// Ingress is this device's serving as an ingress; nil where it is none.
	Ingress *Ingress `cbor:"67,keyasint,omitempty"`

	// Shares are what this device publishes under its own name, in the
	// order they started. Key 68 held a single share: an older CLI fails on
	// anything else there.
	Shares []Share `cbor:"73,keyasint,omitempty"`

	// Terminator is what this device's terminator last said; nil where it
	// never asked.
	Terminator *Terminator `cbor:"69,keyasint,omitempty"`

	// SelfName is this node's member name.
	SelfName string `cbor:"24,keyasint,omitempty"`

	// LeaseSigners is how many members the log makes admin devices,
	// counting expired ones, which may not vouch but still keep freshness
	// enforced: with none, it is not. FreshSince is when the lease that
	// completed the vouching threshold was issued and FreshUntil when it
	// stops counting, both Unix seconds. Stale is set once it has:
	// the node then keeps tunnels only to admin devices, which is how it
	// catches up without trusting a view that may be missing a removal.
	LeaseSigners int   `cbor:"25,keyasint,omitempty"`
	FreshSince   int64 `cbor:"26,keyasint,omitempty"`
	FreshUntil   int64 `cbor:"27,keyasint,omitempty"`

	// Vouchers is how many admin devices must vouch for this node's view,
	// and Vouching how many do with a lease that still counts.
	Vouchers int  `cbor:"35,keyasint,omitempty"`
	Vouching int  `cbor:"36,keyasint,omitempty"`
	Stale    bool `cbor:"28,keyasint,omitempty"`

	// Relays is how many member-run relays this node has installed,
	// RelayCapable how many members the log grants the role, and Relaying
	// reports whether this device is serving one itself. The three differ:
	// a grant with no announcement behind it is a relay nobody can reach.
	Relays       int  `cbor:"21,keyasint,omitempty"`
	Relaying     bool `cbor:"22,keyasint,omitempty"`
	RelayCapable int  `cbor:"23,keyasint,omitempty"`

	// Conflicted is how many members were denied a peer entry for announcing a
	// NAT-traversal key another member or this device already uses. Dropping
	// only those keeps one announcement from costing everyone their data plane.
	Conflicted int `cbor:"18,keyasint,omitempty"`

	// NoKey names the peers whose handshakes mix in a preshared key
	// nobody holds, as behind by more epochs than this device keeps.
	NoKey []string `cbor:"78,keyasint,omitempty"`

	// Alarm is the fork alarm's text while one is raised, and empty
	// otherwise. While it is set the data plane holds no peers at all.
	Alarm string `cbor:"10,keyasint,omitempty"`

	// Disabled names the record that ended the network with a break-glass
	// secret. The data plane then holds no peers, for good.
	Disabled string `cbor:"71,keyasint,omitempty"`

	// HTTPS is this device's use of 443/tcp; nil where none.
	HTTPS *HTTPS `cbor:"72,keyasint,omitempty"`

	// NotMember is set when this device is no longer in the member set. The
	// daemon has torn its own data plane down.
	NotMember bool `cbor:"16,keyasint,omitempty"`

	// StaleKeys is set when the log names different keys for this device than
	// the daemon was started with: a rotation was applied while it ran, and
	// tunnels and the group secret fail until it restarts over the new keys.
	StaleKeys bool `cbor:"17,keyasint,omitempty"`

	// DataPlaneError is set when the peer set was derived but the data plane
	// refused it: the host may be routed for an older peer set than the log
	// names. The daemon retries on every reconcile.
	DataPlaneError string `cbor:"19,keyasint,omitempty"`

	// LastReconcile is when the peer set was last derived, in Unix seconds.
	LastReconcile int64 `cbor:"12,keyasint,omitempty"`
}

// Tunnels is the part of a [Status] the background tunnel check writes,
// replaced whole by each check and cleared when the data plane comes down.
type Tunnels struct {
	// TunnelsLive is how many installed peers' WireGuard tunnels are live,
	// and TunnelsDown names the others, as the last background check found;
	// TunnelsChecked is set once one has run.
	TunnelsChecked bool     `cbor:"39,keyasint,omitempty"`
	TunnelsLive    int      `cbor:"40,keyasint,omitempty"`
	TunnelsDown    []string `cbor:"41,keyasint,omitempty"`

	// Reach is that check per installed peer, ReachChecked when it ran, in
	// Unix seconds, and HomeRelay the member whose relay the data plane
	// keeps its home connection to.
	Reach        []PeerReach `cbor:"42,keyasint,omitempty"`
	ReachChecked int64       `cbor:"43,keyasint,omitempty"`
	HomeRelay    string      `cbor:"44,keyasint,omitempty"`

	// Seeking names the members counted in TunnelsDown that may have
	// restarted or moved, whose newest announcement is being looked for.
	Seeking []string `cbor:"50,keyasint,omitempty"`

	// Absent names those counted in TunnelsDown whose lookup found no newer
	// announcement: most likely offline.
	Absent []string `cbor:"51,keyasint,omitempty"`

	// SyncFailing names the members whose tunnel is live but whose last log
	// sync connected to none of their addresses; SyncNewer those whose
	// frames this build cannot read, as they run a newer one; SyncBroken
	// those whose sync failed otherwise.
	SyncFailing []string `cbor:"46,keyasint,omitempty"`
	SyncNewer   []string `cbor:"75,keyasint,omitempty"`
	SyncBroken  []string `cbor:"76,keyasint,omitempty"`

	// Outdated names the members whose tunnel is live, whose log sync
	// works, and who still announce no epoch after minutes: they run an
	// older build, which gets none of the user's traffic. It names too those
	// without a tunnel that run and announce no epoch, or an older schema
	// than the network's: their build knows no member that joined since.
	Outdated []string `cbor:"77,keyasint,omitempty"`

	// OlderBuild names the members whose tunnel is live and whose log sync
	// works, and who still announce an older schema than the network's after
	// minutes: they run an older build, which applies no change past its
	// schema.
	OlderBuild []string `cbor:"79,keyasint,omitempty"`

	// Firewalled names the TUN device when a running firewalld lets log sync
	// in on it neither by its zone accepting everything nor by the port.
	// FirewallUnsure says the zone is not trusted, and its ports were not
	// told.
	Firewalled     string `cbor:"53,keyasint,omitempty"`
	FirewallUnsure bool   `cbor:"54,keyasint,omitempty"`

	// RelayedFor is how many members this device's relay was found to
	// serve: connected to it, or announcing it as their home. RelayUnreached
	// says it has served none for minutes while a live peer is homed at no
	// member relay: RelayPort, TCP and UDP, is likely closed to the outside.
	RelayedFor     int    `cbor:"55,keyasint,omitempty"`
	RelayUnreached bool   `cbor:"56,keyasint,omitempty"`
	RelayPort      uint16 `cbor:"57,keyasint,omitempty"`
}

// Blocked names the members in TunnelsDown that run a build that could have a
// tunnel: neither offline nor outdated, so the way to them is to blame.
func (t *Tunnels) Blocked() []string {
	return slices.DeleteFunc(slices.Clone(t.TunnelsDown), func(n string) bool {
		return slices.Contains(t.Seeking, n) || slices.Contains(t.Absent, n) || slices.Contains(t.Outdated, n)
	})
}

// Behind names the members in NoKey that are neither offline, read from an
// announcement they may since have outgrown, nor outdated.
func (s *Status) Behind() []string {
	return slices.DeleteFunc(slices.Clone(s.NoKey), func(n string) bool {
		return slices.Contains(s.Seeking, n) || slices.Contains(s.Absent, n) || slices.Contains(s.Outdated, n)
	})
}

// FreshnessEnding returns how long a fresh node stays fresh, where the lease
// completing its threshold is past half its life: vouchers renew hourly, so
// that happens only where too few of them have run for a day.
func (s *Status) FreshnessEnding(now int64) (time.Duration, bool) {
	if s.Stale || s.LeaseSigners == 0 || s.FreshUntil <= s.FreshSince {
		return 0, false
	}
	left := s.FreshUntil - now
	if left <= 0 || 2*left >= s.FreshUntil-s.FreshSince {
		return 0, false
	}
	return time.Duration(left) * time.Second, true
}

// VouchAgain says what keeps a node fresh whose freshness is ending.
func (s *Status) VouchAgain() string {
	if s.Vouchers <= 1 {
		return "a voucher vouches again"
	}
	return strconv.Itoa(s.Vouchers) + " vouchers vouch again"
}

// ForReader is the status as a caller who may not operate sees it. It is an
// allow-list: a field not copied here reaches operators only.
func (s *Status) ForReader() Status {
	return Status{
		Self: s.Self, Addrs: s.Addrs, Network: s.Network,
		Derived: Derived{
			NetworkName: s.NetworkName, Head: s.Head, Epoch: s.Epoch, Schema: s.Schema,
			Members: s.Members, Peers: s.Peers, Unreachable: s.Unreachable, Expired: s.Expired,
			Silent: s.Silent, Unrevoked: s.Unrevoked, Lost: s.Lost, Refused: s.Refused, Overtaken: s.Overtaken, SelfName: s.SelfName,
			LeaseSigners: s.LeaseSigners, FreshSince: s.FreshSince, FreshUntil: s.FreshUntil,
			Vouchers: s.Vouchers, Vouching: s.Vouching, Stale: s.Stale,
			Relays: s.Relays, Relaying: s.Relaying, RelayCapable: s.RelayCapable, Conflicted: s.Conflicted, NoKey: s.NoKey,
			Alarm: s.Alarm, Disabled: s.Disabled, NotMember: s.NotMember, StaleKeys: s.StaleKeys, Exit: s.Exit.forReader(),
			Subnets: s.Subnets.forReader(), Names: s.Names.forReader(), HTTPS: s.HTTPS.forReader(),
			DataPlaneError: s.DataPlaneError, LastReconcile: s.LastReconcile,
		},
		Tunnels: Tunnels{
			TunnelsChecked: s.TunnelsChecked, TunnelsLive: s.TunnelsLive, TunnelsDown: s.TunnelsDown,
			Reach: s.Reach, ReachChecked: s.ReachChecked, HomeRelay: s.HomeRelay,
			Seeking: s.Seeking, Absent: s.Absent, SyncFailing: s.SyncFailing, SyncNewer: s.SyncNewer,
			SyncBroken: s.SyncBroken, Outdated: s.Outdated, OlderBuild: s.OlderBuild, Firewalled: s.Firewalled,
			FirewallUnsure: s.FirewallUnsure, RelayedFor: s.RelayedFor, RelayUnreached: s.RelayUnreached,
			RelayPort: s.RelayPort,
		},
		SyncInTunnel: s.SyncInTunnel, Rendezvous: s.Rendezvous,
		InNetwork: s.InNetwork, StartError: s.StartError, Joining: s.Joining,
		CanOperate: s.CanOperate, Operator: s.Operator,
		EpochError: s.EpochError, SchemaAlarm: s.SchemaAlarm,
		ListenPort: s.ListenPort, GossipPort: s.GossipPort,
		Instance: s.Instance, HostConflict: s.HostConflict, Device: s.Device, V4Claims: coarseClaims(s.V4Claims),
	}
}

// coarseClaims is claims with each single address widened to the /22 it is
// in: enough to draw a prefix clear of them, and no member list.
func coarseClaims(claims []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, c := range claims {
		if c.IsSingleIP() && c.Addr().Is4() {
			c = netip.PrefixFrom(c.Addr(), 22).Masked()
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// A PeerReach is what the last check found for one installed peer.
type PeerReach struct {
	Identity types.Identity `cbor:"1,keyasint"`
	Live     bool           `cbor:"2,keyasint,omitempty"`

	// Direct says a live tunnel runs over a UDP path rather than a relay.
	// Which path is not said: status is anyone's to read, and a peer's
	// public address is nothing a local user sees otherwise.
	Direct bool `cbor:"3,keyasint,omitempty"`

	// Seeking says a tunnel that is down may be so because the peer
	// restarted or moved, and its new announcement is being looked for;
	// Absent that the lookup found none newer, so it is likely offline.
	Seeking bool `cbor:"4,keyasint,omitempty"`
	Absent  bool `cbor:"5,keyasint,omitempty"`

	// Since is when a tunnel down was first found so, and Heard when the
	// peer last signed its announcement, as its clock has it; Unix seconds.
	Since int64 `cbor:"6,keyasint,omitempty"`
	Heard int64 `cbor:"7,keyasint,omitempty"`

	// Outdated says the peer is one of [Tunnels.Outdated], OlderBuild one
	// of [Tunnels.OlderBuild].
	Outdated   bool `cbor:"9,keyasint,omitempty"`
	OlderBuild bool `cbor:"10,keyasint,omitempty"`
}

// A Device is a member as the log lists it.
type Device struct {
	Identity types.Identity `cbor:"1,keyasint"`
	Name     string         `cbor:"2,keyasint,omitempty"`
	V4       string         `cbor:"3,keyasint,omitempty"`
	V6       string         `cbor:"4,keyasint,omitempty"`
	Roles    []types.Role   `cbor:"5,keyasint,omitempty"`

	// Retiring is the IPv4 address a renumbering moved the member from, and
	// RetiringUntil when it stops working, in Unix seconds.
	Retiring      string `cbor:"6,keyasint,omitempty"`
	RetiringUntil int64  `cbor:"7,keyasint,omitempty"`

	// Subnets are the prefixes the member is granted to route, and Names
	// the public names pointed at it.
	Subnets []netip.Prefix `cbor:"8,keyasint,omitempty"`
	Names   []string       `cbor:"9,keyasint,omitempty"`

	// Published are the names the member publishes, under the domain, one
	// published by TCP as NAME:PORT with its public port, and Serving says
	// it serves them, as its announcement says; [DevicesOf] leaves Serving
	// unset.
	Published []string `cbor:"10,keyasint,omitempty"`
	Serving   bool     `cbor:"11,keyasint,omitempty"`

	// Members are those of Published that are for members alone.
	Members []string `cbor:"12,keyasint,omitempty"`

	// Build is the newest schema the member's juist implements, as its
	// announcement says; zero where none says. [DevicesOf] leaves it unset.
	Build types.SchemaVersion `cbor:"13,keyasint,omitempty"`
}

// Exit is a device's use of exit nodes, and its serving as one.
type Exit struct {
	// Node is the exit node chosen, Name its member name; Off is a choice of
	// none. Refused says why the traffic it would carry is refused rather
	// than carried; empty, it is carried.
	Node    types.Identity `cbor:"1,keyasint,omitempty"`
	Name    string         `cbor:"2,keyasint,omitempty"`
	Off     bool           `cbor:"3,keyasint,omitempty"`
	Refused string         `cbor:"4,keyasint,omitempty"`

	// Consent says this device's operator agreed to serve as one, Serving
	// that it does, and NotServing why not, where it agreed.
	Consent    bool   `cbor:"5,keyasint,omitempty"`
	Serving    bool   `cbor:"6,keyasint,omitempty"`
	NotServing string `cbor:"7,keyasint,omitempty"`

	// Offering are the other exit nodes whose operators agreed to serve, as
	// their announcements say.
	Offering []types.Identity `cbor:"8,keyasint,omitempty"`

	// Failed says the data plane could not route as chosen, not even
	// refusing, so that internet traffic may leave directly.
	Failed string `cbor:"9,keyasint,omitempty"`

	// DNS says the host's DNS goes to the exit node in use, and DNSNot why
	// not, where it does not.
	DNS    bool   `cbor:"10,keyasint,omitempty"`
	DNSNot string `cbor:"11,keyasint,omitempty"`

	// Partly says which family the exit node in use refuses, and why, where
	// it carries the other alone.
	Partly string `cbor:"12,keyasint,omitempty"`

	// StrictRP6 says the host's strict IPv6 reverse-path filter drops what
	// the exit node in use answers over IPv6.
	StrictRP6 bool `cbor:"13,keyasint,omitempty"`

	// Isolated says answers to connections that came in by another device go
	// through the exit node in use too, as chosen; AnswersThrough why they
	// would though not chosen, "" where they leave the way they came.
	Isolated       bool   `cbor:"14,keyasint,omitempty"`
	AnswersThrough string `cbor:"15,keyasint,omitempty"`
}

// Names is how the host resolves the network's names: under Domain, as
// home.juist, where Resolved, and else Not says why not; Cannot where the
// host or the network's name does not allow it at all. Accepted says the
// owner agreed to the public names the network points at members, which
// Overrides are. Public is the network's public domain, resolved as Domain is.
type Names struct {
	Domain    string         `cbor:"1,keyasint,omitempty"`
	Resolved  bool           `cbor:"2,keyasint,omitempty"`
	Not       string         `cbor:"3,keyasint,omitempty"`
	Cannot    bool           `cbor:"4,keyasint,omitempty"`
	Accepted  bool           `cbor:"5,keyasint,omitempty"`
	Overrides []NameOverride `cbor:"6,keyasint,omitempty"`
	Public    string         `cbor:"7,keyasint,omitempty"`
	// ForMembers are the names for members alone this device may open,
	// which it reaches where Resolved alone.
	ForMembers []string `cbor:"9,keyasint,omitempty"`
}

// A NameOverride is a public name pointed at Device, and Not why this device
// does not resolve it so now, where accepted.
type NameOverride struct {
	Name   string `cbor:"1,keyasint"`
	Device string `cbor:"2,keyasint,omitempty"`
	Not    string `cbor:"3,keyasint,omitempty"`
}

// forReader is n without the devices names point at, which the device list
// is kept from a reader.
func (n *Names) forReader() *Names {
	if n == nil {
		return nil
	}
	c := *n
	c.Overrides = nil
	return &c
}

// Subnets is what a device makes of subnet routes: Off says its owner turned
// them off; Consent that its operator agreed to route its own, Serving those
// it routes, and NotServing why none, where it agreed. Routes are the routes
// the network grants, each as this device takes it.
type Subnets struct {
	Off        bool           `cbor:"1,keyasint,omitempty"`
	Consent    bool           `cbor:"2,keyasint,omitempty"`
	Serving    []netip.Prefix `cbor:"3,keyasint,omitempty"`
	NotServing string         `cbor:"4,keyasint,omitempty"`
	Routes     []SubnetRoute  `cbor:"5,keyasint,omitempty"`
}

// Publish is whether this device's operator agreed to serve the names the
// network publishes on it, which it serves, or why none.
type Publish struct {
	Consent    bool     `cbor:"1,keyasint,omitempty"`
	Serving    []string `cbor:"2,keyasint,omitempty"`
	NotServing string   `cbor:"3,keyasint,omitempty"`

	// Ending are the names served whose TLS juist ends, as "NAME to ADDR".
	Ending []string `cbor:"4,keyasint,omitempty"`

	// CAA are the records that bind those names' certificates to the
	// terminator's account, once it has one, in zone file syntax.
	CAA []string `cbor:"5,keyasint,omitempty"`

	// Ends says the operator named where some name goes, for juist to end
	// its TLS; TerminatorSilent, that the terminator has not asked lately
	// while there is TLS to end.
	Ends             bool `cbor:"6,keyasint,omitempty"`
	TerminatorSilent bool `cbor:"7,keyasint,omitempty"`

	// To is where the operator said each name whose TLS juist ends goes,
	// published here or not, kept while not serving too; sorted by label.
	To []ServeTo `cbor:"8,keyasint,omitempty"`

	// Passing are the names served by TCP whose bytes juist passes on, as
	// "NAME to ADDR".
	Passing []string `cbor:"9,keyasint,omitempty"`

	// Shared are names for members alone not served, as "NAME with OTHER":
	// their service is OTHER's too, a name or this device's share, whose
	// bytes juist passes on as they are, so that a client of OTHER could ask
	// it for NAME by Host.
	Shared []string `cbor:"10,keyasint,omitempty"`
	// Withheld are the names whose service is for members alone, which the
	// log has public, so not served.
	Withheld []string `cbor:"11,keyasint,omitempty"`
}

// A Terminator says whether this device's terminator asked lately, where it
// listens and where another program holds the port, as ADDR:PORT, and the
// names it has no certificate for.
type Terminator struct {
	Running   bool     `cbor:"1,keyasint,omitempty"`
	Listening []string `cbor:"2,keyasint,omitempty"`
	Unbound   []string `cbor:"3,keyasint,omitempty"`
	NoCert    []NoCert `cbor:"4,keyasint,omitempty"`
}

// HTTPHeldOn are the addresses where another program holds port 80, from
// which the terminator would redirect to https.
func (t *Terminator) HTTPHeldOn() []string {
	var on []string
	for _, u := range t.Unbound {
		if ap, err := netip.ParseAddrPort(u); err == nil && ap.Port() == 80 {
			on = append(on, ap.Addr().String())
		}
	}
	return on
}

// A Share is this device's own name, or a path under it, published while a
// call holds it open: where it goes, its end in Unix seconds, zero for the
// call's, and why it reaches nobody, where it does not.
type Share struct {
	Name      string `cbor:"1,keyasint,omitempty"`
	To        string `cbor:"2,keyasint"`
	Until     int64  `cbor:"3,keyasint,omitempty"`
	NotShared string `cbor:"4,keyasint,omitempty"`

	// CAA binds the name's certificates to the terminator's account.
	CAA []string `cbor:"5,keyasint,omitempty"`

	// What and Path are the shared file or directory and the URL path it is
	// reached under, as [ShareRequest] says. Path is the share's secret.
	What string `cbor:"6,keyasint,omitempty"`
	Path string `cbor:"7,keyasint,omitempty"`
}

// Ingress says whether the ingress on this device asked lately what is
// published, and the names it is told; Ports are the public TCP ports it
// said it listens on, and Unbound those another program holds.
type Ingress struct {
	Running bool     `cbor:"1,keyasint,omitempty"`
	Names   []string `cbor:"2,keyasint,omitempty"`
	Ports   []uint16 `cbor:"3,keyasint,omitempty"`
	Unbound []uint16 `cbor:"4,keyasint,omitempty"`
	NoQUIC  bool     `cbor:"5,keyasint,omitempty"` // 443/udp held by another program
}

// A SubnetRoute is one granted prefix: who routes it, whether this device
// sends it into the tunnel, and why not, or only in part.
type SubnetRoute struct {
	Prefix netip.Prefix   `cbor:"1,keyasint"`
	Router types.Identity `cbor:"2,keyasint,omitempty"`
	Name   string         `cbor:"3,keyasint,omitempty"`
	InUse  bool           `cbor:"4,keyasint,omitempty"`
	Why    string         `cbor:"5,keyasint,omitempty"`
}

// forReader is s without who routes what, which only an operator lists.
func (s *Subnets) forReader() *Subnets {
	if s == nil {
		return nil
	}
	r := *s
	r.Routes = slices.Clone(s.Routes)
	for i := range r.Routes {
		r.Routes[i].Router, r.Routes[i].Name = types.Identity{}, ""
	}
	return &r
}

// forReader is e without the other exit nodes, which only an operator lists.
func (e *Exit) forReader() *Exit {
	if e == nil {
		return nil
	}
	r := *e
	r.Offering = nil
	return &r
}

// DevicesOf lists the members as the log has them at unix time now.
func DevicesOf(state *log.State, now int64) []Device {
	nodes := state.Nodes()
	out := make([]Device, 0, len(nodes))
	for _, n := range nodes {
		dev := Device{Identity: n.Identity, Name: n.Name, V6: state.Addr6(n.Identity).String(),
			Roles: slices.Clone(n.Roles), Subnets: n.SubnetRoutes(), Names: slices.Clone(n.Names)}
		for _, p := range n.Published {
			name := p.Under(state.Domain())
			if p.Public != 0 {
				name = net.JoinHostPort(name, strconv.Itoa(int(p.Public)))
			}
			dev.Published = append(dev.Published, name)
			if p.Members {
				dev.Members = append(dev.Members, name)
			}
		}
		if n.V4 != nil {
			dev.V4 = n.V4.String()
		}
		if n.Retiring.Live(now) {
			dev.Retiring, dev.RetiringUntil = n.Retiring.Addr.String(), int64(n.Retiring.Until)
		}
		out = append(out, dev)
	}
	return out
}

// ErrNotOperator is the text of the refusal a non-operator gets, which the
// CLI recognizes.
const ErrNotOperator = "only this device's operator may do that"

// ErrNothingStaged is the text of [CmdUnstage]'s answer when no rotation
// waits, which the CLI recognizes.
const ErrNothingStaged = "no rotation of this device's keys is waiting"

// ErrStillMember is the text of [CmdReset]'s refusal for a device the log
// still lists, which the CLI recognizes.
const ErrStillMember = "this device is still a member of its network"
