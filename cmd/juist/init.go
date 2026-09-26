package main

import (
	"cmp"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"go4.org/netipx"

	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// numDisablementSecrets is how many break-glass preimages the genesis ceremony
// commits to: enough that losing any one of them does not matter.
const numDisablementSecrets = 10

// drawNetworkName names a network nobody named, as two random words, and
// not as one this keystore has prepared already.
func (a *app) drawNetworkName() (string, error) {
	for {
		name, err := enroll.NetworkName()
		if err != nil {
			return "", err
		}
		if !fileExists(a.home.join(breakGlassFile(name))) && !fileExists(a.home.join(genesisFileFor(name))) {
			return name, nil
		}
	}
}

// An initPlan is what "juist init" was asked for, checked before anything is
// written: the ceremony writes files that cannot simply be written over.
type initPlan struct {
	network, device, adminName string
	noDevice, relay, yes       bool
	adminVotes, quorum         uint
	extraAdmins                stringList
	ipv4                       string
	operator                   optionalString

	// v4 is the parsed --ipv4, and admins every admin key, this keystore's
	// first, whose key the ceremony fills in.
	v4     *netip.Prefix
	admins []types.AdminKey
}

func cmdInit(a *app, args []string) error {
	p, err := a.parseInit(args)
	if err != nil {
		return err
	}
	if err := a.checkInit(&p); err != nil {
		return err
	}
	n, op, err := a.initNode(&p)
	if err != nil {
		return err
	}
	return a.foundNetwork(n, op, &p)
}

func (a *app) parseInit(args []string) (initPlan, error) {
	s := spec{name: "juist init", args: "[NETWORK]", max: 1, about: `
Create a network with this device as its first member and voucher.
NETWORK defaults to two random words.

The admin keys (this keystore's and --admin) and --quorum decide who may
change the network; changing them later takes a quorum as well. Recovery
without the admin keys is not implemented: losing them loses the network.`}
	var p initPlan
	fs := newFlags(s.name)
	fs.StringVar(&p.device, "device", "", "this device's `NAME` (default: the hostname)")
	fs.BoolVar(&p.noDevice, "no-device", false, "do not make this device a member; for a signing-only machine")
	fs.BoolVar(&p.relay, "relay", false, "make this device a relay")
	fs.StringVar(&p.adminName, "admin-name", "", "`NAME` of the admin key created here (default: your user name)")
	fs.Var(&p.extraAdmins, "admin", "another admin, as `NAME=KEY[:VOTES]`; repeatable")
	fs.UintVar(&p.adminVotes, "admin-votes", 1, "votes of the admin key created here")
	fs.UintVar(&p.quorum, "quorum", 1, "votes a change needs")
	fs.StringVar(&p.ipv4, "ipv4", "", "IPv4 `PREFIX`, such as 10.111.0.0/24 (default: "+types.OverlayV4.String()+")")
	fs.BoolVar(&p.yes, "yes", false, "do not ask")
	fs.Var(&p.operator, "operator", "local `USER` who manages this device without sudo")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return p, err
	}
	if len(pos) == 1 {
		p.network = pos[0]
	} else if p.network, err = a.drawNetworkName(); err != nil {
		return p, err
	}
	if p.adminName == "" {
		p.adminName = defaultAdminName()
	}
	return p, nil
}

// checkInit checks everything decidable from the arguments.
func (a *app) checkInit(p *initPlan) error {
	if p.quorum == 0 || p.quorum > types.MaxVotes {
		return fmt.Errorf("--quorum must be between 1 and %d", types.MaxVotes)
	}
	if u := a.sudoUser(); u != "" {
		return fmt.Errorf("run as %s, without sudo: the admin key belongs in your keystore", u)
	}
	if err := checkName("network name", p.network); err != nil {
		return err
	}
	if err := checkName("--admin-name", p.adminName); err != nil {
		return err
	}
	if p.device != "" {
		if err := checkName("--device", p.device); err != nil {
			return err
		}
	}
	if p.ipv4 != "" {
		v4, err := netip.ParsePrefix(p.ipv4)
		if err != nil {
			return fmt.Errorf("--ipv4: bad prefix %q (want e.g. 10.111.0.0/24)", p.ipv4)
		}
		if err := types.ValidateV4Prefix(v4); err != nil {
			return fmt.Errorf("--ipv4: %w", err)
		}
		if used := hostNetsOverlapping(v4); len(used) > 0 {
			a.warn("%v overlaps %s here; traffic to both goes into the network", v4, strings.Join(used, ", "))
			if err := a.proceed(p.yes, "continue?"); err != nil {
				return err
			}
		}
		p.v4 = &v4
	}
	p.admins = []types.AdminKey{{Votes: uint32(p.adminVotes), Name: p.adminName, Holder: p.adminName}}
	for _, spec := range p.extraAdmins {
		key, err := parseAdminSpec(spec)
		if err != nil {
			return err
		}
		// Each key belongs to the person it is named for: two under one name
		// are one admin's, on two devices, and cast one vote.
		key.Holder = key.Name
		p.admins = append(p.admins, key)
	}
	if err := types.ValidateAdmins(p.admins, types.CurrentSchema); err != nil {
		return fmt.Errorf("%w; give one person's keys the same votes", err)
	}
	total := types.AchievableVotes(p.admins)
	if uint32(p.quorum) > total {
		return fmt.Errorf("--quorum %d exceeds the %s the admins cast", p.quorum, count(total, "vote"))
	}
	if uint32(p.quorum) == total && total > 1 {
		a.warn("every change needs every admin; losing one admin's keys locks the network")
	}
	return nil
}

// initNode finds the node the network is founded on, and checks it and the
// keystore can take a new one.
func (a *app) initNode(p *initPlan) (node, operatorChoice, error) {
	n, err := a.openNode()
	if err != nil {
		return nil, operatorChoice{}, err
	}
	if n.status() != nil && p.noDevice {
		return nil, operatorChoice{}, errors.New("--no-device: juistd runs here")
	}
	if err := a.requireOperator(); err != nil {
		return nil, operatorChoice{}, err
	}
	if auth, err := n.log(); err == nil {
		return nil, operatorChoice{}, fmt.Errorf("already in network %q", auth.State().Network())
	} else if !errors.Is(err, errNoNetwork) {
		return nil, operatorChoice{}, err
	}
	op, err := defaultOperator(p.operator, n.status())
	if err != nil {
		return nil, operatorChoice{}, err
	}
	// An admin key already here is used again: one person's key may govern
	// several networks. What belongs to one network alone is named for it.
	for _, name := range []string{breakGlassFile(p.network), genesisFileFor(p.network)} {
		if _, err := os.Stat(a.home.join(name)); err == nil {
			return nil, operatorChoice{}, fmt.Errorf("network %q already prepared here: %s\nhint: pick another "+
				"name, or move the file away if that network never came to be", p.network, a.home.join(name))
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, operatorChoice{}, err
		}
	}
	return n, op, nil
}

// foundNetwork runs the genesis ceremony: it signs the genesis with this
// keystore's admin key and creates the network, or where more admins must
// sign, writes it out for them.
func (a *app) foundNetwork(n node, op operatorChoice, p *initPlan) error {
	localAdmin, reused, err := a.home.adminKey(p.adminName)
	if err != nil {
		return err
	}
	var nodes []types.NodeRecord
	machine := ""
	if !p.noDevice {
		founder, err := founderRecord(n, p)
		if err != nil {
			return err
		}
		nodes, machine = append(nodes, founder), founder.Name
	}
	if reused {
		a.printf("using admin key %q from %s\n", p.adminName, a.home.path)
	} else if localAdmin, err = a.home.createAdminKey(p.adminName); err != nil {
		return err
	}
	p.admins[0].Public = localAdmin.Public()
	p.admins[0].Name = cmp.Or(machine, a.machineName())
	commitments, err := a.writeDisablementSecrets(p.network)
	if err != nil {
		return err
	}
	genesis, err := log.Genesis(p.network, uint32(p.quorum), p.admins, commitments, nodes, sealer())
	if err != nil {
		return err
	}
	genesis.State.V4Prefix = p.v4
	if err := genesis.Sign(localAdmin); err != nil {
		return err
	}
	status, err := log.GenesisStatus(&genesis)
	if err != nil {
		return err
	}
	if !status.Authorized() {
		// The other admins sign it where their keys are; discarding it would
		// strand the keys and secrets already written for it.
		path := a.home.join(genesisFileFor(p.network))
		if err := writeRecordFile(path, &genesis); err != nil {
			return err
		}
		a.printf("prepared %q; needs %s\n", p.network, approvalsNeeded(status, genesis.State.Admins, &genesis))
		a.printf("wrote %s; each admin runs:\n", path)
		a.command("juist approve %s", filepath.Base(path))
		return nil
	}
	if p.noDevice {
		// No device, so no daemon either: the log lives in the keystore.
		st, err := store.Open(a.home.join(logDir))
		if err != nil {
			return err
		}
		if _, err := log.Create(st, genesis); err != nil {
			return err
		}
	} else if err := n.create(genesis, op); err != nil {
		return fmt.Errorf("%w\nhint: if \"juist status\" shows no network, move %s away before retrying",
			err, a.home.join(breakGlassFile(p.network)))
	}
	return a.reportCreated()
}

// founderRecord is this device's record in the genesis: an admin device, at
// the first address of the range.
func founderRecord(n node, p *initPlan) (types.NodeRecord, error) {
	self, err := n.self()
	if err != nil {
		return types.NodeRecord{}, err
	}
	v4, err := firstFreeV4(types.V4Range(types.CurrentSchema, p.v4), nil)
	if err != nil {
		return types.NodeRecord{}, err
	}
	roles := []types.Role{types.RoleAdmin}
	if p.relay {
		roles = append(roles, types.RoleRelayCapable)
	}
	return types.NodeRecord{
		Identity:  self.Identity,
		Name:      cmp.Or(p.device, self.Name),
		WireGuard: self.Keys.WireGuard,
		X25519:    self.Keys.X25519,
		MLKEM:     self.Keys.MLKEM,
		V4:        &v4,
		Roles:     sortRoles(roles),
	}, nil
}

// reportCreated describes a network that has just come into existence.
func (a *app) reportCreated() error {
	a.node = nil
	auth, err := a.networkLog()
	if err != nil {
		return err
	}
	state := auth.State()
	a.ok("created network %q", state.Network())
	id, _, _ := a.selfID()
	if self, member := state.Node(id); member {
		a.field("This device", "%s  %s", displayMember(self), addrList(state, id))
	}
	a.field("IPv4 range", "%v", state.V4Range())
	a.field("Quorum", "%d of %s", state.Quorum(), count(state.TotalVotes(), "vote"))
	if name := a.localAdminName(state); name != "" {
		a.field("Admin", "%s", name)
	}
	// The founder of a ceremony has the file; whoever applied it may not.
	if path := a.home.join(breakGlassFile(state.Network())); fileExists(path) {
		a.field("Break-glass", "%s (keep offline)", path)
	}
	if st := a.node.status(); st != nil && st.Operator != "" {
		a.field("Operator", "%s", st.Operator)
	}
	a.startWarning()
	// --no-device leaves the log in the keystore, and no device to start.
	if a.node.status() == nil && state.IsMember(id) {
		a.startHint()
	}
	return nil
}

func (a *app) writeDisablementSecrets(network string) ([]types.Hash, error) {
	lines := []string{
		"# juist break-glass secrets for network " + network,
		"# Any one of these authorizes recovery if the admin quorum is lost.",
		"# Move this file offline. Losing these AND the admin keys makes the",
		"# network unrecoverable, which is the security property, not a bug.",
	}
	commitments := make([]types.Hash, 0, numDisablementSecrets)
	for range numDisablementSecrets {
		s := make([]byte, types.DisablementSecretSize)
		if _, err := rand.Read(s); err != nil {
			return nil, fmt.Errorf("drawing a break-glass secret: %w", err)
		}
		lines = append(lines, b64.EncodeToString(s))
		commitments = append(commitments, types.DisablementCommit(s))
	}
	return commitments, a.home.writeSecret(breakGlassFile(network), lines)
}

// parseAdminSpec parses NAME=KEY[:VOTES].
func parseAdminSpec(spec string) (types.AdminKey, error) {
	name, rest, ok := strings.Cut(spec, "=")
	if !ok {
		return types.AdminKey{}, fmt.Errorf("--admin %q: expected NAME=KEY[:VOTES]", spec)
	}
	votes := uint64(1)
	// The key's own text form contains a colon, so votes are split off the end.
	if i := strings.LastIndex(rest, ":"); i > 0 {
		if v, err := strconv.ParseUint(rest[i+1:], 10, 32); err == nil {
			votes = v
			rest = rest[:i]
		}
	}
	key, err := types.ParseIdentity(rest)
	if err != nil {
		return types.AdminKey{}, fmt.Errorf("--admin %q: %w", name, err)
	}
	if votes == 0 || votes > types.MaxVotes {
		return types.AdminKey{}, fmt.Errorf("--admin %q: votes must be between 1 and %d", name, types.MaxVotes)
	}
	if err := checkName("--admin", name); err != nil {
		return types.AdminKey{}, err
	}
	return types.AdminKey{Public: key, Votes: uint32(votes), Name: name}, nil
}

// defaultAdminName names the admin key after the person creating it.
func defaultAdminName() string {
	if u, err := user.Current(); err == nil && checkName("user", u.Username) == nil {
		return u.Username
	}
	return "admin"
}

// hostNetsOverlapping names this device's interface networks that overlap p,
// as "10.111.0.0/24 on eth0", other than those at the addresses in own.
func hostNetsOverlapping(p netip.Prefix, own ...netip.Addr) []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipn, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if pfx, ok := netipx.FromStdIPNet(ipn); ok && pfx.Masked().Overlaps(p) && !slices.Contains(own, pfx.Addr()) {
				out = append(out, fmt.Sprintf("%v on %s", pfx.Masked(), ifi.Name))
			}
		}
	}
	return out
}
