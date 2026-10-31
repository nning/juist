package main

import (
	"cmp"
	"crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"go4.org/netipx"

	"github.com/nning/juist/internal/instance"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/trust/store"
	"github.com/nning/juist/types"
)

// drawNetworkName names a network nobody named, as two random words, and
// not as one this keystore has prepared already.
func (a *app) drawNetworkName() (string, error) {
	for {
		name, err := enroll.NetworkName()
		if err != nil {
			return "", err
		}
		if !slices.ContainsFunc([]string{foundedFile(name), breakGlassFile(name), genesisFileFor(name)},
			func(f string) bool { return fileExists(a.home.join(f)) }) {
			return name, nil
		}
	}
}

// An initPlan is what "juist create" was asked for, checked before anything is
// written: the ceremony writes files that cannot simply be written over.
type initPlan struct {
	network, device, adminName string
	adminKey                   string
	noDevice, relay, yes       bool
	voucher                    bool
	adminVotes, quorum         uint
	extraAdmins                stringList
	ipv4                       string
	operator                   optionalString

	// v4 is the parsed --ipv4, and admins every admin key, this keystore's
	// first, whose key the ceremony fills in: key, named keyName, if the
	// keystore holds it already.
	v4       *netip.Prefix
	admins   []types.AdminKey
	keyName  string
	key      types.PrivateIdentity
	keyFound bool
}

func cmdCreate(a *app, args []string) error {
	p, err := a.parseInit(args)
	if err != nil {
		return err
	}
	if err := a.checkInit(&p); err != nil {
		return err
	}
	// On a device already in a network, the new one gets a juistd of its own;
	// one for signing only gets none. $JUIST_NETWORK names a network the
	// device is in, which a new one is not.
	if a.networkFromEnv {
		a.network = ""
	}
	if !p.noDevice {
		a.purpose, a.yes = forFounding, p.yes
	}
	n, op, err := a.initNode(&p)
	if err != nil {
		a.unmake()
		return err
	}
	if err := a.foundNetwork(n, op, &p); err != nil {
		a.unmake()
		return err
	}
	if p.quorum > 1 && !p.voucher {
		a.hint(voucherCarriesHint)
	}
	if p.voucher {
		if auth, err := a.networkLog(); err == nil {
			st := auth.State()
			a.warnVouchers(st.NodesWithRole(types.RoleAdmin), int(st.Vouchers()))
		}
	}
	return nil
}

func (a *app) parseInit(args []string) (initPlan, error) {
	s := spec{name: "juist create", args: "[NETWORK]", max: 1, anyNetwork: true, about: `
Create a network with this device as its first member. NETWORK defaults to
two random words. If the device is already in a network, the new network
gets its own juistd.

--voucher makes this device a voucher too. If it is then off for 48 hours,
the other devices reach only vouchers, so use it on a device that is always
on.

The admin keys (this keystore's and --admin) and --quorum decide who may
change the network. Changing them later takes a quorum too. This keystore's
admin key is new, unless --admin-key reuses one from another network. Losing
the admin keys loses the network: there is no recovery.`}
	var p initPlan
	fs := newFlags(s.name)
	fs.StringVar(&p.device, "device", "", "this device's `NAME` (default: the hostname)")
	fs.BoolVar(&p.noDevice, "no-device", false, "do not make this device a member; for a signing-only machine")
	fs.BoolVar(&p.relay, "relay", false, "make this device a relay")
	fs.BoolVar(&p.voucher, "voucher", false, "make this device a voucher")
	fs.StringVar(&p.adminName, "admin-name", "", "your `NAME` as admin (default: your user name, or --admin-key's)")
	fs.StringVar(&p.adminKey, "admin-key", "", "govern it with the admin key `NAME` here too, as \"juist admins\" lists it")
	fs.Var(&p.extraAdmins, "admin", "another admin, as `NAME=KEY[:VOTES]`; repeatable")
	fs.UintVar(&p.adminVotes, "admin-votes", 1, "votes of the admin key created here")
	fs.UintVar(&p.quorum, "quorum", 1, "votes a change needs")
	fs.StringVar(&p.ipv4, "ipv4", "", "IPv4 `PREFIX`, such as 10.111.0.0/24 (default: a free /22 in "+
		types.OverlayV4.String()+")")
	fs.BoolVar(&p.yes, "yes", false, "do not ask")
	fs.Var(&p.operator, "operator", "local `USER` who manages this device without sudo")
	pos, err := a.parse(s, fs, args)
	if err != nil {
		return p, err
	}
	if p.noDevice && (p.voucher || p.relay) {
		return p, errors.New("--voucher and --relay are roles of this device, which --no-device leaves out")
	}
	if len(pos) == 1 {
		p.network = pos[0]
	} else if p.network, err = a.drawNetworkName(); err != nil {
		return p, err
	}
	switch {
	case p.adminName != "":
	case p.adminKey != "":
		p.adminName = keyPersonOf(p.adminKey)
	default:
		p.adminName = defaultAdminName()
	}
	return p, nil
}

// fileHostAdminKeys files the keys here that a network on this host names.
func (a *app) fileHostAdminKeys() {
	if !a.hostScope() {
		return
	}
	for _, i := range a.networkInstances() {
		if i.st == nil {
			continue
		}
		restore := a.within(i.name())
		a.fileAdminKeys(a.readableLog())
		restore()
	}
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
	// A key made for this network before it, with "juist admins new
	// --network", is the one it was made for.
	p.keyName = cmp.Or(p.adminKey, adminKeyName(p.adminName, p.network))
	// A key another network names is taken only by the name it is filed under.
	a.fileHostAdminKeys()
	var err error
	if p.key, p.keyFound, err = a.home.adminKey(p.keyName); err != nil {
		return err
	} else if !p.keyFound && p.adminKey != "" {
		return fmt.Errorf("--admin-key: no admin key %q here\nhint: juist admins", p.adminKey)
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
		if other := a.networkClaiming(v4); other != "" {
			a.warn("%v overlaps %s, which this device is in; one of the two would run here without IPv4", v4, other)
			if err := a.proceed(p.yes, "continue?"); err != nil {
				return err
			}
		}
		p.v4 = &v4
	} else {
		v4, err := a.drawV4(func(c netip.Prefix) bool {
			return len(hostNetsOverlapping(c)) > 0 || a.networkClaiming(c) != ""
		})
		if err != nil {
			return err
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
	if err := types.ValidateAdmins(p.admins); err != nil {
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
	if p.noDevice && !a.socketExplicit && a.anyInstanceRuns() {
		return nil, operatorChoice{}, errors.New("--no-device: juistd runs here")
	}
	n, err := a.openNode()
	if err != nil {
		return nil, operatorChoice{}, err
	}
	if liveStatus(n) != nil && p.noDevice {
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
	op, err := defaultOperator(p.operator, liveStatus(n))
	if err != nil {
		return nil, operatorChoice{}, err
	}
	// What belongs to one network alone is named for it.
	for _, name := range []string{foundedFile(p.network), breakGlassFile(p.network), genesisFileFor(p.network)} {
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
func (a *app) foundNetwork(n node, op operatorChoice, p *initPlan) (err error) {
	localAdmin := p.key
	var nodes []types.NodeRecord
	machine := ""
	if !p.noDevice {
		founder, err := founderRecord(n, p)
		if err != nil {
			return err
		}
		nodes, machine = append(nodes, founder), founder.Name
	}
	if p.keyFound {
		a.printf("using admin key %q from %s\n", p.keyName, a.home.path)
	} else if localAdmin, err = a.home.createAdminKey(p.keyName, false); err != nil {
		return err
	}
	p.admins[0].Public = localAdmin.Public()
	p.admins[0].Signing, p.admins[0].Endorsement = new(localAdmin.SigningKey()), localAdmin.Endorsement()
	r, err := adminRecipient(localAdmin)
	if err != nil {
		return err
	}
	p.admins[0].Recipient = &r
	p.admins[0].Name = cmp.Or(machine, a.machineName())
	secret, commitment, err := drawBreakGlass()
	if err != nil {
		return err
	}
	genesis, err := log.Genesis(p.network, uint32(p.quorum), p.admins, []types.Hash{commitment}, nodes, sealer())
	if err != nil {
		return err
	}
	genesis.State.V4Prefix = p.v4
	if a.genesisSchema != 0 {
		genesis.State.Schema = a.genesisSchema
	}
	if err := genesis.Sign(localAdmin); err != nil {
		return err
	}
	status, err := log.GenesisStatus(&genesis)
	if err != nil {
		return err
	}
	if !status.Authorized() {
		// The other admins sign it where their keys are; discarding it would
		// strand the key already written for it.
		path := a.home.join(genesisFileFor(p.network))
		if err := writeRecordFile(path, &genesis); err != nil {
			return err
		}
		a.printf("prepared %q; needs %s\n", p.network, approvalsNeeded(status, genesis.State.Admins, &genesis))
		a.printf("wrote %s; each admin runs:\n", path)
		a.command("juist approve %s", filepath.Base(path))
		a.field("Break-glass", "%s", backupLine(breakGlassLine, secret[:]))
		a.breakGlassWarning()
		return nil
	}
	// Handed over, the network may come to be whatever this side hears: its
	// secret is shown, failure or not, or nobody ever has it.
	shown := false
	defer func() {
		if !shown {
			a.field("Break-glass", "%s", backupLine(breakGlassLine, secret[:]))
			a.breakGlassWarning()
		}
	}()
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
		return err
	}
	a.markFounded(p.network)
	return a.reportCreated(&secret, &shown)
}

// markFounded notes in the keystore that the network was founded from it, so
// that no second one of that name is; best effort.
func (a *app) markFounded(network string) {
	_ = os.WriteFile(a.home.join(foundedFile(network)), []byte("# juist: network "+network+" founded here\n"), 0o600)
}

// founderRecord is this device's record in the genesis, at the first address
// of the range.
func founderRecord(n node, p *initPlan) (types.NodeRecord, error) {
	self, err := n.self()
	if err != nil {
		return types.NodeRecord{}, err
	}
	if self.Signing == nil {
		return types.NodeRecord{}, errors.New("juistd runs an older juist than this command\nhint: restart it")
	}
	v4, err := firstFreeV4(types.V4Range(p.v4), nil)
	if err != nil {
		return types.NodeRecord{}, err
	}
	var roles []types.Role
	if p.voucher {
		roles = append(roles, types.RoleAdmin)
	}
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
		Signing:   self.Signing,
	}, nil
}

// reportCreated describes a network that has just come into existence, with
// its break-glass secret where this is the one time it is shown, setting
// shown once it is.
func (a *app) reportCreated(secret *types.DisablementSecret, shown *bool) error {
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
	if secret != nil {
		a.field("Break-glass", "%s", backupLine(breakGlassLine, secret[:]))
		*shown = true
	}
	if st := liveStatus(a.node); st != nil && st.Operator != "" {
		a.field("Operator", "%s", st.Operator)
	}
	a.startWarning()
	a.warnHostOverlap()
	// --no-device leaves the log in the keystore, and no device to start.
	if liveStatus(a.node) == nil && state.IsMember(id) {
		a.startHint()
	}
	if secret != nil {
		a.breakGlassWarning()
	}
	return nil
}

// drawBreakGlass draws the network's one break-glass secret, which juist
// create shows once and writes nowhere, and the genesis's commitment to it.
func drawBreakGlass() (types.DisablementSecret, types.Hash, error) {
	var s types.DisablementSecret
	if _, err := rand.Read(s[:]); err != nil {
		return s, types.Hash{}, fmt.Errorf("drawing the break-glass secret: %w", err)
	}
	return s, types.DisablementCommit(s[:]), nil
}

// breakGlassWarning says what the break-glass secret just shown is for.
func (a *app) breakGlassWarning() {
	a.warn("the break-glass secret is shown only now and kept nowhere: keep it safe, apart from the admin keys")
	a.hint("with it, juist network disable ends the network once too few admin keys are left to change it")
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
	key, signing, endorsement, err := types.ParseAdminKey(rest)
	if err != nil {
		return types.AdminKey{}, fmt.Errorf("--admin %q: %w", name, err)
	}
	if signing == nil {
		return types.AdminKey{}, fmt.Errorf("--admin %q: a key with no signing key, from an older juist\n"+
			"hint: juist admins new prints it whole", name)
	}
	if votes == 0 || votes > types.MaxVotes {
		return types.AdminKey{}, fmt.Errorf("--admin %q: votes must be between 1 and %d", name, types.MaxVotes)
	}
	if err := checkName("--admin", name); err != nil {
		return types.AdminKey{}, err
	}
	return types.AdminKey{Public: key, Votes: uint32(votes), Name: name, Signing: signing, Endorsement: endorsement}, nil
}

// defaultAdminName names the admin key after the person creating it.
func defaultAdminName() string {
	if u, err := user.Current(); err == nil && checkName("user", u.Username) == nil {
		return u.Username
	}
	return "admin"
}

// v4DrawBits is the length of the prefix a network founded without --ipv4
// numbers from: 1022 addresses, one of 128 in [types.OverlayV4]. That is
// about twice [types.MaxNodes] at once, and 1022 admissions over the network's
// life, since no address is handed out twice; renumbering into a larger
// range makes room. A network holding all of 198.18/15 would overlap every
// other on a host that is in two.
const v4DrawBits = 22

// drawV4Prefix picks a random /22 in [types.OverlayV4] that taken leaves. The
// first is never drawn: a network founded before prefixes were drawn numbers
// from the start of the range, so a host in one of those and a new one would
// otherwise hold the same addresses. One that has given out more than 1022
// addresses reaches into the draw's range; a host in both then runs the
// higher instance without IPv4 until one renumbers (daemon/host.go).
func drawV4Prefix(taken func(netip.Prefix) bool) (netip.Prefix, error) {
	candidates := v4DrawCandidates()
	for _, i := range mathrand.Perm(len(candidates)) {
		if !taken(candidates[i]) {
			return candidates[i], nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("every /%d in %v overlaps a network on this host\n"+
		"hint: choose the range with --ipv4", v4DrawBits, types.OverlayV4)
}

// v4DrawCandidates lists the prefixes [drawV4Prefix] draws from, in order:
// every /22 in [types.OverlayV4] but the first.
func v4DrawCandidates() []netip.Prefix {
	var out []netip.Prefix
	p := netip.PrefixFrom(types.OverlayV4.Addr(), v4DrawBits)
	for types.OverlayV4.Contains(p.Addr()) {
		out = append(out, p)
		p = netip.PrefixFrom(netipx.PrefixLastIP(p).Next(), v4DrawBits)
	}
	return out[1:]
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
		// juist's own devices are the host's other networks, which
		// networkClaiming asks about by what they claim.
		if ifi.Flags&net.FlagLoopback != 0 || instance.IsDevice(ifi.Name) {
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
