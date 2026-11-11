package main

import (
	"cmp"
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

	"github.com/nning/juist/internal/govern"
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
two random words. A device already in a network runs the new one in its own
juistd.

Use --voucher only on a device that is always on: if it is off for 48
hours, the other devices reach only vouchers.

Your admin key (new, or --admin-key), the --admin keys and --quorum decide
who may change the network. Losing the admin keys loses the network.`}
	var p initPlan
	fs := newFlags(s.name)
	fs.StringVar(&p.device, "device", "", "this device's `NAME` (default: hostname)")
	fs.BoolVar(&p.noDevice, "no-device", false, "create without this device, for a signing-only machine")
	fs.BoolVar(&p.relay, "relay", false, "make this device a relay")
	fs.BoolVar(&p.voucher, "voucher", false, "make this device a voucher")
	fs.StringVar(&p.adminName, "admin-name", "", "your admin `NAME` (default: user name or --admin-key)")
	fs.StringVar(&p.adminKey, "admin-key", "", "use the existing admin key `NAME` (see juist admins)")
	fs.Var(&p.extraAdmins, "admin", "another admin, as `NAME=KEY[:VOTES]`; repeatable")
	fs.UintVar(&p.adminVotes, "admin-votes", 1, "votes of your admin key")
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
		role := "--voucher"
		if !p.voucher {
			role = "--relay"
		}
		return p, a.usageErr("%s cannot be used with --no-device", role)
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
		return a.usageErr("--quorum must be from 1 to %d", types.MaxVotes)
	}
	if u := a.sudoUser(); u != "" {
		return fmt.Errorf("run as %s, without sudo: the admin key belongs in your keystore", u)
	}
	if err := checkName("network name", p.network); err != nil {
		return a.usageErr("%v", err)
	}
	if err := checkName("--admin-name", p.adminName); err != nil {
		return a.usageErr("%v", err)
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
		return fmt.Errorf("no admin key %q here\nhint: juist admins", p.adminKey)
	}
	if p.device != "" {
		if err := checkName("--device", p.device); err != nil {
			return a.usageErr("%v", err)
		}
	}
	if p.ipv4 != "" {
		v4, err := netip.ParsePrefix(p.ipv4)
		if err != nil {
			return a.usageErr("%q is not an IPv4 prefix", p.ipv4)
		}
		if err := types.ValidateV4Prefix(v4); err != nil {
			return a.usageErr("%v", err)
		}
		if used := hostNetsOverlapping(v4); len(used) > 0 {
			a.warn("%v overlaps %s here; traffic to both goes into the network", v4, strings.Join(used, ", "))
			if err := a.proceed(p.yes, "continue?"); err != nil {
				return err
			}
		}
		if other := a.networkClaiming(v4); other != "" {
			a.warn("%v overlaps %s, which this device is in; one of them would run here without IPv4", v4, other)
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
			return a.usageErr("%v", err)
		}
		// Each key belongs to the person it is named for: two under one name
		// are one admin's, on two devices, and cast one vote.
		key.Holder = key.Name
		p.admins = append(p.admins, key)
	}
	if err := types.ValidateAdmins(p.admins); err != nil {
		return a.usageErr("%v; give one person's keys the same votes", err)
	}
	total := types.AchievableVotes(p.admins)
	if uint32(p.quorum) > total {
		return a.usageErr("--quorum %d is more than the admins have (%s)", p.quorum, count(total, "vote"))
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
				"name, or move the file away if that network was never created", p.network, a.home.join(name))
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
		return types.NodeRecord{}, errors.New("juistd is older than juist\nhint: restart it")
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

// breakGlassWarning says what the break-glass secret just shown is for.
func (a *app) breakGlassWarning() {
	a.warn("the break-glass secret is shown only now and kept nowhere: keep it safe, apart from the admin keys")
	a.hint("with it, juist network disable ends the network when too few admin keys are left")
}

// parseAdminSpec parses NAME=KEY[:VOTES].
func parseAdminSpec(spec string) (types.AdminKey, error) {
	name, rest, ok := strings.Cut(spec, "=")
	if !ok {
		return types.AdminKey{}, fmt.Errorf("--admin %q is not NAME=KEY[:VOTES]", spec)
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
		return types.AdminKey{}, fmt.Errorf("--admin %q: key is from an older juist, without a signing key; make a new one with juist admins new", name)
	}
	if votes == 0 || votes > types.MaxVotes {
		return types.AdminKey{}, fmt.Errorf("--admin %q: votes must be from 1 to %d", name, types.MaxVotes)
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

func drawBreakGlass() (types.DisablementSecret, types.Hash, error) { return govern.DrawBreakGlass() }

func drawV4Prefix(taken func(netip.Prefix) bool) (netip.Prefix, error) { return govern.DrawV4(taken) }

func v4DrawCandidates() []netip.Prefix { return govern.V4DrawCandidates() }
