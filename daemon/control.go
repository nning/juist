package daemon

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/nning/juist/internal/atomicfile"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
)

// mayOperate reports whether who may do more than read the status. A caller
// the platform cannot identify reached a 0600 socket, so it is the daemon's
// own user.
func (s *Service) mayOperate(who caller) bool {
	if !who.known || who.uid == 0 || who.uid == s.selfUID {
		return true
	}
	op := s.operator.Load()
	return op != 0 && who.uid == op
}

// ingressSilence is how long the ingress, which asks every 5 s, may go
// without asking before the status says it is not running.
const ingressSilence = 15 * time.Second

// isIngress and isServe report whether who is the ingress, or the
// terminator.
func (s *Service) isIngress(who caller) bool {
	return who.known && s.ingressUID != 0 && who.uid == s.ingressUID
}

func (s *Service) isServe(who caller) bool {
	return who.known && s.serveUID != 0 && who.uid == s.serveUID
}

// A role is what a caller is to this device; a command's entry in
// [commands] names the roles it answers.
type role uint8

const (
	roleReader   role = 1 << iota // any other local user
	roleIngress                   // the ingress
	roleServe                     // the terminator
	roleOperator                  // root, juistd's own user and the operator
)

// rolesOf is every role who holds: the operator's alone where it holds it.
func (s *Service) rolesOf(who caller) role {
	if s.mayOperate(who) {
		return roleOperator
	}
	var r role
	if s.isIngress(who) {
		r |= roleIngress
	}
	if s.isServe(who) {
		r |= roleServe
	}
	if r == 0 {
		r = roleReader
	}
	return r
}

// tierOf is what who may do on the socket, which decides the pool it waits in.
func (s *Service) tierOf(who caller) tier {
	switch r := s.rolesOf(who); {
	case r == roleOperator:
		return tierOperator
	case r == roleReader:
		return tierReader
	}
	return tierIngress
}

// IngressUser and ServeUser are the users an ingress and a terminator run
// as, which the packages create.
const (
	IngressUser = "juist-ingress"
	ServeUser   = "juist-serve"
)

// lookupUID is name's uid, 0 where there is no such user.
func lookupUID(name string) uint32 {
	u, err := user.Lookup(name)
	if err != nil {
		return 0
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(uid)
}

// mayAppoint reports whether who may choose the operator.
func (s *Service) mayAppoint(who caller) bool {
	return !who.known || who.uid == 0 || who.uid == s.selfUID
}

// A call is one request and who made it, as a command's run takes it.
type call struct {
	ctx     context.Context
	req     *ipc.Request
	who     caller
	events  func(*ipc.Event) error
	replies <-chan ipc.Request
}

// A command is who may ask for it, and what answers it: a response, or an
// error, or neither for the operator's status, the shared default answer.
type command struct {
	who role
	run func(s *Service, c *call) (*ipc.Response, error)
}

// commands answers every command [ipc.Command.Known] names; a test holds the
// two to each other.
var commands = map[ipc.Command]command{
	ipc.CmdStatus:      {roleOperator | roleReader, (*Service).callStatus},
	ipc.CmdPublished:   {roleOperator | roleIngress, (*Service).callPublished},
	ipc.CmdServing:     {roleOperator | roleServe, (*Service).callServing},
	ipc.CmdStatusPage:  {roleOperator | roleServe, (*Service).callStatusPage},
	ipc.CmdSetOperator: {roleOperator, func(s *Service, c *call) (*ipc.Response, error) { return nil, s.appoint(c.req) }},
	ipc.CmdSelf:        {roleOperator, (*Service).callSelf},
	ipc.CmdLog:         {roleOperator, (*Service).callLog},
	ipc.CmdInform:      {roleOperator, func(s *Service, c *call) (*ipc.Response, error) { return nil, s.inform(c.req.Records) }},
	ipc.CmdCreate:      {roleOperator, func(s *Service, c *call) (*ipc.Response, error) { return nil, s.create(c.req) }},
	ipc.CmdJoin:        {roleOperator, (*Service).callJoin},
	ipc.CmdInvite: {roleOperator, func(s *Service, c *call) (*ipc.Response, error) {
		return nil, s.invite(c.ctx, c.req.Offer, c.events, c.replies)
	}},
	ipc.CmdShare: {roleOperator, func(s *Service, c *call) (*ipc.Response, error) {
		return nil, s.share(c.ctx, c.req.Share, c.events)
	}},
	ipc.CmdUnshare: {roleOperator, func(s *Service, c *call) (*ipc.Response, error) { return nil, s.unshare(c.req.Share) }},
	ipc.CmdInviteReply: {roleOperator, func(*Service, *call) (*ipc.Response, error) {
		return nil, errors.New("an invite reply is sent inside the invite it answers")
	}},
	ipc.CmdRotate:   {roleOperator, (*Service).callRotate},
	ipc.CmdUnstage:  {roleOperator, func(s *Service, _ *call) (*ipc.Response, error) { return nil, s.unstage() }},
	ipc.CmdReset:    {roleOperator, func(s *Service, c *call) (*ipc.Response, error) { return nil, s.reset(c.req.Force) }},
	ipc.CmdSubnet:   {roleOperator, func(s *Service, c *call) (*ipc.Response, error) { return nil, s.setSubnet(c.req) }},
	ipc.CmdNames:    {roleOperator, func(s *Service, c *call) (*ipc.Response, error) { return nil, s.setNames(*c.req.AcceptNames) }},
	ipc.CmdSettings: {roleOperator, func(s *Service, c *call) (*ipc.Response, error) { return nil, s.setSettings(c.req) }},
	ipc.CmdPublish:  {roleOperator, func(s *Service, c *call) (*ipc.Response, error) { return nil, s.setPublish(c.req) }},
	ipc.CmdExit:     {roleOperator, func(s *Service, c *call) (*ipc.Response, error) { return nil, s.setExit(c.req) }},
	ipc.CmdPing:     {roleOperator, (*Service).callPing},
	ipc.CmdWaiting:  {roleOperator, (*Service).callWaiting},
}

func (s *Service) handle(ctx context.Context, req *ipc.Request, who caller, events func(*ipc.Event) error,
	replies <-chan ipc.Request) ipc.Response {
	cmd, ok := commands[req.Command]
	if !ok {
		return ipc.Response{Err: fmt.Sprintf("unhandled %v", req.Command)}
	}
	// The one permission check every command passes.
	switch roles := s.rolesOf(who); {
	case roles&cmd.who != 0:
	case roles&roleIngress != 0:
		return ipc.Response{Err: "the ingress may ask what is published, and nothing else"}
	case roles&roleServe != 0:
		return ipc.Response{Err: "the terminator may ask what this device serves and its status page, and nothing else"}
	default:
		return ipc.Response{Err: ipc.ErrNotOperator}
	}
	if req.SetOperator && !s.mayAppoint(who) {
		return ipc.Response{Err: "only root may choose this device's operator"}
	}
	resp, err := cmd.run(s, &call{ctx: ctx, req: req, who: who, events: events, replies: replies})
	switch {
	case err != nil:
		return ipc.Response{Err: err.Error()}
	case resp != nil:
		return *resp
	}
	st := s.Status()
	st.CanOperate = true
	return ipc.Response{Status: &st}
}

func (s *Service) callStatus(c *call) (*ipc.Response, error) {
	st := s.Status()
	st.CanOperate = s.mayOperate(c.who)
	if !st.CanOperate {
		st = st.ForReader()
	} else if m := s.Mesh(); m != nil && st.Exit != nil && !st.Exit.Isolated {
		// Read now, outside the service's lock, as no event says it
		// changed: juist exit use asks it before ending an ssh session.
		ex := *st.Exit
		ex.AnswersThrough = m.answersThrough()
		st.Exit = &ex
	}
	return &ipc.Response{Status: &st}, nil
}

func (s *Service) callPublished(c *call) (*ipc.Response, error) {
	ingress := s.isIngress(c.who)
	if ingress {
		s.ingressAsked.Store(s.now().Unix())
		r := ipc.IngressReportOf(*c.req)
		s.ingressSaid.Store(&r)
		if m := s.Mesh(); m != nil {
			m.NoteIngressListening(r.Listening)
		}
	}
	if m := s.Mesh(); m != nil {
		p := m.Published()
		if ingress && len(p.Relays) > 0 {
			m.ingressTookRelay()
		}
		return &ipc.Response{Published: p}, nil
	}
	return &ipc.Response{Published: &ipc.Published{}}, nil
}

func (s *Service) callServing(c *call) (*ipc.Response, error) {
	if m := s.Mesh(); m != nil {
		req := c.req
		return &ipc.Response{Serving: m.serving(&ipc.TerminatorReport{Account: req.Account,
			Listening: req.Listening, Unbound: req.Unbound, NoCert: req.NoCert, Stopping: req.Stopping}, s.isServe(c.who))}, nil
	}
	return &ipc.Response{Serving: &ipc.Published{}}, nil
}

func (s *Service) callStatusPage(*call) (*ipc.Response, error) {
	p, err := s.StatusPage()
	if err != nil {
		return nil, err
	}
	return &ipc.Response{StatusPage: p}, nil
}

func (s *Service) callSelf(*call) (*ipc.Response, error) {
	s.mu.Lock()
	self := &ipc.Self{Identity: s.keys.Identity.Public(), Keys: s.keys.Public, Name: s.keys.Name,
		Signing: new(s.keys.Identity.SigningKey())}
	s.mu.Unlock()
	return &ipc.Response{Self: self}, nil
}

func (s *Service) callLog(c *call) (*ipc.Response, error) {
	records, err := s.chain()
	var orphans [][]byte
	if err == nil && c.req.Orphans {
		orphans, err = s.orphans(records, maxOrphans)
	}
	if err != nil {
		return nil, err
	}
	return &ipc.Response{Records: records, Orphans: orphans}, nil
}

func (s *Service) callJoin(c *call) (*ipc.Response, error) {
	adm, err := s.join(c.ctx, c.req, c.events)
	if err != nil {
		return nil, err
	}
	st := s.Status()
	st.CanOperate = true
	return &ipc.Response{Status: &st, Admission: adm}, nil
}

func (s *Service) callRotate(c *call) (*ipc.Response, error) {
	rec, proof, err := s.rotate(c.req.Identity)
	if err != nil {
		return nil, err
	}
	return &ipc.Response{Records: [][]byte{rec}, Proof: proof}, nil
}

func (s *Service) callPing(c *call) (*ipc.Response, error) {
	m := s.Mesh()
	if m == nil {
		return nil, errNoNetwork
	}
	p, err := m.Ping(c.ctx, c.req.Ping)
	if err != nil {
		return nil, err
	}
	return &ipc.Response{Ping: p}, nil
}

func (s *Service) callWaiting(c *call) (*ipc.Response, error) {
	m := s.Mesh()
	if m == nil {
		return nil, errNoNetwork
	}
	if err := m.OfferWaiting(c.req.Waiting); err != nil {
		return nil, err
	}
	return &ipc.Response{Waiting: m.Waiting()}, nil
}

func (s *Service) appoint(req *ipc.Request) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.appointLocked(req)
}

func (s *Service) appointLocked(req *ipc.Request) error {
	if !req.SetOperator {
		return nil
	}
	return s.setOperatorLocked(req.OperatorUID)
}

// appointUndoable is appointLocked for a step that may still fail, returning
// how to put the previous operator back.
func (s *Service) appointUndoable(req *ipc.Request) (undo func(), err error) {
	prev := s.operator.Load()
	if err := s.appointLocked(req); err != nil {
		return nil, err
	}
	return func() {
		if req.SetOperator {
			if err := s.setOperatorLocked(prev); err != nil {
				s.logf("daemon: restoring the operator: %v", err)
			}
		}
	}, nil
}

func (s *Service) setOperatorLocked(uid uint32) error {
	path := filepath.Join(s.opts.Home, statedir.OperatorFile)
	if uid == 0 {
		if err := removeIfExists(path); err != nil {
			return err
		}
		s.operator.Store(0)
		return atomicfile.SyncDir(s.opts.Home)
	}
	if err := statedir.WriteFilePrivate(path, []byte(strconv.FormatUint(uint64(uid), 10)+"\n")); err != nil {
		return err
	}
	s.operator.Store(uid)
	return nil
}
