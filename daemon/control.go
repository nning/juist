package daemon

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/nning/juist/internal/keys"
	"github.com/nning/juist/internal/statedir"
	"github.com/nning/juist/ipc"
	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/types"
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

// tierOf is what who may do on the socket.
func (s *Service) tierOf(who caller) tier {
	switch {
	case s.mayOperate(who):
		return tierOperator
	case s.isIngress(who), s.isServe(who):
		return tierIngress
	}
	return tierReader
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

func (s *Service) handle(ctx context.Context, req *ipc.Request, who caller, events func(*ipc.Event) error,
	replies <-chan ipc.Request) ipc.Response {
	operates := s.mayOperate(who)
	switch {
	case req.Command == ipc.CmdPublished && (operates || s.isIngress(who)):
		if s.isIngress(who) {
			s.ingressAsked.Store(s.now().Unix())
			r := ipc.IngressReportOf(*req)
			s.ingressSaid.Store(&r)
			if m := s.Mesh(); m != nil {
				m.NoteIngressListening(r.Listening)
			}
		}
		if m := s.Mesh(); m != nil {
			p := m.Published()
			if s.isIngress(who) && len(p.Relays) > 0 {
				m.ingressTookRelay()
			}
			return ipc.Response{Published: p}
		}
		return ipc.Response{Published: &ipc.Published{}}
	case req.Command == ipc.CmdServing && (operates || s.isServe(who)):
		if m := s.Mesh(); m != nil {
			return ipc.Response{Serving: m.serving(&ipc.TerminatorReport{Account: req.Account,
				Listening: req.Listening, Unbound: req.Unbound, NoCert: req.NoCert, Stopping: req.Stopping}, s.isServe(who))}
		}
		return ipc.Response{Serving: &ipc.Published{}}
	case req.Command == ipc.CmdStatusPage && (operates || s.isServe(who)):
		p, err := s.StatusPage()
		if err != nil {
			return ipc.Response{Err: err.Error()}
		}
		return ipc.Response{StatusPage: p}
	case s.isIngress(who) && !operates:
		return ipc.Response{Err: "the ingress may ask what is published, and nothing else"}
	case s.isServe(who) && !operates:
		return ipc.Response{Err: "the terminator may ask what this device serves and its status page, and nothing else"}
	}
	if req.Command == ipc.CmdStatus {
		st := s.Status()
		st.CanOperate = s.mayOperate(who)
		if !st.CanOperate {
			st = st.ForReader()
		}
		return ipc.Response{Status: &st}
	}
	if !s.mayOperate(who) {
		return ipc.Response{Err: ipc.ErrNotOperator}
	}
	if req.SetOperator && !s.mayAppoint(who) {
		return ipc.Response{Err: "only root may choose this device's operator"}
	}
	var err error
	switch req.Command {
	case ipc.CmdSetOperator:
		err = s.appoint(req)
	case ipc.CmdSelf:
		s.mu.Lock()
		self := &ipc.Self{Identity: s.keys.Identity.Public(), Keys: s.keys.Public, Name: s.keys.Name}
		s.mu.Unlock()
		return ipc.Response{Self: self}
	case ipc.CmdLog:
		var records, orphans [][]byte
		if records, err = s.chain(); err == nil && req.Orphans {
			orphans, err = s.orphans(records, maxOrphans)
		}
		if err == nil {
			return ipc.Response{Records: records, Orphans: orphans}
		}
	case ipc.CmdBootstrap:
		if m := s.Mesh(); m != nil {
			return ipc.Response{Bootstrap: m.bootstrapHints()}
		}
		return ipc.Response{Bootstrap: &ipc.Bootstrap{}}
	case ipc.CmdInform:
		err = s.inform(req.Records)
	case ipc.CmdCreate:
		err = s.create(req)
	case ipc.CmdJoin:
		var adm *enroll.Admission
		if adm, err = s.join(ctx, req, events); err == nil {
			st := s.Status()
			st.CanOperate = true
			return ipc.Response{Status: &st, Admission: adm}
		}
	case ipc.CmdInvite:
		err = s.invite(ctx, req.Offer, events, replies)
	case ipc.CmdShare:
		err = s.share(ctx, req.Share, events)
	case ipc.CmdUnshare:
		err = s.unshare(req.Share)
	case ipc.CmdInviteReply:
		err = errors.New("an invite reply is sent inside the invite it answers")
	case ipc.CmdRotate:
		var rec []byte
		var proof *types.Sig
		if rec, proof, err = s.rotate(req.Identity); err == nil {
			return ipc.Response{Records: [][]byte{rec}, Proof: proof}
		}
	case ipc.CmdUnstage:
		err = s.unstage()
	case ipc.CmdReset:
		err = s.reset(req.Force)
	case ipc.CmdSubnet:
		err = s.setSubnet(req)
	case ipc.CmdNames:
		err = s.setNames(*req.AcceptNames)
	case ipc.CmdSettings:
		err = s.setSettings(req)
	case ipc.CmdPublish:
		err = s.setPublish(req)
	case ipc.CmdExit:
		err = s.setExit(req)
	case ipc.CmdPing:
		m := s.Mesh()
		if m == nil {
			err = errNoNetwork
			break
		}
		var p *ipc.Ping
		if p, err = m.Ping(ctx, req.Ping); err == nil {
			return ipc.Response{Ping: p}
		}
	case ipc.CmdWaiting:
		m := s.Mesh()
		if m == nil {
			err = errNoNetwork
			break
		}
		if err = m.OfferWaiting(req.Waiting); err == nil {
			return ipc.Response{Waiting: m.Waiting()}
		}
	default:
		err = fmt.Errorf("unhandled %v", req.Command)
	}
	if err != nil {
		return ipc.Response{Err: err.Error()}
	}
	st := s.Status()
	st.CanOperate = true
	return ipc.Response{Status: &st}
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
		return keys.SyncDir(s.opts.Home)
	}
	if err := statedir.WriteFilePrivate(path, []byte(strconv.FormatUint(uint64(uid), 10)+"\n")); err != nil {
		return err
	}
	s.operator.Store(uid)
	return nil
}
