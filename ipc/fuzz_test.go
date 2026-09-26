package ipc

import (
	"bytes"
	"testing"

	"github.com/nning/juist/trust/enroll"
	"github.com/nning/juist/types"
)

// FuzzDecodeIPCRequest targets the control socket, the one parser in this
// daemon reachable from a local process rather than the network. The assertion
// is injectivity, as for the record and frame decoders: anything accepted
// re-encodes to the bytes it came from.
func FuzzDecodeIPCRequest(f *testing.F) {
	for _, seed := range []Request{
		{Command: CmdStatus},
		{Command: CmdBootstrap},
		{Command: CmdJoin, Invite: "7-acme-adviser-aimless", Name: "phone"},
		{Command: CmdSetOperator, SetOperator: true, OperatorUID: 1000},
		{Command: CmdRotate, Identity: true},
		{Command: CmdInform, Records: [][]byte{{0xa1, 0x01, 0x01}}},
		{Command: CmdInform, Records: [][]byte{{}, {1}}},
		{Command: CmdInvite, Offer: &InviteOffer{Port: 41642, LAN: true, DHT: true, Expires: 3600}},
		{Command: CmdInviteReply, Reply: &InviteReply{Waiting: &enroll.Waiting{Votes: 1, Quorum: 2}}},
		{Command: CmdInviteReply, Reply: &InviteReply{Name: "phone", Admission: &enroll.Admission{}}},
		{Command: CmdInviteReply, Reply: &InviteReply{Refused: "no"}},
		{Command: CmdReset, Force: true},
		{Command: Command(200)},
	} {
		if b, err := encode(&seed, MaxRequest); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(nil))
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := DecodeRequest(data)
		if err != nil {
			return
		}
		re, err := encode(&req, MaxRequest)
		if err != nil {
			t.Fatalf("a decoded request failed to re-encode: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("re-encoding changed the bytes:\ninput: %x\nagain: %x", data, re)
		}
		if req.Command < CmdStatus || req.Command > CmdReset {
			t.Fatalf("validate() let through %v", req.Command)
		}
		if (req.Offer != nil) != (req.Command == CmdInvite) || (req.Reply != nil) != (req.Command == CmdInviteReply) {
			t.Fatalf("validate() let through a %v request with another command's fields", req.Command)
		}
		if req.Command != CmdInform && req.Command != CmdCreate && len(req.Records) > 0 {
			t.Fatalf("validate() let through a %v request carrying records", req.Command)
		}
		if req.OperatorUID != 0 && !req.SetOperator {
			t.Fatal("validate() let through an operator nobody asked to set")
		}
		if req.Command == CmdJoin && (req.Invite == "" || len(req.Invite) > maxInvite) {
			t.Fatal("validate() let through a join with a bad invite")
		}
		if len(req.Records) > MaxRecords {
			t.Fatal("validate() let through a request over the record limit")
		}
		// Whatever a request carries, turning it into records must terminate
		// without panicking; whether they are valid is the log's business.
		for _, raw := range req.Records {
			_, _ = types.DecodeAUM(raw)
		}
	})
}

// FuzzDecodeIPCResponse covers the half the CLI parses. A daemon is more
// trusted than a peer, but "more trusted" is not "trusted": the socket path is
// caller-supplied, so what answers on it is not guaranteed to be a daemon.
func FuzzDecodeIPCResponse(f *testing.F) {
	for _, seed := range []Response{
		{Err: "no"},
		{Status: &Status{Derived: Derived{Epoch: 3, Members: 2, NetworkName: "n"}}},
		{Bootstrap: &Bootstrap{Endpoints: [][]byte{{1}}, Leases: [][]byte{{2}}}},
	} {
		if b, err := encode(&seed, MaxRequest); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		resp, err := DecodeResponse(data)
		if err != nil {
			return
		}
		re, err := encode(&resp, MaxResponse)
		if err != nil {
			t.Fatalf("a decoded response failed to re-encode: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("re-encoding changed the bytes:\ninput: %x\nagain: %x", data, re)
		}
	})
}
