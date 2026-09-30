package ipc

import (
	"slices"
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

// TestIPCMessageRoundTrip pins the encoding both halves share.
func TestIPCMessageRoundTrip(t *testing.T) {
	req := Request{Command: CmdInform, Records: [][]byte{{1, 2, 3}}}
	b, err := encode(&req, MaxRequest)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRequest(b)
	if err != nil || got.Command != req.Command || len(got.Records) != 1 {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	if _, err := DecodeRequest(append(b, 0)); err == nil {
		t.Error("a request with trailing bytes was accepted")
	}
	resp := Response{Status: &Status{Derived: Derived{Epoch: 4}}, Event: nil}
	rb, err := encode(&resp, MaxResponse)
	if err != nil {
		t.Fatal(err)
	}
	if gotResp, err := DecodeResponse(rb); err != nil || gotResp.Status.Epoch != 4 {
		t.Fatalf("reply round trip: %+v, %v", gotResp, err)
	}
}

// Each command takes exactly the fields listed here beside the ones it needs.
func TestEachCommandTakesItsOwnFields(t *testing.T) {
	on := true
	base := map[Command]Request{
		CmdNames:  {AcceptNames: &on},
		CmdStatus: {}, CmdBootstrap: {}, CmdLog: {}, CmdSelf: {}, CmdUnstage: {}, CmdRotate: {}, CmdReset: {},
		CmdWaiting:     {},
		CmdExit:        {ExitOff: true},
		CmdInform:      {Records: [][]byte{{1}}},
		CmdCreate:      {Records: [][]byte{{1}}},
		CmdJoin:        {Invite: "7-acme-adviser-aimless"},
		CmdSetOperator: {SetOperator: true},
		CmdInvite:      {Offer: &InviteOffer{Expires: 60}},
		CmdInviteReply: {Reply: &InviteReply{Refused: "no"}},
		cmdInvalid:     {}, Command(16): {}, Command(200): {},
	}
	accepts := map[Command][]string{
		CmdStatus: {"Probe"}, CmdLog: {"Orphans"}, CmdRotate: {"Identity"}, CmdReset: {"Force"},
		CmdInform: {"Records"}, CmdCreate: {"SetOperator"}, CmdJoin: {"Invite", "Name", "SetOperator"},
		CmdSetOperator: {"SetOperator", "OperatorUID"}, CmdInvite: {"Offer"}, CmdInviteReply: {"Reply"},
		CmdWaiting: {"Waiting"}, CmdExit: {"ExitOff"}, CmdNames: {"AcceptNames"},
	}
	fields := map[string]func(*Request){
		"Records":     func(r *Request) { r.Records = append(r.Records, []byte{2}) },
		"Invite":      func(r *Request) { r.Invite = "3-other-code-here" },
		"Name":        func(r *Request) { r.Name = "phone" },
		"SetOperator": func(r *Request) { r.SetOperator = true },
		"OperatorUID": func(r *Request) { r.OperatorUID = 1000 },
		"Identity":    func(r *Request) { r.Identity = true },
		"Offer":       func(r *Request) { r.Offer = &InviteOffer{Expires: 60} },
		"Reply":       func(r *Request) { r.Reply = &InviteReply{Refused: "no"} },
		"Orphans":     func(r *Request) { r.Orphans = true },
		"Probe":       func(r *Request) { r.Probe = true },
		"Force":       func(r *Request) { r.Force = true },
		"Waiting":     func(r *Request) { r.Waiting = append(r.Waiting, []byte{3}) },
		"ExitOff":     func(r *Request) { r.ExitOff = true },
		"ExitNode":    func(r *Request) { r.ExitNode = types.Identity{1} },
		"AcceptNames": func(r *Request) { r.AcceptNames = &on },
	}
	for cmd, req := range base {
		req.Command = cmd
		valid := cmd >= CmdStatus && cmd <= CmdExit || cmd == CmdNames
		if err := req.validate(); (err == nil) != valid {
			t.Errorf("%v alone: %v", cmd, err)
		}
		for name, set := range fields {
			r := req
			r.Records = slices.Clone(req.Records)
			set(&r)
			want := valid && slices.Contains(accepts[cmd], name)
			if err := r.validate(); (err == nil) != want {
				t.Errorf("%v with %s: accepted %v, want %v (%v)", cmd, name, err == nil, want, err)
			}
		}
	}
}

// What the daemon says reaches the operator's terminal only as text.
func TestRepliesArePrintableText(t *testing.T) {
	b, err := encode(&Response{Err: "no\x1b]0;owned\x07 way\nhint",
		Status: &Status{
			Derived: Derived{Alarm: "\x1b[2Jcleared", NetworkName: "home\u202egnp.exe",
				Devices: []Device{{Name: "b\x1b[0m", V4: "\u202e1"}}},
			Tunnels: Tunnels{HomeRelay: "\x1b[1mvps", TunnelsDown: []string{"a\x07"}}}}, MaxResponse)
	if err != nil {
		t.Fatal(err)
	}
	r, err := DecodeResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	r.makePrintable()
	for _, s := range []string{r.Err, r.Status.Alarm, r.Status.NetworkName, r.Status.HomeRelay,
		r.Status.TunnelsDown[0], r.Status.Devices[0].Name, r.Status.Devices[0].V4} {
		if strings.ContainsAny(s, "\x1b\x07\u202e") {
			t.Errorf("%q reached the CLI", s)
		}
	}
	if !strings.Contains(r.Err, "\nhint") {
		t.Errorf("the newline before a hint was lost: %q", r.Err)
	}
}

// An exit request sets one thing: a node, isolated or not, off, or serving.
func TestAnExitRequestSetsOneThing(t *testing.T) {
	on := true
	id := types.Identity{1}
	for _, tc := range []struct {
		req  Request
		want bool
	}{
		{Request{ExitNode: id}, true}, {Request{ExitOff: true}, true}, {Request{Serve: &on}, true},
		{Request{}, false}, {Request{ExitNode: id, ExitOff: true}, false}, {Request{ExitOff: true, Serve: &on}, false},
		{Request{ExitNode: id, ExitIsolate: true}, true}, {Request{ExitOff: true, ExitIsolate: true}, false},
		{Request{ExitIsolate: true}, false},
	} {
		tc.req.Command = CmdExit
		if err := tc.req.validate(); (err == nil) != tc.want {
			t.Errorf("%+v: %v, want valid %v", tc.req, err, tc.want)
		}
	}
}

func TestANamesRequestSetsAcceptingAlone(t *testing.T) {
	on := true
	for _, tc := range []struct {
		req  Request
		want bool
	}{
		{Request{AcceptNames: &on}, true}, {Request{}, false}, {Request{AcceptNames: &on, AcceptSubnets: &on}, false},
	} {
		tc.req.Command = CmdNames
		if err := tc.req.validate(); (err == nil) != tc.want {
			t.Errorf("%+v: %v, want valid %v", tc.req, err, tc.want)
		}
	}
	if err := (&Request{Command: CmdSubnet, AcceptSubnets: &on, AcceptNames: &on}).validate(); err == nil {
		t.Error("a subnet request sets names")
	}
}

func TestASubnetRequestSetsOneThing(t *testing.T) {
	on := true
	for _, tc := range []struct {
		req  Request
		want bool
	}{
		{Request{ServeSubnets: &on}, true}, {Request{AcceptSubnets: &on}, true}, {Request{}, false},
		{Request{ServeSubnets: &on, AcceptSubnets: &on}, false}, {Request{ServeSubnets: &on, Serve: &on}, false},
	} {
		tc.req.Command = CmdSubnet
		if err := tc.req.validate(); (err == nil) != tc.want {
			t.Errorf("%+v: %v, want valid %v", tc.req, err, tc.want)
		}
	}
}
