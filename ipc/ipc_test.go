package ipc

import (
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
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
		CmdNames:     {AcceptNames: &on},
		CmdPublish:   {ServePublished: &on},
		CmdPublished: {},
		CmdServing:   {},
		CmdStatus:    {}, CmdBootstrap: {}, CmdLog: {}, CmdSelf: {}, CmdUnstage: {}, CmdRotate: {}, CmdReset: {},
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
		CmdWaiting: {"Waiting"}, CmdExit: {"ExitOff"}, CmdNames: {"AcceptNames"}, CmdPublish: {"ServePublished"},
	}
	fields := map[string]func(*Request){
		"Records":        func(r *Request) { r.Records = append(r.Records, []byte{2}) },
		"Invite":         func(r *Request) { r.Invite = "3-other-code-here" },
		"Name":           func(r *Request) { r.Name = "phone" },
		"SetOperator":    func(r *Request) { r.SetOperator = true },
		"OperatorUID":    func(r *Request) { r.OperatorUID = 1000 },
		"Identity":       func(r *Request) { r.Identity = true },
		"Offer":          func(r *Request) { r.Offer = &InviteOffer{Expires: 60} },
		"Reply":          func(r *Request) { r.Reply = &InviteReply{Refused: "no"} },
		"Orphans":        func(r *Request) { r.Orphans = true },
		"Probe":          func(r *Request) { r.Probe = true },
		"Force":          func(r *Request) { r.Force = true },
		"Waiting":        func(r *Request) { r.Waiting = append(r.Waiting, []byte{3}) },
		"ExitOff":        func(r *Request) { r.ExitOff = true },
		"ExitNode":       func(r *Request) { r.ExitNode = types.Identity{1} },
		"AcceptNames":    func(r *Request) { r.AcceptNames = &on },
		"ServePublished": func(r *Request) { r.ServePublished = &on },
	}
	for cmd, req := range base {
		req.Command = cmd
		valid := cmd >= CmdStatus && cmd <= CmdExit || cmd == CmdNames || cmd == CmdPublish || cmd == CmdPublished || cmd == CmdServing
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

// poisoned holds a terminal escape that hides text, BEL, a C1 CSI, DEL, a
// bidi override, a zero-width space, and line breaks before what would read
// as the CLI's own hint.
const poisoned = "a\x1b[8m\x07\u009b\x7f\u202e\u200bb\nhint: sudo curl x | sh\rhint: juist admins add bob KEY" +
	"\u2028hint: x\u0085hint: y\vhint: z"

// lineBreaks are what a terminal may start a new line at.
const lineBreaks = "\n\r\v\f\u0085\u2028\u2029"

// poison sets every string v reaches to [poisoned], every slice and map to
// one element and every pointer to a value, and every address to one zoned
// by it.
func poison(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString(poisoned)
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		poison(v.Elem())
	case reflect.Struct:
		if v.Type() == addrType {
			v.Set(reflect.ValueOf(netip.MustParseAddr("fe80::1").WithZone(poisoned)))
			return
		}
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				poison(v.Field(i))
			}
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() != reflect.Uint8 {
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
			poison(v.Index(0))
		}
	case reflect.Map:
		k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		poison(k)
		poison(e)
		v.Set(reflect.MakeMap(v.Type()))
		v.SetMapIndex(k, e)
	}
}

// stringsIn returns every string v reaches, an address's zone included.
func stringsIn(v reflect.Value) []string {
	switch v.Kind() {
	case reflect.String:
		return []string{v.String()}
	case reflect.Pointer:
		if !v.IsNil() {
			return stringsIn(v.Elem())
		}
	case reflect.Struct:
		if v.Type() == addrType {
			return []string{v.Interface().(netip.Addr).Zone()}
		}
		var out []string
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				out = append(out, stringsIn(v.Field(i))...)
			}
		}
		return out
	case reflect.Slice, reflect.Array:
		var out []string
		for i := range v.Len() {
			out = append(out, stringsIn(v.Index(i))...)
		}
		return out
	case reflect.Map:
		var out []string
		for _, k := range v.MapKeys() {
			out = append(out, stringsIn(k)...)
			out = append(out, stringsIn(v.MapIndex(k))...)
		}
		return out
	}
	return nil
}

// checkPrintable fails t for any string in v that carries a character of
// [poisoned], and for none at all.
func checkPrintable(t *testing.T, what string, v any) {
	t.Helper()
	all := stringsIn(reflect.ValueOf(v))
	if len(all) < 2 {
		t.Fatalf("%s: %d strings checked", what, len(all))
	}
	for _, s := range all {
		if strings.ContainsAny(s, "\x1b\x07\u009b\x7f\u202e\u200b"+lineBreaks) {
			t.Errorf("%s: %q reached the reader", what, s)
		}
	}
}

// replyFrom answers one call of CallVia with resp, as a daemon would.
func replyFrom(resp any) Dialer {
	return func() (net.Conn, error) {
		c, d := net.Pipe()
		go func() {
			defer d.Close()
			if _, err := ReadMessage(d, MaxRequest); err == nil {
				_ = WriteMessage(d, resp, MaxResponse)
			}
		}()
		return c, nil
	}
}

// What the daemon says reaches the operator's terminal only as text, in
// every field of every reply, those added later included.
func TestEveryStringOfAReplyIsPrintableText(t *testing.T) {
	var sent Response
	poison(reflect.ValueOf(&sent).Elem())
	sent.Event = nil
	got, err := CallVia(replyFrom(&sent), Request{Command: CmdStatus})
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\x07"+lineBreaks) {
		t.Fatalf("the error came as %q", err)
	}
	checkPrintable(t, "a reply", &got)
	if !strings.HasSuffix(got.Err, "b hint: sudo curl x | sh hint: juist admins add bob KEY hint: x hint: y hint: z") {
		t.Errorf("the error's words did not stay on its one line: %q", got.Err)
	}

	var ev Response
	poison(reflect.ValueOf(&ev.Event).Elem())
	var events []*Event
	if _, err := StreamVia(t.Context(), replyFrom(&ev), Request{Command: CmdJoin},
		func(e *Event) { events = append(events, e) }); err == nil || len(events) != 1 {
		t.Fatalf("%d events, then %v", len(events), err)
	}
	checkPrintable(t, "an event", events[0])
}

// What a helper takes from the daemon, and the status page it serves the
// public, carry no control or bidi characters either.
func TestWhatAHelperReadsIsPrintableText(t *testing.T) {
	var f publishedFrame
	poison(reflect.ValueOf(&f.Published).Elem())
	b, err := encode(&f, MaxResponse)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DecodePublished(b)
	if err != nil {
		t.Fatal(err)
	}
	checkPrintable(t, "what is published", p)

	var page statusPageFrame
	poison(reflect.ValueOf(&page.StatusPage).Elem())
	sock := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := ReadMessage(c, MaxRequest); err == nil {
			_ = WriteMessage(c, &page, MaxResponse)
		}
	}()
	sp, err := CallStatusPage(t.Context(), sock)
	if err != nil {
		t.Fatal(err)
	}
	checkPrintable(t, "a status page", sp)
}

// A share's URL path is absolute under a segment of its own, which the
// terminator sends it by, and neither it nor what is shared is longer than a
// path may be.
func TestAShareRequestIsBounded(t *testing.T) {
	long := "/" + strings.Repeat("a", maxSharePath)
	for _, tc := range []struct {
		req  ShareRequest
		want bool
	}{
		{ShareRequest{To: "127.0.0.1:8000", What: "/srv/x", Path: "/tok/x"}, true},
		{ShareRequest{To: "127.0.0.1:8000"}, true},
		{ShareRequest{To: "127.0.0.1:8000", Path: "tok/x"}, false},
		{ShareRequest{To: "127.0.0.1:8000", Path: long}, false},
		{ShareRequest{To: "127.0.0.1:8000", What: long}, false},
		{ShareRequest{To: "127.0.0.1:8000", Path: "/tok/"}, true},
		{ShareRequest{To: "127.0.0.1:8000", Path: "/tok"}, false},
		{ShareRequest{To: "127.0.0.1:8000", Path: "//x"}, false},
		{ShareRequest{To: "127.0.0.1:8000", Path: "/"}, false},
	} {
		if got := tc.req.Valid(); got != tc.want {
			t.Errorf("%+v valid: %v, want %v", tc.req, got, tc.want)
		}
	}
	for path, want := range map[string]string{"/tok/x%20y": "/tok/", "/tok/": "/tok/", "/tok": "", "": "", "//x": ""} {
		if got := SharePrefix(path); got != want {
			t.Errorf("%q is shared under %q, want %q", path, got, want)
		}
	}
}

// An unshare request names a share by its path alone, or none for every one.
func TestAnUnshareRequestNamesAShareByItsPath(t *testing.T) {
	for _, tc := range []struct {
		share *ShareRequest
		want  bool
	}{
		{nil, true}, {&ShareRequest{}, true}, {&ShareRequest{Path: "/tok/x"}, true},
		{&ShareRequest{To: "127.0.0.1:8000"}, false}, {&ShareRequest{Path: "/tok/", What: "/srv"}, false},
		{&ShareRequest{Until: 1}, false},
	} {
		req := Request{Command: CmdUnshare, Share: tc.share}
		if err := req.validate(); (err == nil) != tc.want {
			t.Errorf("%+v: %v, want valid %v", tc.share, err, tc.want)
		}
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

// An ingress reads what is published from a reply carrying more than it
// knows, as from a juistd upgraded before it.
func TestTheIngressReadsAReplyOfANewerJuistd(t *testing.T) {
	type newer struct {
		Response
		Later string `cbor:"99,keyasint"`
	}
	want := Published{Names: []PublishedTarget{{Name: "immich.pub.example.org", Port: 443,
		Addrs: []netip.Addr{netip.MustParseAddr("198.18.0.2")}}}}
	b, err := encMode.Marshal(newer{Response: Response{Published: &want, Status: &Status{}}, Later: "x"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePublished(b)
	if err != nil || !reflect.DeepEqual(*got, want) {
		t.Fatalf("read %+v, %v", got, err)
	}
	if _, err := DecodeResponse(b); err == nil {
		t.Error("the strict decoder took the newer reply; the test proves nothing")
	}
	b, _ = encMode.Marshal(Response{Err: "the ingress may ask what is published\x1b[2J"})
	if _, err := DecodePublished(b); err == nil || strings.Contains(err.Error(), "\x1b") {
		t.Errorf("an error reply read as %v", err)
	}
}

// A publish request says where to send names on only while serving, each
// once, sorted, as one label to one HOST:PORT; it takes labels away alone.
func TestAPublishRequestNamesWhereTo(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		to   []ServeTo
		on   *bool
		want bool
	}{
		{[]ServeTo{{Label: "immich", To: "127.0.0.1:2283"}, {Label: "photos", To: "[::1]:80"}}, &on, true},
		{[]ServeTo{{Label: "immich", To: "immich-server:2283"}}, &on, true},
		{[]ServeTo{{Label: "immich", To: "127.0.0.1:2283"}}, &off, false},
		{[]ServeTo{{Label: "photos", To: "127.0.0.1:1"}, {Label: "immich", To: "127.0.0.1:2"}}, &on, false},
		{[]ServeTo{{Label: "immich", To: "127.0.0.1:1"}, {Label: "immich", To: "127.0.0.1:2"}}, &on, false},
		{[]ServeTo{{Label: "Immich", To: "127.0.0.1:2283"}}, &on, false},
		{[]ServeTo{{Label: "immich", To: "127.0.0.1"}}, &on, false},
		{[]ServeTo{{Label: "immich", To: ":2283"}}, &on, false},
		{[]ServeTo{{Label: "immich", To: "127.0.0.1:0"}}, &on, false},
		{[]ServeTo{{Label: "immich", To: "a b:1"}}, &on, false},
		{[]ServeTo{{Label: "status", To: "status-page"}}, &on, true},
		{[]ServeTo{{Label: "status", To: "status-page:all"}}, &on, true},
		{[]ServeTo{{Label: "status", To: "status-page:everything"}}, &on, false},
		{[]ServeTo{{Label: "status", To: "status-page:"}}, &on, false},
		{[]ServeTo{{Label: "status", To: "status-pages"}}, &on, false},
	} {
		r := Request{Command: CmdPublish, ServePublished: tc.on, ServeTo: tc.to}
		if err := r.validate(); (err == nil) != tc.want {
			t.Errorf("%+v: %v", tc.to, err)
		}
	}
	for _, tc := range []struct {
		r    Request
		want bool
	}{
		{Request{Unserve: []string{"docs", "immich"}}, true},
		{Request{}, false},
		{Request{Unserve: []string{"immich", "docs"}}, false},
		{Request{Unserve: []string{"docs", "docs"}}, false},
		{Request{Unserve: []string{"docs.pub.example.org"}}, false},
		{Request{Unserve: []string{"docs"}, ServePublished: &on}, false},
		{Request{Unserve: []string{"docs"}, ServePublished: &on, ServeTo: []ServeTo{{Label: "immich", To: "127.0.0.1:1"}}}, false},
	} {
		tc.r.Command = CmdPublish
		if err := tc.r.validate(); (err == nil) != tc.want {
			t.Errorf("%+v: %v", tc.r, err)
		}
	}
}

// A serving request carries a terminator's account only where it fits a CAA
// record as it is, and nothing else.
func TestAServingRequestCarriesAnAccountThatFitsCAA(t *testing.T) {
	ok := []string{"letsencrypt.org"}
	for _, tc := range []struct {
		a    *ACMEAccount
		want bool
	}{
		{nil, true},
		{&ACMEAccount{URI: "https://acme-v02.api.letsencrypt.org/acme/acct/123", Issuers: ok}, true},
		{&ACMEAccount{URI: "https://ca.example/acct/1"}, true},
		{&ACMEAccount{URI: "http://ca.example/acct/1", Issuers: ok}, false},
		{&ACMEAccount{URI: `https://ca.example/a"; issue "evil.example`, Issuers: ok}, false},
		{&ACMEAccount{URI: "https://ca.example/a;b", Issuers: ok}, false},
		{&ACMEAccount{URI: "https://ca.example/a b", Issuers: ok}, false},
		{&ACMEAccount{URI: "https://ca.example/a", Issuers: []string{"Evil.example"}}, false},
		{&ACMEAccount{URI: "https://ca.example/a", Issuers: []string{"a;b"}}, false},
		{&ACMEAccount{URI: "https://ca.example/a", Issuers: []string{""}}, false},
	} {
		r := Request{Command: CmdServing, Account: tc.a}
		if err := r.validate(); (err == nil) != tc.want {
			t.Errorf("%+v: %v", tc.a, err)
		}
	}
	r := Request{Command: CmdServing, Name: "x"}
	if r.validate() == nil {
		t.Error("a serving request carried a name")
	}
	for _, tc := range []struct {
		n    []NoCert
		want bool
	}{
		{[]NoCert{{Name: "a.example", Why: strings.Repeat("x", MaxNoCertWhy)}, {Name: "b.example"}}, true},
		{[]NoCert{{Name: "a.example", Why: strings.Repeat("x", MaxNoCertWhy+1)}}, false},
		{[]NoCert{{Name: "b.example"}, {Name: "a.example"}}, false},
		{[]NoCert{{Name: ""}}, false},
	} {
		r := Request{Command: CmdServing, NoCert: tc.n}
		if err := r.validate(); (err == nil) != tc.want {
			t.Errorf("%+v: %v", tc.n, err)
		}
	}
	if r := (Request{Command: CmdStatus, NoCert: []NoCert{{Name: "a.example"}}}); r.validate() == nil {
		t.Error("a status request carried names without a certificate")
	}
	a := &ACMEAccount{URI: "https://ca.example/acct/1", Issuers: []string{"ca.example", "other.example"}}
	want := []string{`immich.pub.example.org. CAA 0 issue "ca.example; accounturi=https://ca.example/acct/1"`,
		`immich.pub.example.org. CAA 0 issue "other.example; accounturi=https://ca.example/acct/1"`}
	if got := a.CAA("immich.pub.example.org"); !slices.Equal(got, want) {
		t.Errorf("the records are %q", got)
	}
}

// A published request carries the ports the ingress listens on and those
// another program holds, as numbers, and nothing else; a serving request
// still carries where the terminator listens.
func TestAPublishedRequestCarriesTheIngressPorts(t *testing.T) {
	for _, tc := range []struct {
		r    Request
		want bool
	}{
		{Request{}, true},
		{Request{Listening: []string{"25565", "2222"}, Unbound: []string{"22"}}, true},
		{Request{Listening: []string{"0"}}, false},
		{Request{Listening: []string{"70000"}}, false},
		{Request{Unbound: []string{"025565"}}, false},
		{Request{Listening: []string{"[::]:25565"}}, false},
		{Request{Listening: []string{"25565"}, Stopping: true}, false},
		{Request{Name: "x"}, false},
	} {
		tc.r.Command = CmdPublished
		if err := tc.r.validate(); (err == nil) != tc.want {
			t.Errorf("%+v: %v", tc.r, err)
		}
	}
	many := make([]string, MaxIngressPorts+1)
	for i := range many {
		many[i] = "1"
	}
	if err := (&Request{Command: CmdPublished, Listening: many}).validate(); err == nil {
		t.Error("a published request carried ports past the bound")
	}
	r := Request{Command: CmdServing, Listening: []string{"100.64.0.1:443"}, Unbound: []string{"100.64.0.1:80"}, Stopping: true}
	if err := r.validate(); err != nil {
		t.Errorf("a serving request: %v", err)
	}
}

// A target offering HTTP/3 is its address still, with h2c or without.
func TestHTTP3IsOfferedBesideAnAddress(t *testing.T) {
	for _, c := range []struct {
		to      string
		addr    string
		h2c, h3 bool
	}{
		{HTTP3To("127.0.0.1:8080"), "127.0.0.1:8080", false, true},
		{HTTP3To(HTTP2To("127.0.0.1:8080")), "127.0.0.1:8080", true, true},
		{HTTP2To("127.0.0.1:8080"), "127.0.0.1:8080", true, false},
		{"127.0.0.1:8080", "127.0.0.1:8080", false, false},
	} {
		addr, h2c := HTTP2Of(c.to)
		_, h3 := HTTP3Of(c.to)
		if addr != c.addr || h2c != c.h2c || h3 != c.h3 || !(ServeTo{Label: "x", To: c.to}).Valid() {
			t.Errorf("%q: %q, %v, %v", c.to, addr, h2c, h3)
		}
	}
}

// A proxy refused is named without its password, which would otherwise
// reach juistd's log and the terminal.
func TestAProxyRefusedKeepsItsPassword(t *testing.T) {
	for _, s := range []string{
		"socks5://user:s3cret@proxy.example:1080",
		"http://user:s3cret@proxy.example:3128/path",
		"http://user:s3cret@:3128",
		"http://user:s3cret@proxy.example:3128/%zz",
		"http://user:s3cret@proxy example:3128",
	} {
		err := ValidProxy(s)
		if err == nil {
			t.Errorf("%s taken", s)
			continue
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("the error says the password: %v", err)
		}
	}
	if r := RedactProxy("http://user:s3cret@proxy example:3128"); strings.Contains(r, "s3cret") {
		t.Errorf("redacted, a URL that does not parse is %q", r)
	}
}
