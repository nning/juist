package malformed

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// decoders are the functions that decode what arrives from outside juistd,
// each of which must recover as the first thing it does. A new decoder of
// outside input joins this list.
var decoders = map[string][]string{
	"types/cbor.go":                       {"DecodeCanonical"},
	"types/aum.go":                        {"DecodeAUM", "DecodeUnsignedAUM"},
	"types/lease.go":                      {"DecodeLease"},
	"gossip/wire.go":                      {"decodeFrame"},
	"gossip/seal.go":                      {"open"},
	"gossip/catchup.go":                   {"decodeCatchUp"},
	"gossip/endpoint.go":                  {"DecodeEndpoint", "DecodeCachedEndpoints"},
	"trust/enroll/session.go":             {"decodeHandshake"},
	"trust/enroll/messages.go":            {"DecodeMessage"},
	"trust/enroll/spake2.go":              {"decodeElement"},
	"internal/aead/aead.go":               {"Open", "OpenPadded"},
	"internal/addrkey/addrkey.go":         {"Open"},
	"internal/waiting/waiting.go":         {"Open", "Decode"},
	"internal/quicinitial/quicinitial.go": {"Parse"},
	"internal/proxyproto/proxyproto.go":   {"ReadLocalUDP", "ReadUDP", "read"},
	"internal/rendezvous/rendezvous.go":   {"open"},
	"internal/names/names.go":             {"Answer", "Question"},
	"discovery/mdns/invite.go":            {"parseInviteAnswer"},
	"discovery/mdns/mdns.go":              {"openPayload"},
	"discovery/dht/dht.go":                {"openAnnouncement"},
	"discovery/dht/store.go":              {"OpenAnnouncement"},
	"relay/cert.go":                       {"DecodeCertificate"},
	"trust/secrets/secrets.go":            {"OpenCatchUp", "OpenFromPeer"},
}

func TestEveryDecoderOfOutsideInputRecovers(t *testing.T) {
	for file, names := range decoders {
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", file), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			for _, name := range names {
				if fn.Name.Name == name {
					found[name] = true
					if !recoversFirst(fn) {
						t.Errorf("%s: %s does not defer malformed.Recover, RecoverOK or RecoverWith first", file, name)
					}
				}
			}
		}
		for _, name := range names {
			if !found[name] {
				t.Errorf("%s: no function %s", file, name)
			}
		}
	}
}

func recoversFirst(fn *ast.FuncDecl) bool {
	if len(fn.Body.List) == 0 {
		return false
	}
	d, ok := fn.Body.List[0].(*ast.DeferStmt)
	if !ok {
		return false
	}
	sel, ok := d.Call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "malformed" &&
		(sel.Sel.Name == "Recover" || sel.Sel.Name == "RecoverOK" || sel.Sel.Name == "RecoverWith")
}
