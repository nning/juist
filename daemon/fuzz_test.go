package daemon

import (
	"bytes"
	"testing"

	"github.com/nning/juist/types"
)

// FuzzDecodeIPCRequest is the IPC request-decoder target
// docs/06-verification.md schedules for M2.
//
// It matters more than its size suggests: the control socket is the only
// parser in this daemon reachable from a local process rather than from the
// network, and docs/04-architecture.md opens on the two CVEs in this space
// that were both reached exactly that way. The assertion is injectivity, the
// same property the record and frame decoders promise — anything accepted
// re-encodes to the bytes it came from, so there is no second spelling of a
// request and nothing can hide in the gap between the two.
func FuzzDecodeIPCRequest(f *testing.F) {
	for _, seed := range []Request{
		{Command: CmdStatus},
		{Command: CmdInform, Records: [][]byte{{0xa1, 0x01, 0x01}}},
		{Command: CmdInform, Records: [][]byte{{}, {1}}},
		{Command: Command(200)},
	} {
		if b, err := ipcEncode(&seed); err == nil {
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
		re, err := ipcEncode(&req)
		if err != nil {
			t.Fatalf("a decoded request failed to re-encode: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("re-encoding changed the bytes:\ninput: %x\nagain: %x", data, re)
		}
		if req.Command != CmdStatus && req.Command != CmdInform {
			t.Fatalf("validate() let through %v", req.Command)
		}
		if len(req.Records) > MaxIPCRecords {
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
		{Status: &Status{Epoch: 3, Members: 2, NetworkName: "n"}},
	} {
		if b, err := ipcEncode(&seed); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(nil))

	f.Fuzz(func(t *testing.T, data []byte) {
		resp, err := DecodeResponse(data)
		if err != nil {
			return
		}
		re, err := ipcEncode(&resp)
		if err != nil {
			t.Fatalf("a decoded response failed to re-encode: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("re-encoding changed the bytes:\ninput: %x\nagain: %x", data, re)
		}
	})
}
