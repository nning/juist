// Command probe is the interop lab's target and client, one static binary
// for every system in it:
//
//	probe serve NAME                  answer each TCP connection on port 80 with "NAME from SOURCE", then echo it
//	probe proxied NAME PORT           as serve, on PORT, SOURCE the client a PROXY protocol v2 header names
//	probe web PORT                    serve HTTP on PORT: a page whose script asks /proto?PROTOCOL, the one it came by, which it prints
//	probe get ADDR:PORT [FROM]        print what the target there answers, asked from FROM
//	probe hold ADDR:PORT FROM SECS    as get, then after SECS on the same connection print the echo of "again"
//	probe dns ADDR                    ask ADDR's port 53 for example.org, and print the answer's code
//	probe resolve ADDR LOG            answer DNS on ADDR's port 53 as the public would, logging "TYPE NAME" to LOG
//	probe tls NAME PORT               as serve, over TLS on PORT, with a certificate of its own
//	probe hello ADDR:PORT SNI [CA]    as get, over TLS, asking for SNI, taking a certificate CA's file issued, or any
//	probe h3get ADDR:PORT NAME CA     fetch https://NAME/ from ADDR:PORT over HTTP/3, and print the protocol and status
//	probe answer ADDR IP [NAME=IP]    answer DNS on ADDR, over UDP and TCP, with IP for every name, "-" for none, but NAMEs
//	probe pairs FILE                  print the newest generation of a pair key in use in juistd's pairs file
//	probe pcap FILE                   print each TCP flow to 443 in a capture with its SNI, or empty, each DNS query, and any other packet
//	probe proxy ADDR USER:PASS LOG NAME=IP...  serve HTTP CONNECT on ADDR to the NAMEs' port 443 alone, logging each request
//	probe visitors [FLAGS] URL        load a website as browsers do, over HTTP/3 with -h3, and print what came of it
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/nning/juist/internal/proxyproto"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "visitors" {
		if err := visitors(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "probe:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 3 && !(len(os.Args) == 4 && slices.Contains([]string{"serve", "get", "resolve", "tls", "hello", "answer", "proxied"}, os.Args[1])) &&
		!(len(os.Args) == 5 && (os.Args[1] == "hold" || os.Args[1] == "hello" || os.Args[1] == "h3get")) && !(len(os.Args) > 4 && os.Args[1] == "answer") &&
		!(len(os.Args) > 5 && os.Args[1] == "proxy") && !(len(os.Args) == 6 && os.Args[1] == "pqget") {
		fmt.Fprintln(os.Stderr, "usage: probe serve NAME [PORT] | proxied NAME PORT | web PORT | get ADDR:PORT [FROM] | hold ADDR:PORT FROM SECS | "+
			"dns ADDR | resolve ADDR LOG | tls NAME PORT | hello ADDR:PORT SNI [CA] | h3get ADDR:PORT NAME CA | pqget ADDR:PORT NAME CA PATH | "+
			"answer ADDR IP [NAME=IP...] | pairs FILE | pcap FILE")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2], append(os.Args[3:], "80")[0])
	case "proxied":
		err = serveProxied(os.Args[2], os.Args[3])
	case "web":
		err = serveWeb(os.Args[2])
	case "get":
		err = get(os.Args[2], os.Args[3:])
	case "hold":
		err = hold(os.Args[2], os.Args[3], os.Args[4])
	case "dns":
		err = dns(os.Args[2])
	case "resolve":
		err = resolve(os.Args[2], os.Args[3])
	case "tls":
		err = serveTLS(os.Args[2], os.Args[3])
	case "hello":
		err = hello(os.Args[2], os.Args[3], os.Args[4:])
	case "h3get":
		err = h3get(os.Args[2], os.Args[3], os.Args[4])
	case "pqget":
		err = pqget(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	case "answer":
		err = answerAll(os.Args[2], os.Args[3], os.Args[4:])
	case "pcap":
		err = pcapFlows(os.Args[2])
	case "pairs":
		err = pairs(os.Args[2])
	case "proxy":
		err = proxy(os.Args[2], os.Args[3], os.Args[4], os.Args[5:])
	default:
		err = fmt.Errorf("no command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

func serve(name, port string) error {
	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Minute))
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			fmt.Fprintf(c, "%s from %s\n", name, host)
			io.Copy(c, c)
		}()
	}
}

func serveProxied(name, port string) error {
	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Minute))
			r := bufio.NewReader(c)
			src, ok, err := proxyproto.Read(r)
			if err != nil || !ok {
				fmt.Fprintf(c, "%s: no PROXY header (%v)\n", name, err)
				return
			}
			fmt.Fprintf(c, "%s from %s\n", name, src.Addr())
			io.Copy(c, r)
		}()
	}
}

// page has a browser say the protocol it fetched the page by, as the
// browser knows it.
const page = `<!doctype html><title>juist</title><script>
fetch('/proto?' + performance.getEntriesByType('navigation')[0].nextHopProtocol)
</script>`

func serveWeb(port string) error {
	return http.ListenAndServe(":"+port, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/proto" {
			fmt.Printf("proto=%s\n", r.URL.RawQuery)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, page)
	}))
}

func serveTLS(name, port string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{name}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	l, err := tls.Listen("tcp", ":"+port, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		return err
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Minute))
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			fmt.Fprintf(c, "%s from %s\n", name, host)
		}()
	}
}

func hello(addr, sni string, ca []string) error {
	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true}
	if len(ca) == 1 {
		pem, err := os.ReadFile(ca[0])
		if err != nil {
			return err
		}
		cfg.RootCAs, cfg.InsecureSkipVerify = x509.NewCertPool(), false
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return fmt.Errorf("%s holds no certificate", ca[0])
		}
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	c, err := tls.DialWithDialer(&d, "tcp", addr, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Print(line)
	return nil
}

// h3get fetches https://name/ over HTTP/3 from addr, by a certificate ca
// issued, and says by which protocol and with what status.
func h3get(addr, name, ca string) error {
	pem, err := os.ReadFile(ca)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("%s holds no certificate", ca)
	}
	tr := &http3.Transport{TLSClientConfig: &tls.Config{ServerName: name, RootCAs: roots},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, addr, tlsCfg, cfg)
		}}
	defer tr.Close()
	c := http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := c.Get("https://" + name + "/")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	fmt.Println(resp.Proto, resp.StatusCode)
	return nil
}

// pqget fetches https://name/path from addr as juist's own ends do, over TLS
// 1.3 with X25519MLKEM768 alone, by a certificate ca issued, and says the
// status and the issuer.
func pqget(addr, name, ca, path string) error {
	pem, err := os.ReadFile(ca)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("%s holds no certificate", ca)
	}
	cfg := &tls.Config{ServerName: name, RootCAs: roots, MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	d := net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{TLSClientConfig: cfg,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://" + name + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	fmt.Println(resp.StatusCode, resp.TLS.PeerCertificates[0].Issuer)
	return nil
}

func answerAll(addr, ip string, names []string) error {
	a, err := netip.ParseAddr(ip)
	if ip != "-" && (err != nil || !a.Is4()) {
		return fmt.Errorf("%q is no IPv4 address", ip)
	}
	byName := map[string]netip.Addr{}
	for _, n := range names {
		name, at, _ := strings.Cut(n, "=")
		na, err := netip.ParseAddr(at)
		if err != nil || !na.Is4() {
			return fmt.Errorf("%q is no NAME=IP", n)
		}
		byName[strings.ToLower(strings.TrimSuffix(name, "."))] = na
	}
	reply := func(q []byte) []byte {
		var p dnsmessage.Parser
		h, err := p.Start(q)
		if err != nil {
			return nil
		}
		question, err := p.Question()
		if err != nil {
			return nil
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true})
		b.StartQuestions()
		b.Question(question)
		b.StartAnswers()
		to := a
		if na, ok := byName[strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))]; ok {
			to = na
		}
		if question.Type == dnsmessage.TypeA && to.IsValid() {
			b.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 5},
				dnsmessage.AResource{A: to.As4()})
		}
		out, _ := b.Finish()
		return out
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := reply(buf[:n]); out != nil {
				pc.WriteTo(out, from)
			}
		}
	}()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Minute))
			for {
				var n [2]byte
				if _, err := io.ReadFull(c, n[:]); err != nil {
					return
				}
				q := make([]byte, int(n[0])<<8|int(n[1]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				out := reply(q)
				if out == nil {
					return
				}
				if _, err := c.Write(append([]byte{byte(len(out) >> 8), byte(len(out))}, out...)); err != nil {
					return
				}
			}
		}()
	}
}

func hold(addr, from, secs string) error {
	n, err := strconv.Atoi(secs)
	if err != nil {
		return err
	}
	ip := net.ParseIP(from)
	if ip == nil {
		return fmt.Errorf("%q is no address", from)
	}
	c, err := (&net.Dialer{Timeout: 10 * time.Second, LocalAddr: &net.TCPAddr{IP: ip}}).Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	r := bufio.NewReader(c)
	if _, err := r.ReadString('\n'); err != nil {
		return err
	}
	fmt.Println("held")
	time.Sleep(time.Duration(n) * time.Second)
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := fmt.Fprintln(c, "again"); err != nil {
		return err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Print(line)
	return nil
}

func get(addr string, from []string) error {
	d := net.Dialer{Timeout: 10 * time.Second}
	if len(from) == 1 {
		ip := net.ParseIP(from[0])
		if ip == nil {
			return fmt.Errorf("%q is no address", from[0])
		}
		d.LocalAddr = &net.TCPAddr{IP: ip}
	}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Print(line)
	return nil
}

func dns(addr string) error {
	name := dnsmessage.MustNewName("example.org.")
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 0x6a75, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	b, err := q.Pack()
	if err != nil {
		return err
	}
	c, err := net.Dial("udp", net.JoinHostPort(addr, "53"))
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(b); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return err
	}
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	if err != nil {
		return err
	}
	if h.ID != q.ID || !h.Response {
		return fmt.Errorf("no answer to the query: %+v", h)
	}
	fmt.Println(h.RCode)
	return nil
}

// Public addresses resolve answers every name with.
var (
	public4 = [4]byte{203, 0, 113, 7}
	public6 = [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 7}
)

func resolve(addr, logPath string) error {
	c, err := net.ListenPacket("udp", net.JoinHostPort(addr, "53"))
	if err != nil {
		return err
	}
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	buf := make([]byte, 1500)
	for {
		n, src, err := c.ReadFrom(buf)
		if err != nil {
			return err
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		fmt.Fprintf(log, "%s %s\n", strings.TrimPrefix(q.Type.String(), "Type"), strings.ToLower(q.Name.String()))
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true,
			RecursionDesired: h.RecursionDesired, RecursionAvailable: true})
		b.StartQuestions()
		b.Question(q)
		b.StartAnswers()
		rh := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 5}
		switch q.Type {
		case dnsmessage.TypeA:
			b.AResource(rh, dnsmessage.AResource{A: public4})
		case dnsmessage.TypeAAAA:
			b.AAAAResource(rh, dnsmessage.AAAAResource{AAAA: public6})
		}
		if msg, err := b.Finish(); err == nil {
			c.WriteTo(msg, src)
		}
	}
}
