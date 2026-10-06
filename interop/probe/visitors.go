package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// visitors loads a website as browsers do: RATE visitors a second, each with
// connections of its own, one over HTTP/2 or up to six over HTTP/1.1,
// fetching the page and what it links, then leaving the connections open
// until the server closes them or HOLD passes.
func visitors(args []string) error {
	fs := flag.NewFlagSet("visitors", flag.ContinueOnError)
	rate := fs.Float64("rate", 4, "visitors a second")
	dur := fs.Duration("for", time.Minute, "how long visitors keep coming")
	hold := fs.Duration("hold", 5*time.Minute, "how long a visitor keeps a quiet connection, as a browser does")
	from := fs.String("from", "", "source addresses, comma-separated, taken in turn")
	to := fs.String("to", "", "ADDR:PORT to connect to instead of the URL's host")
	ca := fs.String("ca", "", "the CA file the certificate must chain to")
	h3 := fs.Bool("h3", false, "visit over HTTP/3, one QUIC connection each")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: probe visitors [flags] URL")
	}
	page, err := url.Parse(fs.Arg(0))
	if err != nil {
		return err
	}
	cfg := &tls.Config{ServerName: page.Hostname()}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			return err
		}
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(pem) {
			return fmt.Errorf("%s holds no certificate", *ca)
		}
	}
	var sources []net.Addr
	for _, s := range strings.Split(*from, ",") {
		if s != "" {
			sources = append(sources, &net.TCPAddr{IP: net.ParseIP(s)})
		}
	}

	l := &load{page: page, to: *to, tls: cfg, sources: sources, hold: *hold, h3: *h3, errs: map[string]int{}}
	start := time.Now()
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				fmt.Printf("%3.0fs %s\n", time.Since(start).Seconds(), l.line())
			case <-stop:
				return
			}
		}
	}()
	var wg sync.WaitGroup
	every := time.Duration(float64(time.Second) / *rate)
	for i := 0; time.Since(start) < *dur; i++ {
		wg.Go(func() { l.visit(i) })
		time.Sleep(time.Until(start.Add(time.Duration(i+1) * every)))
	}
	wg.Wait()
	close(stop)
	fmt.Printf("done %s\n", l.line())
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range l.errs {
			if !yield(k) {
				return
			}
		}
	})
	for _, k := range keys {
		fmt.Printf("error %dx: %s\n", l.errs[k], k)
	}
	return nil
}

type load struct {
	page    *url.URL
	to      string
	tls     *tls.Config
	sources []net.Addr
	hold    time.Duration
	h3      bool

	open, peak, refused, h2, h3s atomic.Int64
	mu                           sync.Mutex
	ok, failed                   int
	times                        []time.Duration
	errs                         map[string]int
}

var linked = regexp.MustCompile(`(?:href|src)=["']?(/[^"' >]+\.(?:css|js|svg|ico))`)
var fonts = regexp.MustCompile(`url\(["']?(/fonts/[^)"']*-latin-[0-9]+\.woff2)`)

func (l *load) visit(i int) {
	if l.h3 {
		l.visit3(i)
		return
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	if len(l.sources) > 0 {
		d.LocalAddr = l.sources[i%len(l.sources)]
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := d.DialContext(ctx, network, cmpOr(l.to, addr))
			if err != nil {
				return nil, err
			}
			if n := l.open.Add(1); n > l.peak.Load() {
				l.peak.Store(n)
			}
			return &counted{Conn: c, l: l}, nil
		},
		TLSClientConfig:     l.tls,
		ForceAttemptHTTP2:   true,
		MaxConnsPerHost:     6,
		MaxIdleConnsPerHost: 6,
		IdleConnTimeout:     l.hold,
	}
	client := &http.Client{Transport: tr, Timeout: time.Minute}
	start := time.Now()
	err := l.fetchAll(client)
	l.mu.Lock()
	if err != nil {
		l.failed++
		l.errs[err.Error()]++
	} else {
		l.ok++
		l.times = append(l.times, time.Since(start))
	}
	l.mu.Unlock()
	time.AfterFunc(l.hold, tr.CloseIdleConnections)
}

// visit3 is visit over HTTP/3: one QUIC connection, from the visitor's
// source, held as long.
func (l *load) visit3(i int) {
	var from net.IP
	if len(l.sources) > 0 {
		from = l.sources[i%len(l.sources)].(*net.TCPAddr).IP
	}
	tr := &http3.Transport{TLSClientConfig: l.tls, QUICConfig: &quic.Config{MaxIdleTimeout: l.hold},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			to, err := net.ResolveUDPAddr("udp", cmpOr(l.to, addr))
			if err != nil {
				return nil, err
			}
			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: from})
			if err != nil {
				return nil, err
			}
			c, err := quic.Dial(ctx, pc, to, tlsCfg, cfg)
			if err != nil {
				pc.Close()
				return nil, err
			}
			if n := l.open.Add(1); n > l.peak.Load() {
				l.peak.Store(n)
			}
			context.AfterFunc(c.Context(), func() {
				pc.Close()
				l.open.Add(-1)
			})
			return c, nil
		}}
	client := &http.Client{Transport: tr, Timeout: time.Minute}
	start := time.Now()
	err := l.fetchAll(client)
	l.mu.Lock()
	if err != nil {
		l.failed++
		l.errs[err.Error()]++
	} else {
		l.ok++
		l.times = append(l.times, time.Since(start))
	}
	l.mu.Unlock()
	time.AfterFunc(l.hold, func() { tr.Close() })
}

// fetchAll fetches the page, then what it links and the fonts its CSS names,
// at once.
func (l *load) fetchAll(c *http.Client) error {
	body, err := l.get(c, l.page.String())
	if err != nil {
		return err
	}
	assets := linked.FindAllStringSubmatch(body, -1)
	var mu sync.Mutex
	var first error
	var wg sync.WaitGroup
	fetch := func(path string) string {
		b, err := l.get(c, l.page.ResolveReference(&url.URL{Path: path}).String())
		if err != nil {
			mu.Lock()
			first = cmpOr(first, err)
			mu.Unlock()
		}
		return b
	}
	for _, m := range assets {
		wg.Go(func() {
			if b := fetch(m[1]); strings.HasSuffix(m[1], ".css") {
				for _, f := range fonts.FindAllStringSubmatch(b, -1) {
					wg.Go(func() { fetch(f[1]) })
				}
			}
		})
	}
	wg.Wait()
	return first
}

func (l *load) get(c *http.Client, u string) (string, error) {
	resp, err := c.Get(u)
	if err != nil {
		if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "reset") {
			l.refused.Add(1)
		}
		return "", trimErr(err)
	}
	defer resp.Body.Close()
	switch resp.ProtoMajor {
	case 2:
		l.h2.Add(1)
	case 3:
		l.h3s.Add(1)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", trimErr(err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: %s", resp.Request.URL.Path, resp.Status)
	}
	return string(b), nil
}

// trimErr drops the URL and source address from err, so that errors of one
// kind count as one.
func trimErr(err error) error {
	s := regexp.MustCompile(`"[^"]*": |\d+\.\d+\.\d+\.\d+:\d+`).ReplaceAllString(err.Error(), "")
	return fmt.Errorf("%s", s)
}

func (l *load) line() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := slices.Clone(l.times)
	slices.Sort(t)
	pct := func(p int) time.Duration {
		if len(t) == 0 {
			return 0
		}
		return t[min(len(t)-1, len(t)*p/100)].Round(time.Millisecond)
	}
	return fmt.Sprintf("visitors=%d failed=%d open=%d peak=%d refused=%d h2=%d h3=%d p50=%v p99=%v",
		l.ok+l.failed, l.failed, l.open.Load(), l.peak.Load(), l.refused.Load(), l.h2.Load(), l.h3s.Load(), pct(50), pct(99))
}

type counted struct {
	net.Conn
	l    *load
	once sync.Once
}

func (c *counted) Close() error {
	c.once.Do(func() { c.l.open.Add(-1) })
	return c.Conn.Close()
}

func cmpOr[T comparable](a, b T) T {
	var zero T
	if a != zero {
		return a
	}
	return b
}
