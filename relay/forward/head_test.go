package forward

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// A proxy that answers with a head without end is cut off at a bound, not
// read into memory until the dial times out.
func TestAnEndlessAnswerIsCutOff(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
			return
		}
		line := "X-Filler: " + strings.Repeat("a", 1000) + "\r\n"
		if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\n")); err != nil {
			return
		}
		for {
			if _, err := c.Write([]byte(line)); err != nil {
				return
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	via := &url.URL{Scheme: "http", Host: ln.Addr().String()}
	if _, err := connect(ctx, "relay.example.org:443", via); !errors.Is(err, errLongHead) {
		t.Errorf("the endless answer ended in %v", err)
	}
}
