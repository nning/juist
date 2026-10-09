package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// proxy serves HTTP CONNECT on addr, to the names given as NAME=IP and port
// 443 alone, for a client whose Proxy-Authorization is auth's, logging each
// request it is asked, granted or not, to logPath.
func proxy(addr, auth, logPath string, names []string) error {
	to := map[string]string{}
	for _, n := range names {
		name, ip, ok := strings.Cut(n, "=")
		if !ok {
			return fmt.Errorf("%q is no NAME=IP", n)
		}
		to[name] = ip
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	note := func(line string) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintln(logf, line)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			br := bufio.NewReader(c)
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			note(req.Method + " " + req.Host)
			host, port, _ := net.SplitHostPort(req.Host)
			ip, known := to[host]
			switch {
			case req.Method != http.MethodConnect:
				io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
				return
			case req.Header.Get("Proxy-Authorization") != want:
				io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
				return
			case !known || port != "443":
				io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
				return
			}
			up, err := net.Dial("tcp", net.JoinHostPort(ip, port))
			if err != nil {
				io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
				return
			}
			defer up.Close()
			io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
			go func() {
				io.Copy(up, br)
				if tc, ok := up.(*net.TCPConn); ok {
					tc.CloseWrite()
				}
			}()
			io.Copy(c, up)
		}()
	}
}
