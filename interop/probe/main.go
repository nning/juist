// Command probe is the interop lab's target and client, one static binary
// for every system in it:
//
//	probe serve NAME                  answer each TCP connection on port 80 with "NAME from SOURCE", then echo it
//	probe get ADDR:PORT [FROM]        print what the target there answers, asked from FROM
//	probe hold ADDR:PORT FROM SECS    as get, then after SECS on the same connection print the echo of "again"
//	probe dns ADDR                    ask ADDR's port 53 for example.org, and print the answer's code
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func main() {
	if len(os.Args) != 3 && !(len(os.Args) == 4 && os.Args[1] == "get") && !(len(os.Args) == 5 && os.Args[1] == "hold") {
		fmt.Fprintln(os.Stderr, "usage: probe serve NAME | get ADDR:PORT [FROM] | hold ADDR:PORT FROM SECS | dns ADDR")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2])
	case "get":
		err = get(os.Args[2], os.Args[3:])
	case "hold":
		err = hold(os.Args[2], os.Args[3], os.Args[4])
	case "dns":
		err = dns(os.Args[2])
	default:
		err = fmt.Errorf("no command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
}

func serve(name string) error {
	l, err := net.Listen("tcp", ":80")
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
