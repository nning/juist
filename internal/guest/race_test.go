package guest

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// The first connection wins at once, and one that connects after it is
// closed rather than left for the host to time out.
func TestALateDialIsClosed(t *testing.T) {
	winner, _ := net.Pipe()
	defer winner.Close()
	late, lateFar := net.Pipe()
	release := make(chan struct{})
	got, err := dialFirst(t.Context(), []func(context.Context) (net.Conn, error){
		func(context.Context) (net.Conn, error) { return nil, errors.New("refused") },
		func(context.Context) (net.Conn, error) { return winner, nil },
		func(context.Context) (net.Conn, error) { <-release; return late, nil },
	})
	if err != nil || got != winner {
		t.Fatalf("dialFirst = %v, %v; want the connection that was made", got, err)
	}
	close(release)
	_ = lateFar.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := lateFar.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("the late connection is still open: %v", err)
	}
}
