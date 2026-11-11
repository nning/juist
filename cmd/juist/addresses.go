package main

import (
	"net/netip"

	"github.com/nning/juist/internal/govern"
	"github.com/nning/juist/trust/log"
	"github.com/nning/juist/types"
)

func nextV4(state *log.State, history []types.AUM) (netip.Addr, error) {
	return govern.NextV4(state, history)
}

func firstFreeV4(r netip.Prefix, taken map[netip.Addr]bool) (netip.Addr, error) {
	return govern.FirstFreeV4(r, taken)
}
