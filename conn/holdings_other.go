//go:build (!linux && !freebsd) || android

package conn

// InstanceHoldings reports nothing: the router here keeps no table per
// instance to read, so instances are kept apart by their prefixes alone.
func InstanceHoldings(self int, own string) ([]Holding, error) { return nil, nil }
