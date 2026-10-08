//go:build !linux

package main

import "syscall"

// dialerControlForMark: SO_MARK-based outgoing policy routing is Linux-only.
// A nil Control callback means the dialer/listener behaves exactly as it did
// before fwmark was configured.
func dialerControlForMark(*fwmarkResolver) func(network, address string, c syscall.RawConn) error {
	return nil
}
