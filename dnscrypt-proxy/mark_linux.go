package main

import (
	"syscall"

	"github.com/jedisct1/dlog"
	"golang.org/x/sys/unix"
)

// dialerControlForMark returns a net.Dialer/net.ListenConfig Control
// callback that sets SO_MARK on the underlying socket, so that outgoing
// packets can be steered by policy routing (e.g. to send DoH queries out via
// a specific VPN client). Setting SO_MARK requires CAP_NET_ADMIN.
//
// The mark is resolved per dial rather than captured here, so that a mark
// which changes while the proxy runs takes effect on the next connection.
//
// A mark that cannot be resolved, or cannot be set, never fails the dial: the
// socket is left unmarked and the query follows the default route. This is
// what the unbound build on the same device does, so a VPN client selection
// steers both services the same way and fails over the same way.
func dialerControlForMark(resolver *fwmarkResolver) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		mark := resolver.fwmark()
		if mark == 0 {
			return nil
		}
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			// The mark is bounded to 31 bits when it is read, so it is
			// representable as an int on every platform this builds for.
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		if sockErr != nil {
			dlog.Warnf("Unable to set fwmark %d on socket, CAP_NET_ADMIN is required: %v", mark, sockErr)
		}
		return nil
	}
}
