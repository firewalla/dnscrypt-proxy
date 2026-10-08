package main

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDialerControlForMarkSetsSockopt(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("setting SO_MARK requires CAP_NET_ADMIN")
	}
	const mark = 2048

	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to open a socket: %v", err)
	}
	defer conn.Close()
	rawConn, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatalf("unable to get the raw connection: %v", err)
	}

	if err := dialerControlForMark(resolverFor(mark))("udp4", "127.0.0.1:0", rawConn); err != nil {
		t.Fatalf("the Control callback failed: %v", err)
	}

	var (
		readMark int
		readErr  error
	)
	if err := rawConn.Control(func(fd uintptr) {
		readMark, readErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil {
		t.Fatalf("unable to read back the socket option: %v", err)
	}
	if readErr != nil {
		t.Fatalf("unable to read back SO_MARK: %v", readErr)
	}
	if readMark != mark {
		t.Fatalf("expected SO_MARK to be %d, got %d", mark, readMark)
	}
}

func TestDialerControlForMarkLeavesTheSocketUnmarkedWhenUnresolvable(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to open a socket: %v", err)
	}
	defer conn.Close()
	rawConn, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		t.Fatalf("unable to get the raw connection: %v", err)
	}

	// Matching unbound, an unresolvable mark leaves the socket unmarked and
	// lets the query follow the default route instead of failing the dial.
	if err := dialerControlForMark(unresolvableFWMark())("udp4", "127.0.0.1:0", rawConn); err != nil {
		t.Fatalf("expected the dial to proceed unmarked, got: %v", err)
	}

	var (
		readMark int
		readErr  error
	)
	if err := rawConn.Control(func(fd uintptr) {
		readMark, readErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil {
		t.Fatalf("unable to read back the socket option: %v", err)
	}
	if readErr != nil {
		t.Fatalf("unable to read back SO_MARK: %v", readErr)
	}
	if readMark != 0 {
		t.Fatalf("expected the socket to be left unmarked, got %d", readMark)
	}
}
