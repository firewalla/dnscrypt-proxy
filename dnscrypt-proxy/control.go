package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/jedisct1/dlog"
)

// A minimal control channel, in the spirit of unbound-control: one line-based
// command per connection, one line of reply. It exists so that a health check
// can drop a name from the cache before probing it - otherwise the probe is
// answered from the cache (or from a stale entry once the upstream is gone)
// and never notices that the upstream is unreachable.
//
//	flush <name>              drop <name> for the common record types
//	flush_type <name> <type>  drop <name> for one record type
//
// The same is available from the command line, against the proxy that runs
// with the given configuration file:
//
//	dnscrypt-proxy -config <file> -flush <name>[,<type>]
//
// Replies are "ok <removed entries>" or "error <reason>". There is no
// authentication: the channel is only ever a unix socket (control_socket),
// readable and writable by its owner only.
//
// control_socket defaults to DefaultControlSocket, so a config needs no key for
// it and stays loadable by builds without the control channel; set it to '' to
// turn the channel off. A missing default directory only disables the channel.

const DefaultControlSocket = "/run/dnscrypt/control.sock"

const (
	controlReadTimeout = 2 * time.Second
	controlMaxLine     = 512
	controlMaxConns    = 4
	// How long a flush keeps requests that started before it from writing the
	// flushed name back into the cache. Far longer than any request lives.
	flushFenceTTL = time.Minute
)

// The same set unbound-control's "flush" removes.
var controlFlushTypes = []uint16{
	dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeSOA, dns.TypeCNAME, dns.TypeDNAME,
	dns.TypeMX, dns.TypePTR, dns.TypeSRV, dns.TypeNAPTR, dns.TypeSVCB, dns.TypeHTTPS, dns.TypeTXT,
}

func (proxy *Proxy) startControl(path string) error {
	listener, err := listenControl(path)
	if err != nil {
		return err
	}
	dlog.Noticef("Control channel listening on %s", path)
	slots := make(chan struct{}, controlMaxConns)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				dlog.Warnf("Control channel accept: %v", err)
				time.Sleep(time.Second)
				continue
			}
			select {
			case slots <- struct{}{}:
				go func() {
					defer func() { <-slots }()
					handleControlConn(conn)
				}()
			default:
				conn.Close()
			}
		}
	}()
	return nil
}

func listenControl(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("control_socket must be an absolute path, got [%s]", path)
	}
	if fi, err := os.Lstat(path); err == nil {
		// Only ever remove a socket, never another file, and only one that no
		// running instance answers on: a socket left behind by a process that
		// did not exit cleanly refuses connections, a live one does not.
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		conn, err := net.DialTimeout("unix", path, controlReadTimeout)
		if err == nil {
			conn.Close()
			return nil, fmt.Errorf("%s is in use by another process", path)
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

func handleControlConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlReadTimeout))
	reply, err := readControlLine(conn)
	if err == nil {
		reply = runControlCommand(reply)
	} else if errors.Is(err, errControlLineTooLong) {
		reply = "error line too long"
	} else {
		return
	}
	fmt.Fprintf(conn, "%s\n", reply)
}

var errControlLineTooLong = errors.New("line too long")

// readControlLine reads one line of at most controlMaxLine bytes. Nothing past
// that is ever read, whatever the client sends.
func readControlLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(r, controlMaxLine+1)).ReadString('\n')
	if len(line) > controlMaxLine {
		return "", errControlLineTooLong
	}
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// Flush implements the -flush command line switch: it asks the running proxy,
// through its control socket, to drop "<name>" or "<name>,<type>" from the
// cache, prints the reply and returns the exit code.
func Flush(path string, arg string) int {
	if path == "" {
		fmt.Fprintln(os.Stderr, "the control channel is turned off (control_socket = '')")
		return 1
	}
	command := "flush " + arg
	if name, qtype, found := strings.Cut(arg, ","); found {
		command = "flush_type " + strings.TrimSpace(name) + " " + strings.TrimSpace(qtype)
	}
	reply, err := sendControlCommand(path, command)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(reply)
	if !strings.HasPrefix(reply, "ok") {
		return 1
	}
	return 0
}

func sendControlCommand(path string, command string) (string, error) {
	conn, err := net.DialTimeout("unix", path, controlReadTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(controlReadTimeout))
	if _, err := fmt.Fprintf(conn, "%s\n", command); err != nil {
		return "", err
	}
	return readControlLine(conn)
}

func runControlCommand(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "error empty command"
	}
	switch fields[0] {
	case "flush":
		if len(fields) != 2 {
			return "error usage: flush <name>"
		}
		return fmt.Sprintf("ok %d", flushCachedName(fields[1], controlFlushTypes))
	case "flush_type":
		if len(fields) != 3 {
			return "error usage: flush_type <name> <type>"
		}
		qtype, ok := dns.StringToType[strings.ToUpper(fields[2])]
		if !ok {
			return "error unknown type " + fields[2]
		}
		return fmt.Sprintf("ok %d", flushCachedName(fields[1], []uint16{qtype}))
	default:
		return "error unknown command " + fields[0]
	}
}

// flushCachedName removes every cached entry for name and the given types,
// fresh or stale, under each combination of the DNSSEC and CD flags that are
// part of the cache key. Returns the number of entries removed.
func flushCachedName(name string, qtypes []uint16) int {
	if cachedResponses == nil {
		return 0
	}
	// cache keys use the question name as sent: fully qualified, any case
	qname := name
	if !strings.HasSuffix(qname, ".") {
		qname += "."
	}
	keys := make([][32]byte, 0, len(qtypes)*4)
	for _, qtype := range qtypes {
		for flags := byte(0); flags < 4; flags++ {
			keys = append(keys, cacheKey(qtype, dns.ClassINET, flags, qname))
		}
	}
	return flushGuard.flush(keys)
}

// flushGuard keeps a flush from being undone by a request that was already in
// flight: such a request may hold the stale entry it found and serve it when
// the upstream fails, and the response plugins would then cache it again as
// fresh. A flush records when each key was flushed, and the cache does not
// store a response for a key flushed after the request started.
//
// The check and the store must not be split by a flush, so the cache does both
// under the read lock (insert) and a flush removes and records under the write
// lock: a flush either comes first, and the store sees it, or comes after, and
// removes what was stored. The flush time is taken after the removal, so every
// request that could still have read a removed entry started before it.
var flushGuard cacheFlushGuard

type cacheFlushGuard struct {
	mu        sync.RWMutex
	flushedAt map[[32]byte]time.Time
}

// set by tests to pause a store between the check and the insert
var testHookBeforeCacheInsert func()

// insert stores response under key unless key was flushed after requestStart,
// and reports whether it did.
func (g *cacheFlushGuard) insert(key [32]byte, requestStart time.Time, response CachedResponse) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if flushed, ok := g.flushedAt[key]; ok && !requestStart.After(flushed) {
		return false
	}
	if testHookBeforeCacheInsert != nil {
		testHookBeforeCacheInsert()
	}
	cachedResponses.Insert(key, response)
	return true
}

// flush removes keys from the cache and records their flush time. Returns the
// number of entries removed.
func (g *cacheFlushGuard) flush(keys [][32]byte) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	removed := 0
	for _, key := range keys {
		if _, ok := cachedResponses.Remove(key); ok {
			removed++
		}
	}
	// only now: a request that read an entry before it was removed, even one
	// that started while this flush waited for the lock, started before this
	now := time.Now()
	if g.flushedAt == nil {
		g.flushedAt = make(map[[32]byte]time.Time)
	}
	for k, t := range g.flushedAt {
		if now.Sub(t) > flushFenceTTL {
			delete(g.flushedAt, k)
		}
	}
	for _, key := range keys {
		g.flushedAt[key] = now
	}
	return removed
}

func (g *cacheFlushGuard) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.flushedAt = nil
}
