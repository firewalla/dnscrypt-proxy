package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
	"github.com/BurntSushi/toml"
)

func resetControlState(t *testing.T) {
	t.Helper()
	cachedResponses = nil
	if err := initCachedResponses(1024); err != nil {
		t.Fatal(err)
	}
	flushGuard.reset()
	t.Cleanup(func() {
		cachedResponses = nil
		flushGuard.reset()
	})
}

func seedCache(t *testing.T, qname string, qtype uint16, flags byte, expiration time.Time) {
	t.Helper()
	cachedResponses.Insert(cacheKey(qtype, dns.ClassINET, flags, qname), CachedResponse{expiration: expiration, msg: new(dns.Msg)})
}

func cached(qname string, qtype uint16, flags byte) bool {
	_, ok := cachedResponses.Get(cacheKey(qtype, dns.ClassINET, flags, qname))
	return ok
}

// a socket path under the test's temp dir, short enough for sun_path
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir + "/c.sock"
}

func TestControlFlush(t *testing.T) {
	resetControlState(t)

	now := time.Now()
	seedCache(t, "firewalla.encipher.io.", dns.TypeA, 0, now.Add(time.Hour))
	seedCache(t, "Firewalla.Encipher.IO.", dns.TypeA, 2, now.Add(-time.Hour)) // stale, CD, mixed case
	seedCache(t, "firewalla.encipher.io.", dns.TypeAAAA, 1, now.Add(time.Hour))
	seedCache(t, "github.com.", dns.TypeA, 0, now.Add(time.Hour))

	if got := runControlCommand("flush_type firewalla.encipher.io aaaa"); got != "ok 1" {
		t.Fatalf("flush_type: got %q", got)
	}
	if cached("firewalla.encipher.io.", dns.TypeAAAA, 1) || !cached("firewalla.encipher.io.", dns.TypeA, 0) {
		t.Fatal("flush_type removed the wrong entries")
	}

	if got := runControlCommand("flush FIREWALLA.encipher.io"); got != "ok 2" {
		t.Fatalf("flush: got %q", got)
	}
	if cached("firewalla.encipher.io.", dns.TypeA, 0) || cached("firewalla.encipher.io.", dns.TypeA, 2) {
		t.Fatal("flush left an entry behind")
	}
	if !cached("github.com.", dns.TypeA, 0) {
		t.Fatal("flush removed an unrelated name")
	}

	if got := runControlCommand("flush firewalla.encipher.io."); got != "ok 0" {
		t.Fatalf("flush of an absent name: got %q", got)
	}
	for _, bad := range []string{"", "flush", "flush_type a.com BOGUS", "purge a.com"} {
		if got := runControlCommand(bad); !strings.HasPrefix(got, "error") {
			t.Fatalf("%q: expected an error, got %q", bad, got)
		}
	}
}

func TestControlUnixSocket(t *testing.T) {
	resetControlState(t)
	seedCache(t, "firewalla.encipher.io.", dns.TypeA, 0, time.Now().Add(time.Hour))

	path := socketPath(t)
	// a socket left behind by a process that is gone must not prevent the bind
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()

	if err := (&Proxy{}).startControl(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode %o, want 600", perm)
	}
	if reply, err := sendControlCommand(path, "flush firewalla.encipher.io"); err != nil || reply != "ok 1" {
		t.Fatalf("got %q, %v", reply, err)
	}

	// never remove something that is not a socket
	file := socketPath(t)
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&Proxy{}).startControl(file); err == nil {
		t.Fatal("expected an error for a regular file")
	}
	if _, err := os.Stat(file); err != nil {
		t.Fatal("regular file was removed")
	}
}

func TestControlOnlyUnixSockets(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9054", "0.0.0.0:0", "[::1]:9054", "relative/c.sock"} {
		if err := (&Proxy{}).startControl(address); err == nil {
			t.Fatalf("%q: expected an error, the control channel is a unix socket only", address)
		}
	}
}

func TestControlLiveSocketIsNotTakenOver(t *testing.T) {
	resetControlState(t)
	path := socketPath(t)
	if err := (&Proxy{}).startControl(path); err != nil {
		t.Fatal(err)
	}
	if err := (&Proxy{}).startControl(path); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("a second instance on a live socket: got %v", err)
	}
	if reply, err := sendControlCommand(path, "flush example.com"); err != nil || reply != "ok 0" {
		t.Fatalf("the first instance must keep the socket: got %q, %v", reply, err)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestControlLineLimit(t *testing.T) {
	huge := &countingReader{r: strings.NewReader("flush " + strings.Repeat("a", 4<<20) + "\n")}
	if _, err := readControlLine(huge); err != errControlLineTooLong {
		t.Fatalf("got %v, want errControlLineTooLong", err)
	}
	if huge.n > controlMaxLine+1 {
		t.Fatalf("read %d bytes of an over-long line, want at most %d", huge.n, controlMaxLine+1)
	}
	exact := "flush " + strings.Repeat("a", controlMaxLine-len("flush ")-1) + "\n"
	if line, err := readControlLine(strings.NewReader(exact)); err != nil || line != strings.TrimSpace(exact) {
		t.Fatalf("a line of exactly %d bytes: got %q, %v", controlMaxLine, line, err)
	}

	resetControlState(t)
	path := socketPath(t)
	if err := (&Proxy{}).startControl(path); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go fmt.Fprintf(conn, "flush %s\n", strings.Repeat("a", 1<<20))
	reply, _ := bufio.NewReader(conn).ReadString('\n')
	if reply != "error line too long\n" {
		t.Fatalf("got %q", reply)
	}
}

func TestControlConnectionCap(t *testing.T) {
	resetControlState(t)
	path := socketPath(t)
	if err := (&Proxy{}).startControl(path); err != nil {
		t.Fatal(err)
	}

	// idle connections hold every slot until their deadline
	var idle []net.Conn
	for range controlMaxConns {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	time.Sleep(100 * time.Millisecond)

	extra, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = extra.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("a connection over the cap should be closed at once, got %v", err)
	}
	extra.Close()

	for _, c := range idle {
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	if reply, err := sendControlCommand(path, "flush example.com"); err != nil || reply != "ok 0" {
		t.Fatalf("slots must be released: got %q, %v", reply, err)
	}
}

func seedStaleAnswer(qname string) *dns.Msg {
	answer := new(dns.Msg)
	answer.Rcode = dns.RcodeSuccess
	answer.Answer = []dns.RR{&dns.A{
		Hdr: dns.Header{Name: qname, Class: dns.ClassINET, TTL: 12},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}}
	cachedResponses.Insert(cacheKey(dns.TypeA, dns.ClassINET, 0, qname),
		CachedResponse{expiration: time.Now().Add(-time.Minute), msg: answer})
	return answer
}

func newRequestState(start time.Time) *PluginsState {
	return &PluginsState{requestStart: start, sessionData: map[string]any{}, cacheMinTTL: 2400, cacheMaxTTL: 86400, cacheNegMinTTL: 60, cacheNegMaxTTL: 600}
}

// staleFallback runs the cache plugin for a request starting now and returns
// the stale entry it keeps as the fallback for an upstream failure
func staleFallback(t *testing.T, qname string) (*PluginsState, *dns.Msg) {
	t.Helper()
	state := newRequestState(time.Now())
	if err := new(PluginCache).Eval(state, dns.NewMsg(qname, dns.TypeA)); err != nil {
		t.Fatal(err)
	}
	stale, ok := state.sessionData["stale"].(*dns.Msg)
	if !ok {
		t.Fatal("expected the cache plugin to keep a stale fallback")
	}
	return state, stale
}

// A request that found a stale entry before the flush serves it when the
// upstream fails; the response plugins must not write it back as fresh.
func TestFlushFenceStopsInFlightRewrite(t *testing.T) {
	resetControlState(t)
	const qname = "firewalla.encipher.io."
	answer := seedStaleAnswer(qname)

	// the in-flight request: the cache plugin hands it the stale entry
	inFlight, stale := staleFallback(t, qname)

	time.Sleep(time.Millisecond)
	if got := runControlCommand("flush " + qname); got != "ok 1" {
		t.Fatalf("flush: got %q", got)
	}

	// the upstream fails and the stale fallback goes through the response plugins
	if err := new(PluginCacheResponse).Eval(inFlight, stale); err != nil {
		t.Fatal(err)
	}
	if cached(qname, dns.TypeA, 0) {
		t.Fatal("a request that started before the flush wrote the stale answer back")
	}

	// a request that starts after the flush caches its answer as usual
	time.Sleep(time.Millisecond)
	fresh := dns.NewMsg(qname, dns.TypeA)
	fresh.Response = true
	fresh.Answer = answer.Answer
	if err := new(PluginCacheResponse).Eval(newRequestState(time.Now()), fresh); err != nil {
		t.Fatal(err)
	}
	if !cached(qname, dns.TypeA, 0) {
		t.Fatal("a request that started after the flush must be cached")
	}
}

func TestFlushFencesExpire(t *testing.T) {
	resetControlState(t)
	a := cacheKey(dns.TypeA, dns.ClassINET, 0, "a.example.")
	b := cacheKey(dns.TypeA, dns.ClassINET, 0, "b.example.")
	old := time.Now().Add(-2 * flushFenceTTL)
	flushGuard.flushedAt = map[[32]byte]time.Time{a: old}
	flushGuard.flush([][32]byte{b})
	if !flushGuard.insert(a, old.Add(-time.Second), CachedResponse{msg: new(dns.Msg)}) {
		t.Fatal("a fence older than flushFenceTTL must be dropped")
	}
	if n := len(flushGuard.flushedAt); n != 1 {
		t.Fatalf("%d fences left, want 1", n)
	}
}

// The fence check and the insert must not be split by a flush: a writer that
// passed the check before the flush must have its entry removed by it.
func TestFlushWaitsForInFlightInsert(t *testing.T) {
	resetControlState(t)
	const qname = "firewalla.encipher.io."
	key := cacheKey(dns.TypeA, dns.ClassINET, 0, qname)

	checked := make(chan struct{})
	resume := make(chan struct{})
	testHookBeforeCacheInsert = func() {
		close(checked)
		<-resume
	}
	defer func() { testHookBeforeCacheInsert = nil }()

	// a request that started before the flush, paused between check and insert
	inserted := make(chan bool)
	go func() {
		inserted <- flushGuard.insert(key, time.Now(), CachedResponse{expiration: time.Now().Add(time.Hour), msg: new(dns.Msg)})
	}()
	<-checked
	testHookBeforeCacheInsert = nil

	flushed := make(chan string)
	go func() { flushed <- runControlCommand("flush " + qname) }()
	select {
	case reply := <-flushed:
		t.Fatalf("flush completed (%q) while a writer was between its check and its insert", reply)
	case <-time.After(100 * time.Millisecond):
	}

	close(resume)
	if !<-inserted {
		t.Fatal("the writer passed its check, it should have inserted")
	}
	if reply := <-flushed; reply != "ok 1" {
		t.Fatalf("flush: got %q, want it to remove the entry the writer stored", reply)
	}
	if cached(qname, dns.TypeA, 0) {
		t.Fatal("the entry stored by the in-flight writer survived the flush")
	}
}

// A request that starts while a flush waits for the lock, and reads the entry
// before the flush removes it, must not be able to cache it again afterwards.
func TestFlushFencesRequestsStartedWhileFlushWaits(t *testing.T) {
	resetControlState(t)
	const qname = "firewalla.encipher.io."
	seedStaleAnswer(qname)

	// another store holds the read lock, so the flush has to wait
	checked := make(chan struct{})
	resume := make(chan struct{})
	testHookBeforeCacheInsert = func() {
		close(checked)
		<-resume
	}
	defer func() { testHookBeforeCacheInsert = nil }()
	holder := cacheKey(dns.TypeA, dns.ClassINET, 0, "holder.example.")
	held := make(chan bool)
	go func() { held <- flushGuard.insert(holder, time.Now(), CachedResponse{msg: new(dns.Msg)}) }()
	<-checked
	testHookBeforeCacheInsert = nil

	flushed := make(chan string)
	go func() { flushed <- runControlCommand("flush " + qname) }()
	time.Sleep(50 * time.Millisecond) // the flush is now waiting for the write lock

	// a request that starts during the wait still finds the stale entry
	waiting, stale := staleFallback(t, qname)

	close(resume)
	<-held
	if reply := <-flushed; reply != "ok 1" {
		t.Fatalf("flush: got %q", reply)
	}

	// its upstream fails and it serves the stale fallback
	if err := new(PluginCacheResponse).Eval(waiting, stale); err != nil {
		t.Fatal(err)
	}
	if cached(qname, dns.TypeA, 0) {
		t.Fatal("a request that read the entry while the flush waited wrote it back")
	}
}

func TestControlFlushClient(t *testing.T) {
	resetControlState(t)
	seedCache(t, "example.com.", dns.TypeA, 0, time.Now().Add(time.Hour))
	seedCache(t, "example.com.", dns.TypeAAAA, 0, time.Now().Add(time.Hour))

	path := socketPath(t)
	if err := (&Proxy{}).startControl(path); err != nil {
		t.Fatal(err)
	}
	if code := Flush(path, "example.com,AAAA"); code != 0 {
		t.Fatalf("flush with a type: exit %d", code)
	}
	if cached("example.com.", dns.TypeAAAA, 0) || !cached("example.com.", dns.TypeA, 0) {
		t.Fatal("<name>,<type> did not flush exactly that type")
	}
	if code := Flush(path, "example.com"); code != 0 || cached("example.com.", dns.TypeA, 0) {
		t.Fatalf("flush: exit %d", code)
	}
	if code := Flush(path, "example.com,BOGUS"); code != 1 {
		t.Fatalf("an error reply must exit 1, got %d", code)
	}
	if code := Flush("", "example.com"); code != 1 {
		t.Fatalf("no control socket must exit 1, got %d", code)
	}
	if code := Flush(socketPath(t), "example.com"); code != 1 {
		t.Fatalf("an unreachable proxy must exit 1, got %d", code)
	}
}

func TestControlSocketDefault(t *testing.T) {
	cfg := newConfig()
	if cfg.ControlSocket != DefaultControlSocket {
		t.Fatalf("default control_socket %q, want %q", cfg.ControlSocket, DefaultControlSocket)
	}
	// a config without the key keeps the default, an empty value turns it off
	if _, err := toml.Decode("cache = true\n", &cfg); err != nil || cfg.ControlSocket != DefaultControlSocket {
		t.Fatalf("without the key: %q, %v", cfg.ControlSocket, err)
	}
	if _, err := toml.Decode("control_socket = ''\n", &cfg); err != nil || cfg.ControlSocket != "" {
		t.Fatalf("control_socket = '': %q, %v", cfg.ControlSocket, err)
	}
	// a missing directory is reported as such, so the default can be skipped quietly
	err := (&Proxy{}).startControl(t.TempDir() + "/missing/c.sock")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing directory: got %v", err)
	}
}
