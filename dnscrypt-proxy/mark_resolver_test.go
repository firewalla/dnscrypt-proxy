package main

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeKeyReader stands in for Redis, counting reads so that the refresh
// throttle can be observed.
type fakeKeyReader struct {
	mu     sync.Mutex
	values map[string]string
	err    error
	reads  int
	closed bool
}

func newFakeKeyReader(values map[string]string) *fakeKeyReader {
	if values == nil {
		values = map[string]string{}
	}
	return &fakeKeyReader{values: values}
}

func (f *fakeKeyReader) get(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	if f.err != nil {
		return "", f.err
	}
	return f.values[key], nil
}

func (f *fakeKeyReader) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeKeyReader) set(key, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[key] = value
}

func (f *fakeKeyReader) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeKeyReader) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reads
}

// newTestFWMark builds a resolver whose clock the test drives.
func newTestFWMark(reader keyReader, key string, clock *time.Time) *fwmarkResolver {
	resolver := newFWMarkResolverWithReader(reader, key)
	resolver.now = func() time.Time { return *clock }
	return resolver
}

// resolverFor yields a resolver that resolves to mark.
func resolverFor(mark uint32) *fwmarkResolver {
	return newFWMarkResolverWithReader(newFakeKeyReader(map[string]string{
		fwmarkRedisKey:        "fwmark:vpn:profile1",
		"fwmark:vpn:profile1": strconv.FormatUint(uint64(mark), 10),
	}), fwmarkRedisKey)
}

// unresolvableFWMark yields a resolver whose mark cannot be resolved, the way
// the real one behaves when the VPN client that owns it is not up.
func unresolvableFWMark() *fwmarkResolver {
	return newFWMarkResolverWithReader(newFakeKeyReader(nil), fwmarkRedisKey)
}

func TestFWMarkResolverFollowsTheIndirection(t *testing.T) {
	reader := newFakeKeyReader(map[string]string{
		fwmarkRedisKey:        "fwmark:vpn:profile1",
		"fwmark:vpn:profile1": "4098",
	})
	clock := time.Now()
	resolver := newTestFWMark(reader, fwmarkRedisKey, &clock)

	if mark := resolver.fwmark(); mark != 4098 {
		t.Fatalf("expected mark 4098, got %d", mark)
	}
}

func TestFWMarkResolverCachesWithinTheRefreshInterval(t *testing.T) {
	reader := newFakeKeyReader(map[string]string{
		fwmarkRedisKey:        "fwmark:vpn:profile1",
		"fwmark:vpn:profile1": "4098",
	})
	clock := time.Now()
	resolver := newTestFWMark(reader, fwmarkRedisKey, &clock)

	resolver.fwmark()
	readsAfterFirst := reader.readCount()

	// A new routing table id, not yet visible: the cached mark is still fresh.
	reader.set("fwmark:vpn:profile1", "4099")
	clock = clock.Add(fwmarkRefreshInterval - time.Millisecond)
	mark := resolver.fwmark()
	if mark != 4098 {
		t.Fatalf("expected the cached mark 4098, got %d", mark)
	}
	if reader.readCount() != readsAfterFirst {
		t.Fatalf("expected no further reads while the mark is fresh, got %d", reader.readCount()-readsAfterFirst)
	}

	// Past the interval the new id is picked up without a restart.
	clock = clock.Add(2 * time.Millisecond)
	if mark = resolver.fwmark(); mark != 4099 {
		t.Fatalf("expected the refreshed mark 4099, got %d", mark)
	}
}

func TestFWMarkResolverFallsBackToTheDefaultRoute(t *testing.T) {
	for _, tt := range []struct {
		name   string
		values map[string]string
		err    error
	}{
		{name: "indirection unset", values: map[string]string{}},
		{
			name:   "target unset",
			values: map[string]string{fwmarkRedisKey: "fwmark:vpn:profile1"},
		},
		{
			name: "target not a number",
			values: map[string]string{
				fwmarkRedisKey:        "fwmark:vpn:profile1",
				"fwmark:vpn:profile1": "not-a-mark",
			},
		},
		{
			name: "target is zero",
			values: map[string]string{
				fwmarkRedisKey:        "fwmark:vpn:profile1",
				"fwmark:vpn:profile1": "0",
			},
		},
		{name: "backend unreachable", values: map[string]string{}, err: errors.New("connection refused")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reader := newFakeKeyReader(tt.values)
			if tt.err != nil {
				reader.fail(tt.err)
			}
			clock := time.Now()
			resolver := newTestFWMark(reader, fwmarkRedisKey, &clock)

			// Matching unbound: an unusable mark leaves the socket
			// unmarked rather than failing the query.
			if mark := resolver.fwmark(); mark != 0 {
				t.Fatalf("expected no mark, got %d", mark)
			}
		})
	}
}

func TestFWMarkResolverCachesFailures(t *testing.T) {
	reader := newFakeKeyReader(map[string]string{})
	reader.fail(errors.New("connection refused"))
	clock := time.Now()
	resolver := newTestFWMark(reader, fwmarkRedisKey, &clock)

	if mark := resolver.fwmark(); mark != 0 {
		t.Fatalf("expected no mark, got %d", mark)
	}
	reads := reader.readCount()
	if mark := resolver.fwmark(); mark != 0 {
		t.Fatalf("expected no mark, got %d", mark)
	}
	if reader.readCount() != reads {
		t.Fatalf("expected the failure to be cached, got %d extra reads", reader.readCount()-reads)
	}
}

func TestFWMarkResolverIsConcurrencySafe(t *testing.T) {
	reader := newFakeKeyReader(map[string]string{
		fwmarkRedisKey:        "fwmark:vpn:profile1",
		"fwmark:vpn:profile1": "4098",
	})
	resolver := newFWMarkResolverWithReader(reader, fwmarkRedisKey)

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if mark := resolver.fwmark(); mark != 4098 {
				t.Errorf("concurrent lookup returned %d", mark)
			}
		}()
	}
	wg.Wait()

	// Every dial racing at startup must not turn into one backend read each.
	if reads := reader.readCount(); reads > 2 {
		t.Fatalf("expected the refresh to be shared, got %d reads", reads)
	}
}

func TestFWMarkResolverCloseClosesTheReader(t *testing.T) {
	reader := newFakeKeyReader(map[string]string{})
	if err := newFWMarkResolverWithReader(reader, fwmarkRedisKey).Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reader.closed {
		t.Fatal("expected the reader to be closed")
	}
}

func TestFWMarkResolverDistinguishesUnconfiguredFromUnavailable(t *testing.T) {
	// No mark requested at all: the steady state when no VPN client is
	// selected, and not worth warning about.
	resolver := newFWMarkResolverWithReader(newFakeKeyReader(nil), fwmarkRedisKey)
	if _, err := resolver.lookup(); !errors.Is(err, errNoFWMarkKey) {
		t.Fatalf("expected errNoFWMarkKey when the indirection is unset, got: %v", err)
	}

	// The backend is unreachable, so whether a mark was requested cannot be
	// established either. That is the shape of a host with no Redis at all -
	// the CI suite runs one - and it has to stay as quiet as the case above.
	unreachable := newFakeKeyReader(nil)
	unreachable.fail(errors.New("connection refused"))
	resolver = newFWMarkResolverWithReader(unreachable, fwmarkRedisKey)
	if _, err := resolver.lookup(); !errors.Is(err, errNoFWMarkKey) {
		t.Fatalf("expected errNoFWMarkKey when the backend is unreachable, got: %v", err)
	}

	// A mark was requested but the client that owns it has published none.
	// That is a real problem and has to stay distinguishable.
	resolver = newFWMarkResolverWithReader(newFakeKeyReader(map[string]string{
		fwmarkRedisKey: "fwmark:vpn:profile1",
	}), fwmarkRedisKey)
	_, err := resolver.lookup()
	if err == nil {
		t.Fatal("expected an error when the mark itself is unset")
	}
	if errors.Is(err, errNoFWMarkKey) {
		t.Fatalf("an unavailable mark must not look unconfigured, got: %v", err)
	}
}

func TestFWMarkResolverAcceptsTheUsableMarkRange(t *testing.T) {
	// Route marks are routing table ids, far below the limit; the top of the
	// range is here to pin where the 31-bit bound actually falls.
	for _, mark := range []uint32{1, 1024, 4098, 64512, 0x40000000, 1<<31 - 1} {
		reader := newFakeKeyReader(map[string]string{
			fwmarkRedisKey:        "fwmark:vpn:profile1",
			"fwmark:vpn:profile1": strconv.FormatUint(uint64(mark), 10),
		})
		clock := time.Now()
		if got := newTestFWMark(reader, fwmarkRedisKey, &clock).fwmark(); got != mark {
			t.Fatalf("expected mark %d, got %d", mark, got)
		}
		// The mark is handed to SetsockoptInt as an int, so it has to be
		// representable there without changing value.
		if back := uint32(int(mark)); back != mark {
			t.Fatalf("mark %d does not survive the conversion to int, got %d", mark, back)
		}
	}
}

func TestFWMarkResolverRejectsUnusableMarks(t *testing.T) {
	// Above 31 bits a mark could not be passed to SetsockoptInt without
	// relying on it wrapping through a negative int, so it is refused rather
	// than sent as something else.
	for _, value := range []string{"2147483648", "4294967296", "-1", "1e5", " 4098"} {
		reader := newFakeKeyReader(map[string]string{
			fwmarkRedisKey:        "fwmark:vpn:profile1",
			"fwmark:vpn:profile1": value,
		})
		clock := time.Now()
		if got := newTestFWMark(reader, fwmarkRedisKey, &clock).fwmark(); got != 0 {
			t.Fatalf("expected [%s] to be rejected, got mark %d", value, got)
		}
	}
}
