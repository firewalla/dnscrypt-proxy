package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/jedisct1/dlog"
	"github.com/redis/go-redis/v9"
)

const (
	// How long a resolved mark is reused before it is looked up again. Kept in
	// step with the interval the unbound build on the same device uses, so both
	// resolvers notice a VPN client coming back up at the same rate.
	fwmarkRefreshInterval = 5 * time.Second
	// A lookup runs on the dial path, so it must not stall a query for long.
	fwmarkLookupTimeout = 500 * time.Millisecond
	fwmarkRedisAddr     = "127.0.0.1:6379"
	// The key holding the name of the key that holds the mark. Fixed rather
	// than configurable, the way the unbound build on the same device fixes
	// its own: the config file then says nothing about the VPN client at all,
	// so selecting one, switching between them or turning one off never
	// rewrites the config and never restarts the proxy.
	fwmarkRedisKey = "dnscrypt:markkey"
)

// errNoFWMarkKey reports that it could not be established that a mark was asked
// for - either nothing requested one, or the request itself was unreadable. In
// neither case is anything known to be wrong, and having no mark is the normal
// state wherever no VPN client is selected, so it is not worth a warning.
// A mark that was definitely requested and could not be resolved is.
var errNoFWMarkKey = errors.New("no outgoing fwmark is configured")

// A keyReader reads a single string value by key, reporting an unset key as an
// empty value rather than an error. Backed by Redis at run time.
type keyReader interface {
	get(ctx context.Context, key string) (string, error)
	Close() error
}

type redisKeyReader struct {
	client *redis.Client
}

// redisLogger routes the client's own diagnostics into dlog. Left alone it
// writes them straight to stderr, bypassing the proxy's logging: on a host
// with no Redis at all that is a steady trickle of connection failures on a
// path which is meant to stay quiet.
type redisLogger struct{}

func (redisLogger) Printf(_ context.Context, format string, v ...interface{}) {
	dlog.Debugf(format, v...)
}

var redisLoggerOnce sync.Once

func newRedisKeyReader(addr string) *redisKeyReader {
	redisLoggerOnce.Do(func() { redis.SetLogger(redisLogger{}) })
	return &redisKeyReader{
		client: redis.NewClient(&redis.Options{
			Addr:         addr,
			DialTimeout:  fwmarkLookupTimeout,
			ReadTimeout:  fwmarkLookupTimeout,
			WriteTimeout: fwmarkLookupTimeout,
			// Retrying only spends the lookup budget over and over when there
			// is nothing listening, and the next dial will try again anyway.
			MaxRetries: -1,
		}),
	}
}

func (r *redisKeyReader) get(ctx context.Context, key string) (string, error) {
	value, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return value, err
}

func (r *redisKeyReader) Close() error { return r.client.Close() }

// A fwmarkResolver yields the mark to set on outgoing DoH sockets, read at dial
// time rather than at startup so that a VPN client which is restarted (and
// comes back with a different routing table id) is picked up without
// restarting the proxy.
//
// The lookup is deliberately indirect, matching what the device's unbound build
// does: the configured key holds the *name* of the key that holds the mark. The
// owner of the route publishes the mark under its own stable key and only has
// to point the indirection at it once.
//
// A mark that cannot be resolved is not an error: the socket is left unmarked
// and the query follows the default route, which is how the unbound build on
// the same device behaves for the same setting. Both services therefore make
// the same choice between the VPN client and the WAN, and what happens when
// the route is unavailable is left to the killSwitch handling above them.
type fwmarkResolver struct {
	reader keyReader
	key    string
	// now is time.Now except in tests.
	now func() time.Time

	mu      sync.RWMutex
	cached  uint32
	fetched time.Time
}

func newFWMarkResolverWithReader(reader keyReader, key string) *fwmarkResolver {
	return &fwmarkResolver{reader: reader, key: key, now: time.Now}
}

func newFWMarkResolver() *fwmarkResolver {
	return newFWMarkResolverWithReader(newRedisKeyReader(fwmarkRedisAddr), fwmarkRedisKey)
}

func (r *fwmarkResolver) fresh() bool {
	return !r.fetched.IsZero() && r.now().Sub(r.fetched) < fwmarkRefreshInterval
}

// fwmark returns the mark to set on outgoing sockets, or 0 when none could be
// resolved, in which case the socket is left unmarked.
func (r *fwmarkResolver) fwmark() uint32 {
	r.mu.RLock()
	if r.fresh() {
		mark := r.cached
		r.mu.RUnlock()
		return mark
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	// Another dial may have refreshed while this one waited for the lock.
	if r.fresh() {
		return r.cached
	}
	// A failure is cached like a success: an unreachable Redis would otherwise
	// be hit once per dial, and the mark is unknown either way.
	mark, err := r.lookup()
	if err != nil {
		mark = 0
	}
	// Only report a change, so that a mark which stays unresolvable does not
	// log once per refresh for as long as the proxy runs.
	if first := r.fetched.IsZero(); first || mark != r.cached {
		switch {
		case errors.Is(err, errNoFWMarkKey):
			// The steady state whenever no VPN client is selected.
			dlog.Debugf("DoH queries are not marked: %v", err)
		case mark == 0:
			dlog.Warnf("No fwmark for DoH queries, they will follow the default route: %v", err)
		case first:
			dlog.Noticef("DoH queries are marked %d", mark)
		default:
			dlog.Noticef("The fwmark for DoH queries changed from %d to %d", r.cached, mark)
		}
	}
	r.cached = mark
	r.fetched = r.now()
	return mark
}

func (r *fwmarkResolver) lookup() (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fwmarkLookupTimeout)
	defer cancel()

	markKey, err := r.reader.get(ctx, r.key)
	if err != nil {
		// Whether a mark was even asked for is now unknown, so this is not
		// reported as a problem: a host with no Redis simply marks nothing.
		return 0, fmt.Errorf("unable to read [%s]: %w: %w", r.key, err, errNoFWMarkKey)
	}
	if len(markKey) == 0 {
		return 0, fmt.Errorf("[%s] is not set: %w", r.key, errNoFWMarkKey)
	}

	value, err := r.reader.get(ctx, markKey)
	if err != nil {
		return 0, fmt.Errorf("unable to read the fwmark from [%s]: %w", markKey, err)
	}
	if len(value) == 0 {
		return 0, fmt.Errorf("fwmark key [%s] points at [%s], which is not set", r.key, markKey)
	}

	// Parsed as 31 bits, not the 32 the kernel's u32 would allow: the mark ends
	// up in unix.SetsockoptInt, whose argument is a signed int, so a mark with
	// the high bit set would only arrive intact by relying on that package
	// truncating it back to an int32. Route marks are routing table ids and do
	// not come near the limit - the ones this reads are id<<10 for id < 64 -
	// so the range that is given up is one nothing publishes.
	mark, err := strconv.ParseUint(value, 10, 31)
	if err != nil {
		return 0, fmt.Errorf("[%s] does not hold a usable fwmark: %w", markKey, err)
	}
	if mark == 0 {
		// Mark 0 is what an unmarked socket already carries, so it cannot
		// select a routing rule; treating it as valid would silently send the
		// query over the default route.
		return 0, fmt.Errorf("[%s] holds 0, which is not a usable fwmark", markKey)
	}
	return uint32(mark), nil
}

func (r *fwmarkResolver) Close() error { return r.reader.Close() }
