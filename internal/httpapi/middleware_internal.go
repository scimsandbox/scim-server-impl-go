package httpapi

import (
	"container/list"
	"context"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/messages"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
	"golang.org/x/time/rate"
)

const (
	defaultRateLimitWaitTimeout    = time.Duration(0)
	maxRateLimitWaitTimeout        = 5 * time.Second
	maxConcurrentRateLimitWaits    = 64
	maxDefaultRateLimitBurst       = 1000
	defaultPerKeyRequestsPerSecond = 250.0
	defaultPerKeyMaxBurst          = 50
	defaultMaxRateLimitBuckets     = 4096
	defaultRateLimitShards         = 32
	defaultRateLimitBucketTTL      = 10 * time.Minute
	maxExpiredEvictPerAccess       = 4
	rateLimitRetryAfterSeconds     = 1
	rateLimitScimType              = "tooMany"
	rateLimitCapacityDetail        = "Rate limit exceeded. Try again later."
)

type statusCapture struct {
	http.ResponseWriter
	statusCode int
}

type requestLimiter interface {
	Allow() bool
	Wait(context.Context) error
}

type limiterProvider interface {
	LimiterFor(*http.Request) requestLimiter
}

type limiterEntry struct {
	key      string
	limiter  *rate.Limiter
	lastSeen time.Time
}

type limiterShard struct {
	mu         sync.Mutex
	entries    map[string]*list.Element
	lru        *list.List
	maxEntries int
}

type keyedLimiterStore struct {
	shards    []limiterShard
	shardMask uint32
	limit     rate.Limit
	burst     int
	ttl       time.Duration
	now       func() time.Time
}

func (s *statusCapture) WriteHeader(code int) {
	s.statusCode = code
	s.ResponseWriter.WriteHeader(code)
}

func sanitizeRateLimit(requestsPerSecond float64) rate.Limit {
	if math.IsNaN(requestsPerSecond) || requestsPerSecond <= 0 {
		return 0
	}
	if math.IsInf(requestsPerSecond, 1) {
		return rate.Inf
	}
	return rate.Limit(requestsPerSecond)
}

func resolveRateLimitBurst(requestsPerSecond float64, burst int) int {
	if burst > 0 {
		return burst
	}
	if math.IsNaN(requestsPerSecond) || requestsPerSecond <= 1 {
		return 1
	}
	if math.IsInf(requestsPerSecond, 1) || requestsPerSecond >= float64(maxDefaultRateLimitBurst) {
		return maxDefaultRateLimitBurst
	}
	return int(math.Ceil(requestsPerSecond))
}

func resolveSubRateLimit(globalRPS float64, globalBurst int, subRPS float64, subBurst int) (float64, int) {
	resolvedGlobalBurst := resolveRateLimitBurst(globalRPS, globalBurst)

	hasExplicitSubRPS := !math.IsNaN(subRPS) && !math.IsInf(subRPS, -1) && subRPS > 0
	var effectiveRPS float64
	switch {
	case hasExplicitSubRPS:
		effectiveRPS = subRPS
	case !math.IsNaN(globalRPS) && globalRPS > 0 && globalRPS < defaultPerKeyRequestsPerSecond:
		effectiveRPS = globalRPS
	default:
		effectiveRPS = defaultPerKeyRequestsPerSecond
	}

	var effectiveBurst int
	switch {
	case subBurst > 0:
		effectiveBurst = subBurst
	case hasExplicitSubRPS:
		effectiveBurst = resolveRateLimitBurst(effectiveRPS, 0)
	default:
		effectiveBurst = resolvedGlobalBurst
		if effectiveBurst > defaultPerKeyMaxBurst {
			effectiveBurst = defaultPerKeyMaxBurst
		}
		if effectiveBurst < 1 {
			effectiveBurst = 1
		}
	}

	return effectiveRPS, effectiveBurst
}

// ParseTrustedProxies parses a comma-separated list of IP addresses or CIDR ranges.
// An empty string returns nil, meaning default loopback/private/link-local peers are trusted.
func ParseTrustedProxies(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			pfx, err := netip.ParsePrefix(item)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", item, err)
			}
			addr := pfx.Addr()
			if addr.Is4In6() && pfx.Bits() >= 96 {
				unmapped := addr.Unmap()
				prefixes = append(prefixes, netip.PrefixFrom(unmapped, pfx.Bits()-96).Masked())
			} else {
				prefixes = append(prefixes, pfx.Masked())
			}
			continue
		}

		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy IP %q: %w", item, err)
		}
		addr = addr.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return prefixes, nil
}

func isTrustedProxyPeer(peerAddr netip.Addr, trustedProxies []netip.Prefix) bool {
	if !peerAddr.IsValid() {
		return false
	}
	peerAddr = peerAddr.Unmap()
	if len(trustedProxies) > 0 {
		for _, pfx := range trustedProxies {
			if pfx.Contains(peerAddr) {
				return true
			}
		}
		return false
	}
	return peerAddr.IsLoopback() || peerAddr.IsPrivate() || peerAddr.IsLinkLocalUnicast()
}

func parseHeaderAddr(raw string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return netip.Addr{}, false
	}
	hostNoZone, _, _ := strings.Cut(trimmed, "%")
	addr, err := netip.ParseAddr(hostNoZone)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func extractClientIPKey(r *http.Request, trustedProxies []netip.Prefix) string {
	if r == nil {
		return "global"
	}
	addr := strings.TrimSpace(r.RemoteAddr)
	if addr == "" {
		return "global"
	}

	rawHost := addr
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		rawHost = host
	}

	peerAddr, ok := parseHeaderAddr(rawHost)
	if !ok {
		return "ip:" + rawHost
	}

	if isTrustedProxyPeer(peerAddr, trustedProxies) {
		cfValues := r.Header.Values("CF-Connecting-IP")
		if len(cfValues) == 1 && !strings.Contains(cfValues[0], ",") {
			if cfAddr, valid := parseHeaderAddr(cfValues[0]); valid {
				return "ip:" + cfAddr.String()
			}
		}

		xffValues := r.Header.Values("X-Forwarded-For")
		if len(xffValues) > 0 {
			lastHeader := xffValues[len(xffValues)-1]
			lastHop := lastHeader
			if idx := strings.LastIndexByte(lastHeader, ','); idx >= 0 {
				lastHop = lastHeader[idx+1:]
			}
			if xffAddr, valid := parseHeaderAddr(lastHop); valid {
				return "ip:" + xffAddr.String()
			}
		}
	}

	return "ip:" + peerAddr.String()
}

func newKeyedLimiterStore(requestsPerSecond float64, burst int) *keyedLimiterStore {
	return newKeyedLimiterStoreWithOptions(
		requestsPerSecond,
		burst,
		defaultMaxRateLimitBuckets,
		defaultRateLimitBucketTTL,
		time.Now,
	)
}

func newKeyedLimiterStoreWithOptions(
	requestsPerSecond float64,
	burst int,
	maxEntries int,
	ttl time.Duration,
	nowFn func() time.Time,
) *keyedLimiterStore {
	if maxEntries <= 0 {
		maxEntries = defaultMaxRateLimitBuckets
	}

	numShards := 1
	if maxEntries >= defaultRateLimitShards {
		numShards = defaultRateLimitShards
	}

	shards := make([]limiterShard, numShards)
	baseCap := maxEntries / numShards
	rem := maxEntries % numShards
	for i := range shards {
		shardCap := baseCap
		if i < rem {
			shardCap++
		}
		shards[i] = limiterShard{
			entries:    make(map[string]*list.Element),
			lru:        list.New(),
			maxEntries: shardCap,
		}
	}

	return &keyedLimiterStore{
		shards:    shards,
		shardMask: uint32(numShards - 1),
		limit:     sanitizeRateLimit(requestsPerSecond),
		burst:     resolveRateLimitBurst(requestsPerSecond, burst),
		ttl:       ttl,
		now:       nowFn,
	}
}

func fnv32a(s string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}

func (s *keyedLimiterStore) shardFor(key string) *limiterShard {
	if len(s.shards) == 1 {
		return &s.shards[0]
	}
	return &s.shards[fnv32a(key)&s.shardMask]
}

func (sh *limiterShard) removeElementLocked(elem *list.Element) {
	entry := sh.lru.Remove(elem).(*limiterEntry)
	delete(sh.entries, entry.key)
}

func (s *keyedLimiterStore) LimiterFor(r *http.Request) requestLimiter {
	return s.LimiterForKey(extractClientIPKey(r, nil))
}

func (s *keyedLimiterStore) LimiterForKey(key string) requestLimiter {
	shard := s.shardFor(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	now := s.now()

	for i := 0; i < maxExpiredEvictPerAccess; i++ {
		front := shard.lru.Front()
		if front == nil {
			break
		}
		fe := front.Value.(*limiterEntry)
		if now.Sub(fe.lastSeen) < s.ttl {
			break
		}
		shard.removeElementLocked(front)
	}

	if elem, ok := shard.entries[key]; ok {
		entry := elem.Value.(*limiterEntry)
		if now.Sub(entry.lastSeen) < s.ttl {
			entry.lastSeen = now
			shard.lru.MoveToBack(elem)
			return entry.limiter
		}
		shard.removeElementLocked(elem)
	}

	if len(shard.entries) >= shard.maxEntries {
		if front := shard.lru.Front(); front != nil {
			shard.removeElementLocked(front)
		}
	}

	lim := rate.NewLimiter(s.limit, s.burst)
	elem := shard.lru.PushBack(&limiterEntry{
		key:      key,
		limiter:  lim,
		lastSeen: now,
	})
	shard.entries[key] = elem
	return lim
}

func (s *keyedLimiterStore) lenEntries() int {
	total := 0
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		total += len(sh.entries)
		sh.mu.Unlock()
	}
	return total
}

func (s *keyedLimiterStore) hasKey(key string) bool {
	sh := s.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	_, ok := sh.entries[key]
	return ok
}

func resolveRateLimitWaitTimeout(waitTimeout time.Duration) time.Duration {
	if waitTimeout <= 0 {
		return defaultRateLimitWaitTimeout
	}
	if waitTimeout > maxRateLimitWaitTimeout {
		return maxRateLimitWaitTimeout
	}
	return waitTimeout
}

func writeRateLimitExceeded(w http.ResponseWriter, r *http.Request) {
	middleware.MarkThrottled(r, middleware.ThrottledYes)
	w.Header().Set("Retry-After", strconv.Itoa(rateLimitRetryAfterSeconds))
	scim.WriteScimError(w, scim.NewScimError(http.StatusTooManyRequests, rateLimitScimType, rateLimitCapacityDetail))
}

func acquireLimiters(
	r *http.Request,
	waitTimeout time.Duration,
	waitSem chan struct{},
	limiters ...requestLimiter,
) (allowed bool, canceled bool) {
	if r.Context().Err() != nil {
		return false, true
	}

	firstBlocked := -1
	for i, lim := range limiters {
		if !lim.Allow() {
			firstBlocked = i
			break
		}
	}
	if firstBlocked == -1 {
		return true, false
	}

	if waitTimeout <= 0 {
		return false, false
	}

	select {
	case waitSem <- struct{}{}:
		defer func() { <-waitSem }()
	default:
		return false, false
	}

	waitCtx, cancel := context.WithTimeout(r.Context(), waitTimeout)
	defer cancel()

	for i := firstBlocked; i < len(limiters); i++ {
		if i > firstBlocked && limiters[i].Allow() {
			continue
		}
		if err := limiters[i].Wait(waitCtx); err != nil {
			if r.Context().Err() != nil {
				return false, true
			}
			return false, false
		}
	}

	return true, false
}

func preAuthThrottlingMiddleware(cfg RateLimitConfig, next http.Handler) http.Handler {
	globalBurst := resolveRateLimitBurst(cfg.RequestsPerSecond, cfg.Burst)
	globalLimiter := rate.NewLimiter(sanitizeRateLimit(cfg.RequestsPerSecond), globalBurst)

	ipRPS, ipBurst := resolveSubRateLimit(
		cfg.RequestsPerSecond,
		cfg.Burst,
		cfg.PerIPRequestsPerSecond,
		cfg.PerIPBurst,
	)
	ipStore := newKeyedLimiterStore(ipRPS, ipBurst)
	trustedProxies, _ := ParseTrustedProxies(cfg.TrustedProxies)
	waitTimeout := resolveRateLimitWaitTimeout(cfg.WaitTimeout)

	var waitSem chan struct{}
	if waitTimeout > 0 {
		waitSem = make(chan struct{}, maxConcurrentRateLimitWaits)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.MarkThrottled(r, middleware.ThrottledNo)
		ipLimiter := ipStore.LimiterForKey(extractClientIPKey(r, trustedProxies))
		allowed, canceled := acquireLimiters(r, waitTimeout, waitSem, ipLimiter, globalLimiter)
		if canceled {
			return
		}
		if !allowed {
			writeRateLimitExceeded(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func throttlingMiddleware(provider limiterProvider, waitTimeout time.Duration, next http.Handler) http.Handler {
	var waitSem chan struct{}
	if waitTimeout > 0 {
		waitSem = make(chan struct{}, maxConcurrentRateLimitWaits)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.MarkThrottled(r, middleware.ThrottledNo)
		allowed, canceled := acquireLimiters(r, waitTimeout, waitSem, provider.LimiterFor(r))
		if canceled {
			return
		}
		if !allowed {
			writeRateLimitExceeded(w, r)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func requestLoggingMiddleware(logger logging.Logger, localizer messages.Localizer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		capture := &statusCapture{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(capture, r)

		duration := time.Since(start)

		logger.Info(localizer.Text(messages.KeyHTTPRequestCompleted),
			logging.String("method", r.Method),
			logging.String("path", r.URL.RequestURI()),
			logging.Int("status", capture.statusCode),
			logging.Duration("duration", duration),
		)
	})
}
