package httpapi

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
	statusCode  int
	wroteHeader bool
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
	if !s.wroteHeader {
		s.statusCode = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusCapture) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusCapture) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusCapture) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
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
// An empty string returns nil, meaning no proxy peers are trusted (fail closed).
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
	if !peerAddr.IsValid() || len(trustedProxies) == 0 {
		return false
	}
	peerAddr = peerAddr.Unmap()
	for _, pfx := range trustedProxies {
		if pfx.Contains(peerAddr) {
			return true
		}
	}
	return false
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

func formatClientAddrKey(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is4() {
		return "ip:" + addr.String()
	}
	if addr.Is6() {
		pfx, _ := addr.Prefix(64)
		return "ip:" + pfx.String()
	}
	return "ip:" + addr.String()
}

func extractClientIPKey(r *http.Request, trustedProxies, trustedCloudflareProxies []netip.Prefix) string {
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

	cfTrusted := isTrustedProxyPeer(peerAddr, trustedCloudflareProxies)
	if cfTrusted {
		cfValues := r.Header.Values("CF-Connecting-IP")
		if len(cfValues) == 1 && !strings.Contains(cfValues[0], ",") {
			if cfAddr, valid := parseHeaderAddr(cfValues[0]); valid {
				return formatClientAddrKey(cfAddr)
			}
		}
	}

	if cfTrusted || isTrustedProxyPeer(peerAddr, trustedProxies) {
		xffValues := r.Header.Values("X-Forwarded-For")
		if len(xffValues) > 0 {
			var lastValidTrusted netip.Addr
			for hIdx := len(xffValues) - 1; hIdx >= 0; hIdx-- {
				hdr := xffValues[hIdx]
				for {
					commaIdx := strings.LastIndexByte(hdr, ',')
					var hop string
					if commaIdx >= 0 {
						hop = hdr[commaIdx+1:]
						hdr = hdr[:commaIdx]
					} else {
						hop = hdr
					}

					hopAddr, valid := parseHeaderAddr(hop)
					if !valid {
						if lastValidTrusted.IsValid() {
							return formatClientAddrKey(lastValidTrusted)
						}
						return formatClientAddrKey(peerAddr)
					}

					if !isTrustedProxyPeer(hopAddr, trustedProxies) && !isTrustedProxyPeer(hopAddr, trustedCloudflareProxies) {
						return formatClientAddrKey(hopAddr)
					}

					lastValidTrusted = hopAddr
					if commaIdx < 0 {
						break
					}
				}
			}
			if lastValidTrusted.IsValid() {
				return formatClientAddrKey(lastValidTrusted)
			}
		}
	}

	return formatClientAddrKey(peerAddr)
}

func extractSCIMWorkspaceUUID(urlPath string) (string, bool) {
	const (
		wsPrefix = "/ws/"
		scimSeg  = "/scim/v2"
	)
	if !strings.HasPrefix(urlPath, wsPrefix) {
		return "", false
	}
	rest := urlPath[len(wsPrefix):]
	slashIdx := strings.IndexByte(rest, '/')
	if slashIdx <= 0 {
		return "", false
	}
	seg := rest[:slashIdx]
	tail := rest[slashIdx:]
	if tail != scimSeg && !strings.HasPrefix(tail, scimSeg+"/") {
		return "", false
	}
	parsed, err := uuid.Parse(seg)
	if err != nil || parsed == uuid.Nil {
		return "", false
	}
	return parsed.String(), true
}

func extractBearerToken(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", false
	}
	rawToken := strings.TrimPrefix(authHeader, "Bearer ")
	if strings.TrimSpace(rawToken) == "" {
		return "", false
	}
	return rawToken, true
}

type verifiedBearerKey struct {
	ipKey     string
	wsID      string
	tokenHash [32]byte
}

type verifiedBearerEntry struct {
	key      verifiedBearerKey
	lastSeen time.Time
}

type verifiedBearerShard struct {
	mu         sync.Mutex
	entries    map[verifiedBearerKey]*list.Element
	lru        *list.List
	maxEntries int
}

type verifiedBearerCache struct {
	shards    []verifiedBearerShard
	shardMask uint32
	ttl       time.Duration
}

func newVerifiedBearerCache(maxEntries int, ttl time.Duration) *verifiedBearerCache {
	if maxEntries <= 0 {
		maxEntries = defaultMaxRateLimitBuckets
	}
	numShards := 1
	if maxEntries >= defaultRateLimitShards {
		numShards = defaultRateLimitShards
	}
	shards := make([]verifiedBearerShard, numShards)
	baseCap := maxEntries / numShards
	rem := maxEntries % numShards
	for i := range shards {
		shardCap := baseCap
		if i < rem {
			shardCap++
		}
		shards[i] = verifiedBearerShard{
			entries:    make(map[verifiedBearerKey]*list.Element),
			lru:        list.New(),
			maxEntries: shardCap,
		}
	}
	return &verifiedBearerCache{
		shards:    shards,
		shardMask: uint32(numShards - 1),
		ttl:       ttl,
	}
}

func (c *verifiedBearerCache) shardFor(key verifiedBearerKey) *verifiedBearerShard {
	if len(c.shards) == 1 {
		return &c.shards[0]
	}
	h := binary.LittleEndian.Uint32(key.tokenHash[:4]) ^ fnv32a(key.ipKey) ^ fnv32a(key.wsID)
	return &c.shards[h&c.shardMask]
}

func (sh *verifiedBearerShard) removeElementLocked(elem *list.Element) {
	entry := sh.lru.Remove(elem).(*verifiedBearerEntry)
	delete(sh.entries, entry.key)
}

func (sh *verifiedBearerShard) evictExpiredFrontLocked(now time.Time, ttl time.Duration) {
	for i := 0; i < maxExpiredEvictPerAccess; i++ {
		front := sh.lru.Front()
		if front == nil {
			break
		}
		fe := front.Value.(*verifiedBearerEntry)
		if now.Sub(fe.lastSeen) < ttl {
			break
		}
		sh.removeElementLocked(front)
	}
}

func (c *verifiedBearerCache) Contains(key verifiedBearerKey, now time.Time) bool {
	sh := c.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	sh.evictExpiredFrontLocked(now, c.ttl)

	elem, ok := sh.entries[key]
	if !ok {
		return false
	}
	entry := elem.Value.(*verifiedBearerEntry)
	if now.Sub(entry.lastSeen) >= c.ttl {
		sh.removeElementLocked(elem)
		return false
	}
	entry.lastSeen = now
	sh.lru.MoveToBack(elem)
	return true
}

func (c *verifiedBearerCache) Put(key verifiedBearerKey, now time.Time) {
	sh := c.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	sh.evictExpiredFrontLocked(now, c.ttl)

	if elem, ok := sh.entries[key]; ok {
		entry := elem.Value.(*verifiedBearerEntry)
		entry.lastSeen = now
		sh.lru.MoveToBack(elem)
		return
	}
	if len(sh.entries) >= sh.maxEntries {
		if front := sh.lru.Front(); front != nil {
			sh.removeElementLocked(front)
		}
	}
	elem := sh.lru.PushBack(&verifiedBearerEntry{
		key:      key,
		lastSeen: now,
	})
	sh.entries[key] = elem
}

func (c *verifiedBearerCache) Delete(key verifiedBearerKey) {
	sh := c.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if elem, ok := sh.entries[key]; ok {
		sh.removeElementLocked(elem)
	}
}

type preAuthVerifyCallbackKey struct{}

type preAuthVerifyHook struct {
	onAuthenticated func(authWSID uuid.UUID)
}

func notifyPreAuthTokenVerified(ctx context.Context, authWSID uuid.UUID) {
	if authWSID == uuid.Nil {
		return
	}
	if hook, ok := ctx.Value(preAuthVerifyCallbackKey{}).(preAuthVerifyHook); ok && hook.onAuthenticated != nil {
		hook.onAuthenticated(authWSID)
	}
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
	if nowFn == nil {
		nowFn = time.Now
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

func (s *keyedLimiterStore) LimiterForKey(key string) *rate.Limiter {
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

type limiterReservation struct {
	res   *rate.Reservation
	actAt time.Time
}

func acquireLimiters(
	r *http.Request,
	nowFn func() time.Time,
	waitTimeout time.Duration,
	waitSem chan struct{},
	limiters ...*rate.Limiter,
) (allowed bool, canceled bool) {
	return acquireLimitersWithHook(r, nowFn, waitTimeout, waitSem, nil, limiters...)
}

func acquireLimitersWithHook(
	r *http.Request,
	nowFn func() time.Time,
	waitTimeout time.Duration,
	waitSem chan struct{},
	onWaitStart func(),
	limiters ...*rate.Limiter,
) (allowed bool, canceled bool) {
	if r.Context().Err() != nil {
		return false, true
	}
	if len(limiters) == 0 {
		return true, false
	}

	now := nowFn()
	var stackRes [2]limiterReservation
	reservations := stackRes[:0]

	allOK := true
	var maxDelay time.Duration
	for _, lim := range limiters {
		res := lim.ReserveN(now, 1)
		if !res.OK() {
			reservations = append(reservations, limiterReservation{res: res})
			allOK = false
			continue
		}
		d := res.DelayFrom(now)
		reservations = append(reservations, limiterReservation{
			res:   res,
			actAt: now.Add(d),
		})
		if d > maxDelay {
			maxDelay = d
		}
	}

	cancelAll := func(cancelTime time.Time) {
		for _, lr := range reservations {
			if !lr.res.OK() {
				continue
			}
			at := cancelTime
			if lr.actAt.Before(cancelTime) {
				at = lr.actAt
			}
			lr.res.CancelAt(at)
		}
	}

	if !allOK || (waitTimeout <= 0 && maxDelay > 0) || (waitTimeout > 0 && maxDelay > waitTimeout) {
		cancelAll(now)
		return false, false
	}

	if maxDelay <= 0 {
		return true, false
	}

	select {
	case waitSem <- struct{}{}:
		defer func() { <-waitSem }()
	default:
		cancelAll(now)
		return false, false
	}

	timer := time.NewTimer(maxDelay)
	defer timer.Stop()

	if onWaitStart != nil {
		onWaitStart()
	}

	select {
	case <-r.Context().Done():
		cancelAll(nowFn())
		return false, true
	case <-timer.C:
		return true, false
	}
}

func newPreAuthThrottlingMiddleware(cfg RateLimitConfig, next http.Handler, nowFn func() time.Time) http.Handler {
	return newPreAuthThrottlingMiddlewareWithHooks(cfg, next, nowFn, nil)
}

func newPreAuthThrottlingMiddlewareWithHooks(
	cfg RateLimitConfig,
	next http.Handler,
	nowFn func() time.Time,
	onWaitStart func(),
) http.Handler {
	if nowFn == nil {
		nowFn = time.Now
	}

	globalBurst := resolveRateLimitBurst(cfg.RequestsPerSecond, cfg.Burst)
	globalLimiter := rate.NewLimiter(sanitizeRateLimit(cfg.RequestsPerSecond), globalBurst)

	ipRPS, ipBurst := resolveSubRateLimit(
		cfg.RequestsPerSecond,
		cfg.Burst,
		cfg.PerIPRequestsPerSecond,
		cfg.PerIPBurst,
	)
	unauthIPStore := newKeyedLimiterStoreWithOptions(
		ipRPS,
		ipBurst,
		defaultMaxRateLimitBuckets,
		defaultRateLimitBucketTTL,
		nowFn,
	)
	verifiedIPWSStore := newKeyedLimiterStoreWithOptions(
		ipRPS,
		ipBurst,
		defaultMaxRateLimitBuckets,
		defaultRateLimitBucketTTL,
		nowFn,
	)
	verifiedCache := newVerifiedBearerCache(defaultMaxRateLimitBuckets, defaultRateLimitBucketTTL)

	trustedProxies, _ := ParseTrustedProxies(cfg.TrustedProxies)
	trustedCloudflareProxies, _ := ParseTrustedProxies(cfg.TrustedCloudflareProxies)
	waitTimeout := resolveRateLimitWaitTimeout(cfg.WaitTimeout)

	var waitSem chan struct{}
	if waitTimeout > 0 {
		waitSem = make(chan struct{}, maxConcurrentRateLimitWaits)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.MarkThrottled(r, middleware.ThrottledNo)
		ipKey := extractClientIPKey(r, trustedProxies, trustedCloudflareProxies)

		urlWS, hasWS := extractSCIMWorkspaceUUID(r.URL.Path)
		bearerToken, hasBearer := extractBearerToken(r)
		if hasWS && hasBearer {
			vKey := verifiedBearerKey{
				ipKey:     ipKey,
				wsID:      urlWS,
				tokenHash: sha256.Sum256([]byte(bearerToken)),
			}
			if verifiedCache.Contains(vKey, nowFn()) {
				ipwsLim := verifiedIPWSStore.LimiterForKey(ipKey + "|ws:" + urlWS)
				allowed, canceled := acquireLimitersWithHook(r, nowFn, waitTimeout, waitSem, onWaitStart, ipwsLim, globalLimiter)
				if canceled {
					return
				}
				if !allowed {
					writeRateLimitExceeded(w, r)
					return
				}

				rec := &statusCapture{ResponseWriter: w, statusCode: http.StatusOK}
				next.ServeHTTP(rec, r)
				if rec.statusCode == http.StatusUnauthorized || rec.statusCode == http.StatusForbidden {
					verifiedCache.Delete(vKey)
				}
				return
			}

			unauthLim := unauthIPStore.LimiterForKey(ipKey)
			allowed, canceled := acquireLimitersWithHook(r, nowFn, waitTimeout, waitSem, onWaitStart, unauthLim, globalLimiter)
			if canceled {
				return
			}
			if !allowed {
				writeRateLimitExceeded(w, r)
				return
			}

			hook := preAuthVerifyHook{
				onAuthenticated: func(authWSID uuid.UUID) {
					if authWSID != uuid.Nil && authWSID.String() == urlWS {
						verifiedCache.Put(vKey, nowFn())
					}
				},
			}
			r = r.WithContext(context.WithValue(r.Context(), preAuthVerifyCallbackKey{}, hook))
			next.ServeHTTP(w, r)
			return
		}

		unauthLim := unauthIPStore.LimiterForKey(ipKey)
		allowed, canceled := acquireLimitersWithHook(r, nowFn, waitTimeout, waitSem, onWaitStart, unauthLim, globalLimiter)
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
