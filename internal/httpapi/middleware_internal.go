package httpapi

import (
	"context"
	"math"
	"net"
	"net/http"
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
	defaultRateLimitWaitTimeout = time.Duration(0)
	maxRateLimitWaitTimeout     = 5 * time.Second
	maxConcurrentRateLimitWaits = 64
	maxDefaultRateLimitBurst    = 1000
	defaultMaxRateLimitBuckets  = 4096
	defaultRateLimitBucketTTL   = 10 * time.Minute
	defaultRateLimitSweepPeriod = time.Minute
	rateLimitRetryAfterSeconds  = 1
	rateLimitScimType           = "tooMany"
	rateLimitCapacityDetail     = "Rate limit exceeded. Try again later."
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
	limiter  *rate.Limiter
	lastSeen time.Time
}

type keyedLimiterStore struct {
	mu          sync.Mutex
	entries     map[string]*limiterEntry
	limit       rate.Limit
	burst       int
	maxEntries  int
	ttl         time.Duration
	sweepPeriod time.Duration
	lastSweep   time.Time
	now         func() time.Time
}

func (s *statusCapture) WriteHeader(code int) {
	s.statusCode = code
	s.ResponseWriter.WriteHeader(code)
}

func resolveRateLimitBurst(requestsPerSecond float64, burst int) int {
	if burst > 0 {
		return burst
	}
	if requestsPerSecond <= 1 {
		return 1
	}
	computed := int(math.Ceil(requestsPerSecond))
	if computed > maxDefaultRateLimitBurst {
		return maxDefaultRateLimitBurst
	}
	return computed
}

func newKeyedLimiterStore(requestsPerSecond float64, burst int) *keyedLimiterStore {
	return newKeyedLimiterStoreWithOptions(
		requestsPerSecond,
		burst,
		defaultMaxRateLimitBuckets,
		defaultRateLimitBucketTTL,
		defaultRateLimitSweepPeriod,
		time.Now,
	)
}

func newKeyedLimiterStoreWithOptions(
	requestsPerSecond float64,
	burst int,
	maxEntries int,
	ttl time.Duration,
	sweepPeriod time.Duration,
	nowFn func() time.Time,
) *keyedLimiterStore {
	return &keyedLimiterStore{
		entries:     make(map[string]*limiterEntry),
		limit:       rate.Limit(requestsPerSecond),
		burst:       resolveRateLimitBurst(requestsPerSecond, burst),
		maxEntries:  maxEntries,
		ttl:         ttl,
		sweepPeriod: sweepPeriod,
		now:         nowFn,
	}
}

func extractRateLimitKey(r *http.Request) string {
	if r != nil && r.URL != nil && strings.HasPrefix(r.URL.Path, "/ws/") {
		seg, _, _ := strings.Cut(r.URL.Path[len("/ws/"):], "/")
		if seg != "" {
			if wsID, err := uuid.Parse(seg); err == nil {
				return "ws:" + wsID.String()
			}
		}
	}

	if r == nil {
		return "global"
	}
	addr := strings.TrimSpace(r.RemoteAddr)
	if addr == "" {
		return "global"
	}
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		return "ip:" + host
	}
	return "ip:" + addr
}

func (s *keyedLimiterStore) LimiterFor(r *http.Request) requestLimiter {
	key := extractRateLimitKey(r)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	if s.lastSweep.IsZero() || now.Sub(s.lastSweep) >= s.sweepPeriod {
		s.evictExpiredLocked(now)
	}

	if entry, ok := s.entries[key]; ok {
		if now.Sub(entry.lastSeen) < s.ttl {
			entry.lastSeen = now
			return entry.limiter
		}
		delete(s.entries, key)
	}

	if len(s.entries) >= s.maxEntries {
		s.evictExpiredLocked(now)
		if len(s.entries) >= s.maxEntries {
			s.evictOldestLocked()
		}
	}

	lim := rate.NewLimiter(s.limit, s.burst)
	s.entries[key] = &limiterEntry{
		limiter:  lim,
		lastSeen: now,
	}
	return lim
}

func (s *keyedLimiterStore) evictExpiredLocked(now time.Time) {
	for k, entry := range s.entries {
		if now.Sub(entry.lastSeen) >= s.ttl {
			delete(s.entries, k)
		}
	}
	s.lastSweep = now
}

func (s *keyedLimiterStore) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	for k, entry := range s.entries {
		if oldestKey == "" || entry.lastSeen.Before(oldestTime) || (entry.lastSeen.Equal(oldestTime) && k < oldestKey) {
			oldestKey = k
			oldestTime = entry.lastSeen
		}
	}
	if oldestKey != "" {
		delete(s.entries, oldestKey)
	}
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

func throttlingMiddleware(provider limiterProvider, waitTimeout time.Duration, next http.Handler) http.Handler {
	var waitSem chan struct{}
	if waitTimeout > 0 {
		waitSem = make(chan struct{}, maxConcurrentRateLimitWaits)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.MarkThrottled(r, middleware.ThrottledNo)
		if r.Context().Err() != nil {
			return
		}

		limiter := provider.LimiterFor(r)
		if limiter.Allow() {
			next.ServeHTTP(w, r)
			return
		}

		if waitTimeout <= 0 {
			writeRateLimitExceeded(w, r)
			return
		}

		select {
		case waitSem <- struct{}{}:
			defer func() { <-waitSem }()
		default:
			writeRateLimitExceeded(w, r)
			return
		}

		waitCtx, cancel := context.WithTimeout(r.Context(), waitTimeout)
		defer cancel()

		if err := limiter.Wait(waitCtx); err != nil {
			if r.Context().Err() != nil {
				return
			}
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
