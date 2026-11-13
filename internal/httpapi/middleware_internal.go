package httpapi

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

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

func newRequestLimiter(requestsPerSecond float64, burst int) requestLimiter {
	return rate.NewLimiter(rate.Limit(requestsPerSecond), resolveRateLimitBurst(requestsPerSecond, burst))
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

func isManagementPath(path string) bool {
	return path == "/metrics" || path == "/actuator" || strings.HasPrefix(path, "/actuator/")
}

func writeRateLimitExceeded(w http.ResponseWriter, r *http.Request) {
	middleware.MarkThrottled(r, middleware.ThrottledYes)
	w.Header().Set("Retry-After", strconv.Itoa(rateLimitRetryAfterSeconds))
	scim.WriteScimError(w, scim.NewScimError(http.StatusTooManyRequests, rateLimitScimType, rateLimitCapacityDetail))
}

func throttlingMiddleware(limiter requestLimiter, waitTimeout time.Duration, next http.Handler) http.Handler {
	var waitSem chan struct{}
	if waitTimeout > 0 {
		waitSem = make(chan struct{}, maxConcurrentRateLimitWaits)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isManagementPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		middleware.MarkThrottled(r, middleware.ThrottledNo)
		if r.Context().Err() != nil {
			return
		}

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
