package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/messages"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
	"golang.org/x/time/rate"
)

const (
	defaultRateLimitWaitTimeout = 60 * time.Second
	rateLimitRetryAfter         = 5 * time.Minute
	rateLimitCapacityDetail     = "The server reached max capacity. Try again later."
)

type statusCapture struct {
	http.ResponseWriter
	statusCode int
}

type requestLimiter interface {
	Wait(context.Context) error
}

func (s *statusCapture) WriteHeader(code int) {
	s.statusCode = code
	s.ResponseWriter.WriteHeader(code)
}

func newRequestLimiter(requestsPerSecond float64) requestLimiter {
	return rate.NewLimiter(rate.Limit(requestsPerSecond), 1)
}

func resolveRateLimitWaitTimeout(waitTimeout time.Duration) time.Duration {
	if waitTimeout == 0 {
		return defaultRateLimitWaitTimeout
	}

	return waitTimeout
}

func throttlingMiddleware(limiter requestLimiter, waitTimeout time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.MarkThrottled(r, middleware.ThrottledNo)
		waitCtx, cancel := context.WithTimeout(r.Context(), waitTimeout)
		defer cancel()

		if err := limiter.Wait(waitCtx); err != nil {
			if r.Context().Err() != nil {
				return
			}

			middleware.MarkThrottled(r, middleware.ThrottledYes)
			w.Header().Set("Retry-After", strconv.Itoa(int(rateLimitRetryAfter/time.Second)))
			scim.WriteScimError(w, scim.NewScimError(http.StatusServiceUnavailable, "", rateLimitCapacityDetail))
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
