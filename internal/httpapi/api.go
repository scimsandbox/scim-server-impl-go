package httpapi

import (
	"net/http"
	"time"

	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/messages"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
)

type RateLimitConfig struct {
	Enabled           bool          `yaml:"enabled" env:"GO_RATE_LIMIT_ENABLED"`
	RequestsPerSecond float64       `yaml:"requests_per_second" env:"GO_RATE_LIMIT_REQUESTS_PER_SECOND"`
	WaitTimeout       time.Duration `yaml:"wait_timeout" env:"GO_RATE_LIMIT_WAIT_TIMEOUT"`
}

type Config struct {
	Logger    logging.Logger
	Localizer messages.Localizer
	RateLimit RateLimitConfig
}

func New(handler http.Handler, config Config) http.Handler {
	logger := config.Logger
	localizer := config.Localizer
	wrapped := handler
	if config.RateLimit.Enabled {
		wrapped = throttlingMiddleware(
			newRequestLimiter(config.RateLimit.RequestsPerSecond),
			resolveRateLimitWaitTimeout(config.RateLimit.WaitTimeout),
			wrapped,
		)
	}
	wrapped = middleware.ScimMetrics(wrapped)
	wrapped = requestLoggingMiddleware(logger, localizer, wrapped)

	return wrapped
}
