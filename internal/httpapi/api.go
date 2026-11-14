package httpapi

import (
	"net/http"
	"time"

	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/messages"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
)

type RateLimitConfig struct {
	Enabled                       bool          `yaml:"enabled" env:"GO_RATE_LIMIT_ENABLED"`
	RequestsPerSecond             float64       `yaml:"requests_per_second" env:"GO_RATE_LIMIT_REQUESTS_PER_SECOND"`
	Burst                         int           `yaml:"burst" env:"GO_RATE_LIMIT_BURST"`
	PerIPRequestsPerSecond        float64       `yaml:"per_ip_requests_per_second" env:"GO_RATE_LIMIT_PER_IP_REQUESTS_PER_SECOND"`
	PerIPBurst                    int           `yaml:"per_ip_burst" env:"GO_RATE_LIMIT_PER_IP_BURST"`
	PerWorkspaceRequestsPerSecond float64       `yaml:"per_workspace_requests_per_second" env:"GO_RATE_LIMIT_PER_WORKSPACE_REQUESTS_PER_SECOND"`
	PerWorkspaceBurst             int           `yaml:"per_workspace_burst" env:"GO_RATE_LIMIT_PER_WORKSPACE_BURST"`
	TrustedProxies                string        `yaml:"trusted_proxies" env:"GO_RATE_LIMIT_TRUSTED_PROXIES"`
	WaitTimeout                   time.Duration `yaml:"wait_timeout" env:"GO_RATE_LIMIT_WAIT_TIMEOUT"`
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
		wrapped = preAuthThrottlingMiddleware(config.RateLimit, wrapped)
	}
	wrapped = middleware.ScimMetrics(wrapped)
	wrapped = requestLoggingMiddleware(logger, localizer, wrapped)

	return wrapped
}

// NewWorkspaceRateLimitMiddleware enforces post-authentication per-workspace
// rate limits using only the verified workspace UUID set by BearerTokenAuth.
func NewWorkspaceRateLimitMiddleware(cfg RateLimitConfig) func(http.Handler) http.Handler {
	if !cfg.Enabled {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	wsRPS, wsBurst := resolveSubRateLimit(
		cfg.RequestsPerSecond,
		cfg.Burst,
		cfg.PerWorkspaceRequestsPerSecond,
		cfg.PerWorkspaceBurst,
	)
	wsStore := newKeyedLimiterStore(wsRPS, wsBurst)
	waitTimeout := resolveRateLimitWaitTimeout(cfg.WaitTimeout)

	var waitSem chan struct{}
	if waitTimeout > 0 {
		waitSem = make(chan struct{}, maxConcurrentRateLimitWaits)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wsID, ok := middleware.AuthenticatedWorkspaceID(r.Context())
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			wsLimiter := wsStore.LimiterForKey("ws:" + wsID.String())
			allowed, canceled := acquireLimiters(r, waitTimeout, waitSem, wsLimiter)
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
}
