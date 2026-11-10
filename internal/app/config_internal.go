package app

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/scimsandbox/scim-server-impl-go/internal/service"
)

const (
	defaultManagementPort = 9090
	minCursorSecretLength = 32
	pgScheme              = "postgres://"
)

func normalizeDSN(rawDSN string) string {
	// Convert JDBC URL to pgx-compatible format
	dsn := strings.TrimPrefix(rawDSN, "jdbc:")
	if strings.HasPrefix(dsn, "postgresql://") {
		dsn = pgScheme + strings.TrimPrefix(dsn, "postgresql://")
	}
	if !strings.Contains(dsn, "sslmode=") {
		if strings.Contains(dsn, "?") {
			dsn += "&sslmode=disable"
		} else {
			dsn += "?sslmode=disable"
		}
	}
	return dsn
}

func resolveDSN(cfg Config) string {
	dsn := normalizeDSN(cfg.Storage.DSN)
	if cfg.Storage.Username != "" {
		if parsed, err := url.Parse(dsn); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			parsed.User = url.UserPassword(cfg.Storage.Username, cfg.Storage.Password)
			return parsed.String()
		}
		encoded := url.UserPassword(cfg.Storage.Username, cfg.Storage.Password).String()
		dsn = strings.Replace(dsn, pgScheme, pgScheme+encoded+"@", 1)
	}
	return dsn
}

func redactDSN(rawDSN, username string) string {
	dsn := normalizeDSN(rawDSN)
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "[REDACTED]"
	}
	if parsed.RawQuery != "" {
		q, qErr := url.ParseQuery(parsed.RawQuery)
		if qErr != nil {
			return "[REDACTED]"
		}
		modified := false
		for k := range q {
			lower := strings.ToLower(k)
			if strings.Contains(lower, "pass") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "key") {
				q.Set(k, "***")
				modified = true
			}
		}
		if modified {
			parsed.RawQuery = q.Encode()
		}
	}
	if username != "" {
		encodedUser := url.User(username).String()
		parsed.User = nil
		schemePrefix := parsed.Scheme + "://"
		return strings.Replace(parsed.String(), schemePrefix, schemePrefix+encodedUser+":***@", 1)
	}
	return parsed.Redacted()
}

func managementPort(cfg Config) int {
	if cfg.Management.Port == 0 {
		return defaultManagementPort
	}
	return cfg.Management.Port
}

func serverBaseURL(cfg Config) string {
	if u := strings.TrimRight(strings.TrimSpace(cfg.Server.BaseURL), "/"); u != "" {
		return u
	}
	port := cfg.Server.Port
	if port <= 0 {
		port = 8080
	}
	return fmt.Sprintf("http://localhost:%d", port)
}

func printableConfig(cfg Config) Config {
	masked := cfg
	if masked.Storage.Password != "" {
		masked.Storage.Password = "***"
	}
	if masked.Server.CursorSecret != "" {
		masked.Server.CursorSecret = "***"
	}
	return masked
}

func applyConfigDefaults(cfg *Config) {
	cfg.Server.BaseURL = strings.TrimRight(strings.TrimSpace(cfg.Server.BaseURL), "/")
	if cfg.Cleanup.RequestLogs.Enabled == nil {
		defaultEnabled := true
		cfg.Cleanup.RequestLogs.Enabled = &defaultEnabled
	}
	if cfg.Cleanup.RequestLogs.Interval == 0 {
		cfg.Cleanup.RequestLogs.Interval = service.DefaultRequestLogCleanupInterval
	}
	if cfg.Cleanup.RequestLogs.MaxCount == 0 {
		cfg.Cleanup.RequestLogs.MaxCount = service.DefaultRequestLogCleanupMaxCount
	}
	if cfg.Cleanup.AsyncEvents.Enabled == nil {
		defaultEnabled := true
		cfg.Cleanup.AsyncEvents.Enabled = &defaultEnabled
	}
	if cfg.Cleanup.AsyncEvents.Interval == 0 {
		cfg.Cleanup.AsyncEvents.Interval = service.DefaultAsyncEventCleanupInterval
	}
	if cfg.Cleanup.AsyncEvents.MaxCount == 0 {
		cfg.Cleanup.AsyncEvents.MaxCount = service.DefaultAsyncEventCleanupMaxCount
	}
	if cfg.Cleanup.AsyncEvents.StalePendingAfter == 0 {
		cfg.Cleanup.AsyncEvents.StalePendingAfter = service.DefaultAsyncEventStalePendingAfter
	}
}

func validateConfig(cfg Config) error {
	if cfg.Server.BaseURL != "" && !strings.HasPrefix(cfg.Server.BaseURL, "http://") && !strings.HasPrefix(cfg.Server.BaseURL, "https://") {
		return fmt.Errorf("server.base_url must start with http:// or https://")
	}
	if s := strings.TrimSpace(cfg.Server.CursorSecret); s != "" && len(s) < minCursorSecretLength {
		return fmt.Errorf("server.cursor_secret must be at least %d characters long", minCursorSecretLength)
	}
	if cfg.RateLimit.Enabled && cfg.RateLimit.RequestsPerSecond <= 0 {
		return fmt.Errorf("rate_limit.requests_per_second must be greater than 0 when rate limiting is enabled")
	}
	if cfg.RateLimit.WaitTimeout < 0 {
		return fmt.Errorf("rate_limit.wait_timeout must be greater than or equal to 0")
	}
	if cfg.Cleanup.RequestLogs.Interval <= 0 {
		return fmt.Errorf("cleanup.request_logs.interval must be greater than 0")
	}
	if cfg.Cleanup.RequestLogs.MaxCount <= 0 {
		return fmt.Errorf("cleanup.request_logs.max_count must be greater than 0")
	}
	if cfg.Cleanup.AsyncEvents.Interval <= 0 {
		return fmt.Errorf("cleanup.async_events.interval must be greater than 0")
	}
	if cfg.Cleanup.AsyncEvents.MaxCount <= 0 {
		return fmt.Errorf("cleanup.async_events.max_count must be greater than 0")
	}
	if cfg.Cleanup.AsyncEvents.StalePendingAfter <= 0 {
		return fmt.Errorf("cleanup.async_events.stale_pending_after must be greater than 0")
	}

	return nil
}
