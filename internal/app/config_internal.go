package app

import (
	"fmt"
	"strings"
	"time"
)

const (
	defaultManagementPort              = 9090
	defaultCleanupRequestLogsMaxCount = 10000
	defaultCleanupRequestLogsInterval = time.Hour
)

func resolveDSN(cfg Config) string {
	dsn := cfg.Storage.DSN
	// Convert JDBC URL to pgx-compatible format
	dsn = strings.TrimPrefix(dsn, "jdbc:")
	const newConst = "postgres://"
	dsn = strings.Replace(dsn, "postgresql://", newConst, 1)
	if cfg.Storage.Username != "" {
		dsn = strings.Replace(dsn, newConst, newConst+cfg.Storage.Username+":"+cfg.Storage.Password+"@", 1)
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

func managementPort(cfg Config) int {
	if cfg.Management.Port == 0 {
		return defaultManagementPort
	}
	return cfg.Management.Port
}

func printableConfig(cfg Config) Config {
	masked := cfg
	if masked.Storage.Password != "" {
		masked.Storage.Password = "***"
	}
	return masked
}

func applyConfigDefaults(cfg *Config) {
	if cfg.Cleanup.RequestLogs.Interval == 0 {
		cfg.Cleanup.RequestLogs.Interval = defaultCleanupRequestLogsInterval
	}
	if cfg.Cleanup.RequestLogs.MaxCount == 0 {
		cfg.Cleanup.RequestLogs.MaxCount = defaultCleanupRequestLogsMaxCount
	}
}

func cleanupRequestLogsMaxCount(cfg Config) int {
	if cfg.Cleanup.RequestLogs.MaxCount <= 0 {
		return defaultCleanupRequestLogsMaxCount
	}
	return cfg.Cleanup.RequestLogs.MaxCount
}

func cleanupRequestLogsInterval(cfg Config) time.Duration {
	if cfg.Cleanup.RequestLogs.Interval <= 0 {
		return defaultCleanupRequestLogsInterval
	}
	return cfg.Cleanup.RequestLogs.Interval
}

func validateConfig(cfg Config) error {
	if cfg.RateLimit.Enabled && cfg.RateLimit.RequestsPerSecond <= 0 {
		return fmt.Errorf("rate_limit.requests_per_second must be greater than 0 when rate limiting is enabled")
	}
	if cfg.RateLimit.WaitTimeout < 0 {
		return fmt.Errorf("rate_limit.wait_timeout must be greater than or equal to 0")
	}
	if cfg.Cleanup.RequestLogs.Interval < 0 {
		return fmt.Errorf("cleanup.request_logs.interval must be greater than or equal to 0")
	}
	if cfg.Cleanup.RequestLogs.MaxCount < 0 {
		return fmt.Errorf("cleanup.request_logs.max_count must be greater than or equal to 0")
	}

	return nil
}
