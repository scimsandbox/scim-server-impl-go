package app

import (
	"fmt"
	"strings"
)

const defaultManagementPort = 9090

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

func validateConfig(cfg Config) error {
	if cfg.RateLimit.Enabled && cfg.RateLimit.RequestsPerSecond <= 0 {
		return fmt.Errorf("rate_limit.requests_per_second must be greater than 0 when rate limiting is enabled")
	}
	if cfg.RateLimit.WaitTimeout < 0 {
		return fmt.Errorf("rate_limit.wait_timeout must be greater than or equal to 0")
	}

	return nil
}
