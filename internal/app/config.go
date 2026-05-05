package app

import (
	"time"

	"github.com/scimsandbox/scim-server-impl-go/internal/httpapi"
	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/messages"
)

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Management ManagementConfig `yaml:"management"`
	RateLimit  RateLimitConfig  `yaml:"rate_limit"`
	Storage    StorageConfig    `yaml:"storage"`
	Cleanup    CleanupConfig    `yaml:"cleanup"`
	Messages   messages.Config  `yaml:"messages"`
	Logging    LoggingConfig    `yaml:"logging"`
}

type ServerConfig struct {
	Port              int           `yaml:"port" env:"GO_SERVER_PORT"`
	ReadTimeout       time.Duration `yaml:"read_timeout" env:"GO_SERVER_READ_TIMEOUT"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" env:"GO_SERVER_READ_HEADER_TIMEOUT"`
	WriteTimeout      time.Duration `yaml:"write_timeout" env:"GO_SERVER_WRITE_TIMEOUT"`
	IdleTimeout       time.Duration `yaml:"idle_timeout" env:"GO_SERVER_IDLE_TIMEOUT"`
	ShutdownTimeout   time.Duration `yaml:"shutdown_timeout" env:"GO_SERVER_SHUTDOWN_TIMEOUT"`
}

type ManagementConfig struct {
	Port int `yaml:"port" env:"GO_MANAGEMENT_PORT"`
}

type RateLimitConfig = httpapi.RateLimitConfig

type StorageConfig struct {
	DSN      string `yaml:"dsn" env:"GO_DATASOURCE_URL"`
	Username string `yaml:"username" env:"GO_DATASOURCE_USERNAME"`
	Password string `yaml:"password" env:"GO_DATASOURCE_PASSWORD"`
	MaxConns int32  `yaml:"max_conns" env:"GO_DATASOURCE_MAX_CONNS"`
	MinConns int32  `yaml:"min_conns" env:"GO_DATASOURCE_MIN_CONNS"`
}

type CleanupConfig struct {
	Enabled    bool          `yaml:"enabled" env:"GO_CLEANUP_ENABLED"`
	Interval   time.Duration `yaml:"interval" env:"GO_CLEANUP_INTERVAL"`
	StaleAfter time.Duration `yaml:"stale_after" env:"GO_CLEANUP_STALE_AFTER"`
}

type LoggingConfig struct {
	Level logging.Level `yaml:"level" env:"GO_LOGGING_LEVEL"`
}
