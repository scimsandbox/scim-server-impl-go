package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	t.Run("returns error when main config file is missing", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		_, err := loadConfig(func(key string) (string, bool) {
			if key == "GO_CONFIG_DIR" {
				return configDir, true
			}
			return "", false
		})
		if err == nil {
			t.Fatal("loadConfig() error = nil, want missing config file error")
		}

		want := filepath.Join(configDir, "app-conf.yaml")
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("loadConfig() error = %q, want path %q", err.Error(), want)
		}
	})

	t.Run("loads mandatory config and applies env overrides", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		config := strings.Join([]string{
			"server:",
			"  port: 8080",
			"management:",
			"  port: 9090",
			"rate_limit:",
			"  enabled: true",
			"  requests_per_second: 200",
			"  wait_timeout: 60s",
			"storage:",
			"  dsn: \"jdbc:postgresql://localhost:5432/scimplayground\"",
			"  username: \"scim_playground\"",
			"  password: \"scim_playground\"",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		cfg, err := loadConfig(func(key string) (string, bool) {
			switch key {
			case "GO_CONFIG_DIR":
				return configDir, true
			case "GO_SERVER_PORT":
				return "8181", true
			case "GO_RATE_LIMIT_REQUESTS_PER_SECOND":
				return "125.5", true
			case "GO_RATE_LIMIT_WAIT_TIMEOUT":
				return "45s", true
			default:
				return "", false
			}
		})
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.Server.Port != 8181 {
			t.Fatalf("cfg.Server.Port = %d, want 8181", cfg.Server.Port)
		}
		if cfg.Management.Port != 9090 {
			t.Fatalf("cfg.Management.Port = %d, want 9090", cfg.Management.Port)
		}
		if !cfg.RateLimit.Enabled {
			t.Fatal("cfg.RateLimit.Enabled = false, want true")
		}
		if cfg.RateLimit.RequestsPerSecond != 125.5 {
			t.Fatalf("cfg.RateLimit.RequestsPerSecond = %v, want 125.5", cfg.RateLimit.RequestsPerSecond)
		}
		if cfg.RateLimit.WaitTimeout != 45*time.Second {
			t.Fatalf("cfg.RateLimit.WaitTimeout = %v, want 45s", cfg.RateLimit.WaitTimeout)
		}
	})

	t.Run("returns error when rate limit is enabled without a positive request rate", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		config := strings.Join([]string{
			"server:",
			"  port: 8080",
			"management:",
			"  port: 9090",
			"rate_limit:",
			"  enabled: true",
			"  requests_per_second: 0",
			"storage:",
			"  dsn: \"jdbc:postgresql://localhost:5432/scimplayground\"",
			"  username: \"scim_playground\"",
			"  password: \"scim_playground\"",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		_, err := loadConfig(func(key string) (string, bool) {
			if key == "GO_CONFIG_DIR" {
				return configDir, true
			}
			return "", false
		})
		if err == nil {
			t.Fatal("loadConfig() error = nil, want invalid rate limit error")
		}
		if !strings.Contains(err.Error(), "rate_limit.requests_per_second") {
			t.Fatalf("loadConfig() error = %q, want rate limit validation message", err.Error())
		}
	})

	t.Run("returns error when wait timeout is negative", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		config := strings.Join([]string{
			"server:",
			"  port: 8080",
			"management:",
			"  port: 9090",
			"rate_limit:",
			"  enabled: true",
			"  requests_per_second: 200",
			"  wait_timeout: -1s",
			"storage:",
			"  dsn: \"jdbc:postgresql://localhost:5432/scimplayground\"",
			"  username: \"scim_playground\"",
			"  password: \"scim_playground\"",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		_, err := loadConfig(func(key string) (string, bool) {
			if key == "GO_CONFIG_DIR" {
				return configDir, true
			}
			return "", false
		})
		if err == nil {
			t.Fatal("loadConfig() error = nil, want invalid wait timeout error")
		}
		if !strings.Contains(err.Error(), "rate_limit.wait_timeout") {
			t.Fatalf("loadConfig() error = %q, want wait timeout validation message", err.Error())
		}
	})
}

func TestResolveDSN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "plain postgres URL unchanged, sslmode appended",
			cfg:  Config{Storage: StorageConfig{DSN: "postgres://host:5432/db"}},
			want: "postgres://host:5432/db?sslmode=disable",
		},
		{
			name: "jdbc: prefix stripped",
			cfg:  Config{Storage: StorageConfig{DSN: "jdbc:postgresql://host:5432/db"}},
			want: "postgres://host:5432/db?sslmode=disable",
		},
		{
			name: "credentials injected into URL",
			cfg: Config{Storage: StorageConfig{
				DSN:      "postgres://host:5432/db",
				Username: "alice",
				Password: "secret",
			}},
			want: "postgres://alice:secret@host:5432/db?sslmode=disable",
		},
		{
			name: "jdbc URL with credentials",
			cfg: Config{Storage: StorageConfig{
				DSN:      "jdbc:postgresql://host:5432/db",
				Username: "bob",
				Password: "pass",
			}},
			want: "postgres://bob:pass@host:5432/db?sslmode=disable",
		},
		{
			name: "existing sslmode not duplicated",
			cfg:  Config{Storage: StorageConfig{DSN: "postgres://host:5432/db?sslmode=require"}},
			want: "postgres://host:5432/db?sslmode=require",
		},
		{
			name: "existing query param plus sslmode appended",
			cfg:  Config{Storage: StorageConfig{DSN: "postgres://host:5432/db?connect_timeout=5"}},
			want: "postgres://host:5432/db?connect_timeout=5&sslmode=disable",
		},
		{
			name: "empty username leaves URL without credentials",
			cfg: Config{Storage: StorageConfig{
				DSN:      "postgres://host:5432/db",
				Username: "",
				Password: "ignored",
			}},
			want: "postgres://host:5432/db?sslmode=disable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := resolveDSN(tc.cfg)
			if got != tc.want {
				t.Fatalf("resolveDSN() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestManagementPort(t *testing.T) {
	t.Parallel()

	t.Run("returns default when port is zero", func(t *testing.T) {
		t.Parallel()
		got := managementPort(Config{Management: ManagementConfig{Port: 0}})
		if got != defaultManagementPort {
			t.Fatalf("managementPort() = %d, want %d", got, defaultManagementPort)
		}
	})

	t.Run("returns configured port", func(t *testing.T) {
		t.Parallel()
		got := managementPort(Config{Management: ManagementConfig{Port: 9191}})
		if got != 9191 {
			t.Fatalf("managementPort() = %d, want 9191", got)
		}
	})
}

func TestPrintableConfig(t *testing.T) {
	t.Parallel()

	t.Run("masks non-empty password", func(t *testing.T) {
		t.Parallel()
		cfg := Config{Storage: StorageConfig{DSN: "postgres://host/db", Username: "user", Password: "secret"}}
		result := printableConfig(cfg)
		if result.Storage.Password != "***" {
			t.Fatalf("printableConfig() password = %q, want %q", result.Storage.Password, "***")
		}
		// Original config is not modified
		if cfg.Storage.Password != "secret" {
			t.Fatalf("original config password mutated to %q", cfg.Storage.Password)
		}
	})

	t.Run("empty password stays empty", func(t *testing.T) {
		t.Parallel()
		cfg := Config{Storage: StorageConfig{DSN: "postgres://host/db"}}
		result := printableConfig(cfg)
		if result.Storage.Password != "" {
			t.Fatalf("printableConfig() password = %q, want empty", result.Storage.Password)
		}
	})

	t.Run("other fields are preserved", func(t *testing.T) {
		t.Parallel()
		cfg := Config{Storage: StorageConfig{DSN: "postgres://host/db", Username: "alice", Password: "pw"}}
		result := printableConfig(cfg)
		if result.Storage.DSN != cfg.Storage.DSN {
			t.Fatalf("printableConfig() DSN = %q, want %q", result.Storage.DSN, cfg.Storage.DSN)
		}
		if result.Storage.Username != cfg.Storage.Username {
			t.Fatalf("printableConfig() Username = %q, want %q", result.Storage.Username, cfg.Storage.Username)
		}
	})
}
