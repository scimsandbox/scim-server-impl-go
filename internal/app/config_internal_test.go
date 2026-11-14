package app

import (
	"bytes"
	"context"
	"math"
	"net/url"
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
		{
			name: "plain postgresql:// scheme normalized",
			cfg:  Config{Storage: StorageConfig{DSN: "postgresql://host:5432/db"}},
			want: "postgres://host:5432/db?sslmode=disable",
		},
		{
			name: "reserved characters in username and password are percent-encoded",
			cfg: Config{Storage: StorageConfig{
				DSN:      "postgres://host:5432/db",
				Username: "alice@example.com",
				Password: "p@ss:w/rd%1",
			}},
			want: "postgres://alice%40example.com:p%40ss%3Aw%2Frd%251@host:5432/db?sslmode=disable",
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

func TestRedactDSN(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		rawDSN          string
		username        string
		wantExact       string
		wantScheme      string
		wantHost        string
		wantUser        string
		wantSSLMode     string
		forbiddenValues []string
	}{
		{
			name:        "jdbc URL with configured username masks credentials",
			rawDSN:      "jdbc:postgresql://localhost:5432/scimplayground",
			username:    "scim_playground",
			wantScheme:  "postgres",
			wantHost:    "localhost:5432",
			wantUser:    "scim_playground",
			wantSSLMode: "disable",
		},
		{
			name:      "plain postgres URL without credentials",
			rawDSN:    "postgres://host:5432/db",
			username:  "",
			wantExact: "postgres://host:5432/db?sslmode=disable",
		},
		{
			name:            "plain postgresql:// URL normalizes scheme and redacts inline secret",
			rawDSN:          "postgresql://bob:topsecret@host:5432/db",
			username:        "",
			wantScheme:      "postgres",
			wantHost:        "host:5432",
			wantUser:        "bob",
			wantSSLMode:     "disable",
			forbiddenValues: []string{"topsecret"},
		},
		{
			name:            "inline password in DSN redacted when username empty",
			rawDSN:          "postgres://bob:supersecret@host:5432/db?sslmode=require",
			username:        "",
			wantScheme:      "postgres",
			wantHost:        "host:5432",
			wantUser:        "bob",
			wantSSLMode:     "require",
			forbiddenValues: []string{"supersecret"},
		},
		{
			name:            "inline password in DSN stripped when username overridden",
			rawDSN:          "postgres://bob:supersecret@host:5432/db",
			username:        "alice",
			wantScheme:      "postgres",
			wantHost:        "host:5432",
			wantUser:        "alice",
			wantSSLMode:     "disable",
			forbiddenValues: []string{"supersecret", "bob"},
		},
		{
			name:        "configured username with reserved characters remains valid URL",
			rawDSN:      "postgres://host:5432/db",
			username:    "alice@example.com",
			wantScheme:  "postgres",
			wantHost:    "host:5432",
			wantUser:    "alice@example.com",
			wantSSLMode: "disable",
		},
		{
			name:            "query parameter password redacted without configured username",
			rawDSN:          "postgres://host:5432/db?password=mysecret&sslmode=require",
			username:        "",
			wantScheme:      "postgres",
			wantHost:        "host:5432",
			wantSSLMode:     "require",
			forbiddenValues: []string{"mysecret"},
		},
		{
			name:            "query parameter password redacted with configured username",
			rawDSN:          "postgres://host:5432/db?password=mysecret&connect_timeout=5",
			username:        "alice@example.com",
			wantScheme:      "postgres",
			wantHost:        "host:5432",
			wantUser:        "alice@example.com",
			wantSSLMode:     "disable",
			forbiddenValues: []string{"mysecret"},
		},
		{
			name:            "key-value DSN redacted completely",
			rawDSN:          "host=localhost user=postgres password=mysecret dbname=db",
			username:        "",
			wantExact:       "[REDACTED]",
			forbiddenValues: []string{"mysecret"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := redactDSN(tc.rawDSN, tc.username)
			for _, secret := range tc.forbiddenValues {
				if strings.Contains(got, secret) {
					t.Fatalf("redactDSN(%q, %q) = %q, leaked forbidden value %q", tc.rawDSN, tc.username, got, secret)
				}
			}
			if tc.wantExact != "" {
				if got != tc.wantExact {
					t.Fatalf("redactDSN(%q, %q) = %q, want %q", tc.rawDSN, tc.username, got, tc.wantExact)
				}
				return
			}
			parsed, err := url.Parse(got)
			if err != nil {
				t.Fatalf("redactDSN(%q, %q) = %q, produced invalid URL: %v", tc.rawDSN, tc.username, got, err)
			}
			if parsed.Scheme != tc.wantScheme {
				t.Fatalf("scheme = %q, want %q (got %q)", parsed.Scheme, tc.wantScheme, got)
			}
			if parsed.Host != tc.wantHost {
				t.Fatalf("host = %q, want %q (got %q)", parsed.Host, tc.wantHost, got)
			}
			if tc.wantUser != "" {
				if parsed.User == nil || parsed.User.Username() != tc.wantUser {
					var gotUser string
					if parsed.User != nil {
						gotUser = parsed.User.Username()
					}
					t.Fatalf("username = %q, want %q (got %q)", gotUser, tc.wantUser, got)
				}
				if _, hasPass := parsed.User.Password(); !hasPass {
					t.Fatalf("expected masked password placeholder in userinfo of %q", got)
				}
			}
			if tc.wantSSLMode != "" {
				if gotSSL := parsed.Query().Get("sslmode"); gotSSL != tc.wantSSLMode {
					t.Fatalf("sslmode = %q, want %q (got %q)", gotSSL, tc.wantSSLMode, got)
				}
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

	t.Run("masks non-empty cursor secret", func(t *testing.T) {
		t.Parallel()
		cfg := Config{Server: ServerConfig{Port: 8080, CursorSecret: "top-secret-hmac-key"}}
		result := printableConfig(cfg)
		if result.Server.CursorSecret != "***" {
			t.Fatalf("printableConfig() CursorSecret = %q, want %q", result.Server.CursorSecret, "***")
		}
		if cfg.Server.CursorSecret != "top-secret-hmac-key" {
			t.Fatalf("original config CursorSecret mutated to %q", cfg.Server.CursorSecret)
		}
	})

	t.Run("preserves jdbc DSN shape when no inline credentials are present", func(t *testing.T) {
		t.Parallel()
		cfg := Config{Storage: StorageConfig{DSN: "jdbc:postgresql://localhost:5432/scimplayground", Username: "scim_playground", Password: "pw"}}
		result := printableConfig(cfg)
		if result.Storage.DSN != cfg.Storage.DSN {
			t.Fatalf("printableConfig() DSN = %q, want %q", result.Storage.DSN, cfg.Storage.DSN)
		}
	})

	t.Run("masks inline and query-string DSN credentials without normalizing DSN shape", func(t *testing.T) {
		t.Parallel()
		cases := []struct {
			name        string
			dsn         string
			wantPrefix  string
			forbidden   []string
			wantLiteral string
		}{
			{
				name:       "inline password in postgres URL",
				dsn:        "postgres://bob:supersecret@host:5432/db",
				wantPrefix: "postgres://bob:",
				forbidden:  []string{"supersecret", "sslmode="},
			},
			{
				name:       "inline password in jdbc URL preserves jdbc prefix",
				dsn:        "jdbc:postgresql://bob:supersecret@host:5432/db",
				wantPrefix: "jdbc:postgresql://bob:",
				forbidden:  []string{"supersecret", "sslmode="},
			},
			{
				name:       "query parameter password in DSN",
				dsn:        "postgres://host:5432/db?password=querysecret&connect_timeout=5",
				wantPrefix: "postgres://host:5432/db?",
				forbidden:  []string{"querysecret", "sslmode="},
			},
			{
				name:        "key-value DSN redacted completely",
				dsn:         "host=localhost user=postgres password=kvsecret dbname=db",
				forbidden:   []string{"kvsecret"},
				wantLiteral: "[REDACTED]",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				cfg := Config{Storage: StorageConfig{DSN: tc.dsn}}
				result := printableConfig(cfg)
				for _, secret := range tc.forbidden {
					if strings.Contains(result.Storage.DSN, secret) {
						t.Fatalf("printableConfig() DSN = %q, leaked or injected %q", result.Storage.DSN, secret)
					}
				}
				if tc.wantLiteral != "" && result.Storage.DSN != tc.wantLiteral {
					t.Fatalf("printableConfig() DSN = %q, want %q", result.Storage.DSN, tc.wantLiteral)
				}
				if tc.wantPrefix != "" && !strings.HasPrefix(result.Storage.DSN, tc.wantPrefix) {
					t.Fatalf("printableConfig() DSN = %q, want prefix %q", result.Storage.DSN, tc.wantPrefix)
				}
				if cfg.Storage.DSN != tc.dsn {
					t.Fatalf("original config DSN mutated to %q", cfg.Storage.DSN)
				}
			})
		}
	})

	t.Run("printConfig redacts inline and query secrets from printed JSON", func(t *testing.T) {
		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		yamlBody := strings.Join([]string{
			"server:",
			"  port: 8080",
			"storage:",
			"  dsn: \"jdbc:postgresql://localhost:5432/scimplayground\"",
			"  username: \"scim_playground\"",
			"  password: \"yaml-db-secret\"",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(yamlBody), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		var out bytes.Buffer
		err := printConfig(&out, func(key string) (string, bool) {
			switch key {
			case "GO_CONFIG_DIR":
				return configDir, true
			case "GO_DATASOURCE_URL":
				return "postgres://bob:supersecret@host:5432/db?password=querysecret", true
			case "GO_CURSOR_SECRET":
				return "local-dev-cursor-secret-change-me-1234", true
			default:
				return "", false
			}
		})
		if err != nil {
			t.Fatalf("printConfig() error = %v", err)
		}

		rendered := out.String()
		for _, secret := range []string{"supersecret", "querysecret", "yaml-db-secret", "local-dev-cursor-secret-change-me-1234"} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("printConfig() output leaked %q:\n%s", secret, rendered)
			}
		}
		if !strings.Contains(rendered, `"Password": "***"`) {
			t.Fatalf("printConfig() output missing masked Password:\n%s", rendered)
		}
		if !strings.Contains(rendered, `"CursorSecret": "***"`) {
			t.Fatalf("printConfig() output missing masked CursorSecret:\n%s", rendered)
		}
	})
}

func TestServerBaseURLAndEnsureCursorSecret(t *testing.T) {
	t.Run("serverBaseURL defaults and overrides", func(t *testing.T) {
		cfg := Config{Server: ServerConfig{Port: 8181}}
		applyConfigDefaults(&cfg)
		if cfg.Server.BaseURL != "" {
			t.Fatalf("cfg.Server.BaseURL = %q, want empty string when not configured", cfg.Server.BaseURL)
		}
		if got := serverBaseURL(cfg); got != "http://localhost:8181" {
			t.Fatalf("serverBaseURL() = %q, want http://localhost:8181", got)
		}
		// Simulate SERVER_PORT override when BaseURL was not explicitly configured
		cfg.Server.Port = 9000
		if got := serverBaseURL(cfg); got != "http://localhost:9000" {
			t.Fatalf("serverBaseURL() after port override = %q, want http://localhost:9000", got)
		}

		// Explicit BaseURL set to http://localhost:8080 is preserved even if port changes
		cfgExplicitLocal := Config{Server: ServerConfig{Port: 8080, BaseURL: "http://localhost:8080"}}
		applyConfigDefaults(&cfgExplicitLocal)
		cfgExplicitLocal.Server.Port = 9000
		if got := serverBaseURL(cfgExplicitLocal); got != "http://localhost:8080" {
			t.Fatalf("serverBaseURL() with explicit localhost:8080 = %q, want http://localhost:8080", got)
		}

		cfgCustom := Config{Server: ServerConfig{Port: 8080, BaseURL: "https://scim.example.com/"}}
		applyConfigDefaults(&cfgCustom)
		if got := serverBaseURL(cfgCustom); got != "https://scim.example.com" {
			t.Fatalf("serverBaseURL() = %q, want https://scim.example.com", got)
		}

		cfgBad := Config{Server: ServerConfig{Port: 8080, BaseURL: "ftp://scim.example.com"}}
		if err := validateConfig(cfgBad); err == nil {
			t.Fatal("expected validateConfig error for non-http(s) base_url")
		}
	})

	t.Run("ensureCursorSecret uses configured secret without DB", func(t *testing.T) {
		cfg := Config{Server: ServerConfig{CursorSecret: "configured-cursor-secret-at-least-32-bytes"}}
		if err := ensureCursorSecret(cfg, nil); err != nil {
			t.Fatalf("ensureCursorSecret() error = %v", err)
		}
	})

	t.Run("ensureCursorSecret uses GO_CURSOR_SECRET from lookupEnv without DB", func(t *testing.T) {
		cfg := Config{}
		err := ensureCursorSecret(cfg, func(k string) (string, bool) {
			if k == "GO_CURSOR_SECRET" {
				return "env-cursor-secret-at-least-32-bytes-long", true
			}
			return "", false
		})
		if err != nil {
			t.Fatalf("ensureCursorSecret() error = %v", err)
		}
	})

	t.Run("rejects cursor secret shorter than minimum length", func(t *testing.T) {
		t.Setenv("GO_CURSOR_SECRET", "")
		shortCfg := Config{
			Server: ServerConfig{CursorSecret: "too-short-secret"},
			Cleanup: CleanupConfig{
				RequestLogs: CleanupRequestLogsConfig{Interval: time.Hour, MaxCount: 1000},
				AsyncEvents: CleanupAsyncEventsConfig{Interval: time.Hour, MaxCount: 1000, StalePendingAfter: time.Minute},
			},
		}
		if err := validateConfig(shortCfg); err == nil {
			t.Fatal("expected validateConfig error for cursor_secret shorter than 32 characters")
		}
		if err := ensureCursorSecret(shortCfg, nil); err == nil {
			t.Fatal("expected ensureCursorSecret error for cursor_secret shorter than 32 characters")
		}
		if err := ensureCursorSecret(Config{}, func(k string) (string, bool) {
			if k == "GO_CURSOR_SECRET" {
				return "short-env-secret", true
			}
			return "", false
		}); err == nil {
			t.Fatal("expected ensureCursorSecret error for GO_CURSOR_SECRET shorter than 32 characters")
		}
	})

	t.Run("ensureCursorSecret returns error when no secret is configured", func(t *testing.T) {
		t.Setenv("GO_CURSOR_SECRET", "")
		cfg := Config{}
		err := ensureCursorSecret(cfg, func(string) (string, bool) { return "", false })
		if err == nil {
			t.Fatal("expected ensureCursorSecret error when no cursor secret is configured")
		}
		if !strings.Contains(err.Error(), "GO_CURSOR_SECRET") {
			t.Fatalf("ensureCursorSecret() error = %q, want mention of GO_CURSOR_SECRET", err.Error())
		}
	})
}

func TestCleanupRequestLogsConfig(t *testing.T) {
	t.Parallel()

	t.Run("loads request logs cleanup config from YAML with env overrides", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		config := strings.Join([]string{
			"server:",
			"  port: 8080",
			"cleanup:",
			"  enabled: true",
			"  interval: 2h",
			"  stale_after: 2160h",
			"  request_logs:",
			"    enabled: true",
			"    interval: 1h",
			"    max_count: 5000",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		cfg, err := loadConfig(func(key string) (string, bool) {
			switch key {
			case "GO_CONFIG_DIR":
				return configDir, true
			case "GO_CLEANUP_REQUEST_LOGS_MAX_COUNT":
				return "15000", true
			case "GO_CLEANUP_REQUEST_LOGS_INTERVAL":
				return "30m", true
			default:
				return "", false
			}
		})
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.Cleanup.RequestLogs.Enabled == nil || !*cfg.Cleanup.RequestLogs.Enabled {
			t.Fatal("cfg.Cleanup.RequestLogs.Enabled = false or nil, want true")
		}
		if cfg.Cleanup.RequestLogs.MaxCount != 15000 {
			t.Fatalf("cfg.Cleanup.RequestLogs.MaxCount = %d, want 15000", cfg.Cleanup.RequestLogs.MaxCount)
		}
		if cfg.Cleanup.RequestLogs.Interval != 30*time.Minute {
			t.Fatalf("cfg.Cleanup.RequestLogs.Interval = %v, want 30m", cfg.Cleanup.RequestLogs.Interval)
		}
	})

	t.Run("applies default enabled, interval and max_count when request_logs omitted in YAML", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		config := strings.Join([]string{
			"server:",
			"  port: 8080",
			"cleanup:",
			"  enabled: true",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		cfg, err := loadConfig(func(key string) (string, bool) {
			if key == "GO_CONFIG_DIR" {
				return configDir, true
			}
			return "", false
		})
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.Cleanup.RequestLogs.Enabled == nil || !*cfg.Cleanup.RequestLogs.Enabled {
			t.Fatal("cfg.Cleanup.RequestLogs.Enabled should default to true when omitted")
		}
		if cfg.Cleanup.RequestLogs.MaxCount != 10000 {
			t.Fatalf("cfg.Cleanup.RequestLogs.MaxCount = %d, want 10000", cfg.Cleanup.RequestLogs.MaxCount)
		}
		if cfg.Cleanup.RequestLogs.Interval != time.Hour {
			t.Fatalf("cfg.Cleanup.RequestLogs.Interval = %v, want 1h", cfg.Cleanup.RequestLogs.Interval)
		}
	})

	t.Run("honors explicit false for request_logs enabled in YAML and via env", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		config := strings.Join([]string{
			"server:",
			"  port: 8080",
			"cleanup:",
			"  enabled: true",
			"  request_logs:",
			"    enabled: false",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		cfg, err := loadConfig(func(key string) (string, bool) {
			if key == "GO_CONFIG_DIR" {
				return configDir, true
			}
			return "", false
		})
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.Cleanup.RequestLogs.Enabled == nil || *cfg.Cleanup.RequestLogs.Enabled {
			t.Fatal("cfg.Cleanup.RequestLogs.Enabled = true, want explicit false")
		}

		// Also test env override to disable when YAML had true
		configWithTrue := strings.Replace(config, "enabled: false", "enabled: true", 1)
		if err := os.WriteFile(configPath, []byte(configWithTrue), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		cfgOverridden, err := loadConfig(func(key string) (string, bool) {
			switch key {
			case "GO_CONFIG_DIR":
				return configDir, true
			case "GO_CLEANUP_REQUEST_LOGS_ENABLED":
				return "false", true
			default:
				return "", false
			}
		})
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfgOverridden.Cleanup.RequestLogs.Enabled == nil || *cfgOverridden.Cleanup.RequestLogs.Enabled {
			t.Fatal("cfgOverridden.Cleanup.RequestLogs.Enabled = true, want env override to false")
		}
	})

	t.Run("returns error when request logs interval is negative", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		config := strings.Join([]string{
			"server:",
			"  port: 8080",
			"cleanup:",
			"  request_logs:",
			"    interval: -1h",
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
			t.Fatal("loadConfig() error = nil, want invalid interval error")
		}
		if !strings.Contains(err.Error(), "cleanup.request_logs.interval") {
			t.Fatalf("loadConfig() error = %q, want request logs interval validation message", err.Error())
		}
	})

	t.Run("returns error when request logs max_count is negative", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		config := strings.Join([]string{
			"server:",
			"  port: 8080",
			"cleanup:",
			"  request_logs:",
			"    max_count: -5",
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
			t.Fatal("loadConfig() error = nil, want invalid max_count error")
		}
		if !strings.Contains(err.Error(), "cleanup.request_logs.max_count") {
			t.Fatalf("loadConfig() error = %q, want request logs max_count validation message", err.Error())
		}
	})

	t.Run("loads cleanly without app-secrets.yaml and applies HTTP server timeout defaults", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		// Write ONLY app-conf.yaml (no app-secrets.yaml on disk) and omit server timeout fields to verify safe fallback defaults.
		configPath := filepath.Join(configDir, "app-conf.yaml")
		config := strings.Join([]string{
			"server:",
			"  port: 8080",
			"rate_limit:",
			"  enabled: true",
			"  requests_per_second: 500",
			"  burst: 50",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		cfg, err := loadConfig(func(key string) (string, bool) {
			switch key {
			case "GO_CONFIG_DIR":
				return configDir, true
			case "GO_DATASOURCE_URL":
				return "postgres://env_user:env_pass@db.internal:5432/scim", true
			case "GO_CURSOR_SECRET":
				return "env-provided-cursor-secret-at-least-32-chars", true
			default:
				return "", false
			}
		})
		if err != nil {
			t.Fatalf("loadConfig() without app-secrets.yaml failed: %v", err)
		}
		if cfg.RateLimit.Burst != 50 {
			t.Fatalf("cfg.RateLimit.Burst = %d, want 50", cfg.RateLimit.Burst)
		}
		if cfg.Server.ReadTimeout != defaultServerReadTimeout {
			t.Fatalf("ReadTimeout = %v, want %v", cfg.Server.ReadTimeout, defaultServerReadTimeout)
		}
		if cfg.Server.ReadHeaderTimeout != defaultServerReadHeaderTimeout {
			t.Fatalf("ReadHeaderTimeout = %v, want %v", cfg.Server.ReadHeaderTimeout, defaultServerReadHeaderTimeout)
		}
		if cfg.Server.WriteTimeout != defaultServerWriteTimeout {
			t.Fatalf("WriteTimeout = %v, want %v", cfg.Server.WriteTimeout, defaultServerWriteTimeout)
		}
		if cfg.Server.IdleTimeout != defaultServerIdleTimeout {
			t.Fatalf("IdleTimeout = %v, want %v", cfg.Server.IdleTimeout, defaultServerIdleTimeout)
		}
		if cfg.Server.ShutdownTimeout != defaultServerShutdownTimeout {
			t.Fatalf("ShutdownTimeout = %v, want %v", cfg.Server.ShutdownTimeout, defaultServerShutdownTimeout)
		}
	})

	t.Run("preserves explicit 0s HTTP server timeouts in YAML and environment overrides", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		yamlZero := strings.Join([]string{
			"server:",
			"  port: 8080",
			"  read_timeout: 0s",
			"  read_header_timeout: 0s",
			"  write_timeout: 0s",
			"  idle_timeout: 0s",
			"  shutdown_timeout: 0s",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(yamlZero), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		cfgYAMLZero, err := loadConfig(func(key string) (string, bool) {
			if key == "GO_CONFIG_DIR" {
				return configDir, true
			}
			return "", false
		})
		if err != nil {
			t.Fatalf("loadConfig(YAML 0s) error = %v", err)
		}
		if cfgYAMLZero.Server.ReadTimeout != 0 ||
			cfgYAMLZero.Server.ReadHeaderTimeout != 0 ||
			cfgYAMLZero.Server.WriteTimeout != 0 ||
			cfgYAMLZero.Server.IdleTimeout != 0 ||
			cfgYAMLZero.Server.ShutdownTimeout != 0 {
			t.Fatalf("expected all YAML 0s server timeouts to remain 0, got %+v", cfgYAMLZero.Server)
		}

		yamlNonZero := strings.Join([]string{
			"server:",
			"  port: 8080",
			"  read_timeout: 20s",
			"  read_header_timeout: 12s",
			"  write_timeout: 45s",
			"  idle_timeout: 90s",
			"  shutdown_timeout: 25s",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(yamlNonZero), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		cfgEnvZero, err := loadConfig(func(key string) (string, bool) {
			switch key {
			case "GO_CONFIG_DIR":
				return configDir, true
			case "GO_SERVER_READ_TIMEOUT",
				"GO_SERVER_READ_HEADER_TIMEOUT",
				"GO_SERVER_WRITE_TIMEOUT",
				"GO_SERVER_IDLE_TIMEOUT",
				"GO_SERVER_SHUTDOWN_TIMEOUT":
				return "0s", true
			default:
				return "", false
			}
		})
		if err != nil {
			t.Fatalf("loadConfig(env 0s) error = %v", err)
		}
		if cfgEnvZero.Server.ReadTimeout != 0 ||
			cfgEnvZero.Server.ReadHeaderTimeout != 0 ||
			cfgEnvZero.Server.WriteTimeout != 0 ||
			cfgEnvZero.Server.IdleTimeout != 0 ||
			cfgEnvZero.Server.ShutdownTimeout != 0 {
			t.Fatalf("expected all env 0s server timeouts to remain 0, got %+v", cfgEnvZero.Server)
		}

		// Verify shutdownContext does not immediately expire when ShutdownTimeout == 0.
		noTimeoutCtx, noTimeoutCancel := shutdownContext(context.Background(), 0)
		defer noTimeoutCancel()
		if _, hasDeadline := noTimeoutCtx.Deadline(); hasDeadline {
			t.Fatal("expected no deadline on shutdownContext when timeout == 0")
		}
		if err := noTimeoutCtx.Err(); err != nil {
			t.Fatalf("expected non-expired context when timeout == 0, got %v", err)
		}

		withTimeoutCtx, withTimeoutCancel := shutdownContext(context.Background(), 5*time.Second)
		defer withTimeoutCancel()
		if _, hasDeadline := withTimeoutCtx.Deadline(); !hasDeadline {
			t.Fatal("expected deadline on shutdownContext when timeout > 0")
		}
	})

	t.Run("rejects negative server timeouts and negative rate limit burst", func(t *testing.T) {
		t.Parallel()

		baseValid := func() Config {
			return Config{
				Cleanup: CleanupConfig{
					RequestLogs: CleanupRequestLogsConfig{Interval: time.Hour, MaxCount: 100},
					AsyncEvents: CleanupAsyncEventsConfig{Interval: time.Hour, MaxCount: 100, StalePendingAfter: time.Minute},
				},
			}
		}

		cases := []struct {
			name    string
			mutate  func(*Config)
			wantMsg string
		}{
			{"negative ReadTimeout", func(c *Config) { c.Server.ReadTimeout = -time.Second }, "server.read_timeout"},
			{"negative ReadHeaderTimeout", func(c *Config) { c.Server.ReadHeaderTimeout = -time.Second }, "server.read_header_timeout"},
			{"negative WriteTimeout", func(c *Config) { c.Server.WriteTimeout = -time.Second }, "server.write_timeout"},
			{"negative IdleTimeout", func(c *Config) { c.Server.IdleTimeout = -time.Second }, "server.idle_timeout"},
			{"negative ShutdownTimeout", func(c *Config) { c.Server.ShutdownTimeout = -time.Second }, "server.shutdown_timeout"},
			{"negative RateLimit.Burst", func(c *Config) { c.RateLimit.Burst = -1 }, "rate_limit.burst"},
			{"negative RateLimit.PerIPRequestsPerSecond", func(c *Config) { c.RateLimit.PerIPRequestsPerSecond = -0.5 }, "rate_limit.per_ip_requests_per_second"},
			{"negative RateLimit.PerIPBurst", func(c *Config) { c.RateLimit.PerIPBurst = -1 }, "rate_limit.per_ip_burst"},
			{"negative RateLimit.PerWorkspaceRequestsPerSecond", func(c *Config) { c.RateLimit.PerWorkspaceRequestsPerSecond = -1 }, "rate_limit.per_workspace_requests_per_second"},
			{"negative RateLimit.PerWorkspaceBurst", func(c *Config) { c.RateLimit.PerWorkspaceBurst = -2 }, "rate_limit.per_workspace_burst"},
			{"invalid RateLimit.TrustedProxies IP", func(c *Config) { c.RateLimit.TrustedProxies = "not-an-ip" }, "rate_limit.trusted_proxies"},
			{"invalid RateLimit.TrustedProxies CIDR", func(c *Config) { c.RateLimit.TrustedProxies = "10.0.0.0/99" }, "rate_limit.trusted_proxies"},
			{"NaN RateLimit.RequestsPerSecond", func(c *Config) { c.RateLimit.Enabled = true; c.RateLimit.RequestsPerSecond = math.NaN() }, "rate_limit.requests_per_second"},
			{"Inf RateLimit.RequestsPerSecond", func(c *Config) { c.RateLimit.Enabled = true; c.RateLimit.RequestsPerSecond = math.Inf(1) }, "rate_limit.requests_per_second"},
			{"negative disabled RateLimit.RequestsPerSecond", func(c *Config) { c.RateLimit.Enabled = false; c.RateLimit.RequestsPerSecond = -1 }, "rate_limit.requests_per_second"},
			{"NaN RateLimit.PerIPRequestsPerSecond", func(c *Config) { c.RateLimit.PerIPRequestsPerSecond = math.NaN() }, "rate_limit.per_ip_requests_per_second"},
			{"Inf RateLimit.PerIPRequestsPerSecond", func(c *Config) { c.RateLimit.PerIPRequestsPerSecond = math.Inf(1) }, "rate_limit.per_ip_requests_per_second"},
			{"NaN RateLimit.PerWorkspaceRequestsPerSecond", func(c *Config) { c.RateLimit.PerWorkspaceRequestsPerSecond = math.NaN() }, "rate_limit.per_workspace_requests_per_second"},
			{"Inf RateLimit.PerWorkspaceRequestsPerSecond", func(c *Config) { c.RateLimit.PerWorkspaceRequestsPerSecond = math.Inf(-1) }, "rate_limit.per_workspace_requests_per_second"},
		}

		for _, tc := range cases {
			cfg := baseValid()
			tc.mutate(&cfg)
			err := validateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("%s: validateConfig() = %v, want error containing %q", tc.name, err, tc.wantMsg)
			}
		}
	})

	t.Run("loads 3-tier rate limit settings from YAML and env overrides", func(t *testing.T) {
		t.Parallel()

		configDir := t.TempDir()
		configPath := filepath.Join(configDir, "app-conf.yaml")
		yamlText := strings.Join([]string{
			"server:",
			"  port: 8080",
			"rate_limit:",
			"  enabled: true",
			"  requests_per_second: 1000",
			"  burst: 100",
			"  per_ip_requests_per_second: 250",
			"  per_ip_burst: 50",
			"  per_workspace_requests_per_second: 250",
			"  per_workspace_burst: 50",
			"  trusted_proxies: \"10.0.0.0/8, 127.0.0.1\"",
			"  wait_timeout: 0s",
		}, "\n") + "\n"
		if err := os.WriteFile(configPath, []byte(yamlText), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", configPath, err)
		}

		cfg, err := loadConfig(func(key string) (string, bool) {
			switch key {
			case "GO_CONFIG_DIR":
				return configDir, true
			case "GO_RATE_LIMIT_PER_IP_REQUESTS_PER_SECOND":
				return "120.5", true
			case "GO_RATE_LIMIT_PER_IP_BURST":
				return "30", true
			case "GO_RATE_LIMIT_PER_WORKSPACE_REQUESTS_PER_SECOND":
				return "300", true
			case "GO_RATE_LIMIT_PER_WORKSPACE_BURST":
				return "60", true
			case "GO_RATE_LIMIT_TRUSTED_PROXIES":
				return "172.16.0.0/12, ::1", true
			default:
				return "", false
			}
		})
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}
		if cfg.RateLimit.PerIPRequestsPerSecond != 120.5 || cfg.RateLimit.PerIPBurst != 30 {
			t.Fatalf("PerIP = (%v, %d), want (120.5, 30)", cfg.RateLimit.PerIPRequestsPerSecond, cfg.RateLimit.PerIPBurst)
		}
		if cfg.RateLimit.PerWorkspaceRequestsPerSecond != 300 || cfg.RateLimit.PerWorkspaceBurst != 60 {
			t.Fatalf("PerWorkspace = (%v, %d), want (300, 60)", cfg.RateLimit.PerWorkspaceRequestsPerSecond, cfg.RateLimit.PerWorkspaceBurst)
		}
		if cfg.RateLimit.TrustedProxies != "172.16.0.0/12, ::1" {
			t.Fatalf("TrustedProxies = %q, want %q", cfg.RateLimit.TrustedProxies, "172.16.0.0/12, ::1")
		}
	})
}
