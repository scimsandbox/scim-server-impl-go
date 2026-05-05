package configloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const applicationFileName = "application.yaml"

type testConfig struct {
	Service struct {
		Name string `yaml:"name"`
		Port int    `yaml:"port"`
		HTTP struct {
			ReadTimeout time.Duration `yaml:"read_timeout"`
		} `yaml:"http"`
	} `yaml:"service"`
	Database struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password" env:"DB_PASSWORD"`
	} `yaml:"database"`
	FeatureFlag bool `yaml:"feature_flag"`
}

func TestLoadMergesFilesIntoNestedStruct(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	baseFile := writeTestFile(t, dir, applicationFileName, `
service:
  name: demo-service
  port: 8080
  http:
    read_timeout: 5s
database:
  host: localhost
  port: 5432
  user: app
feature_flag: false
`)
	secretsFile := writeTestFile(t, dir, "secrets.yaml", `
database:
  password: from-file
service:
  http:
    read_timeout: 10s
feature_flag: true
`)

	cfg, err := Load[testConfig](LoadOptions{Files: []string{baseFile, secretsFile}})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Service.Name != "demo-service" {
		t.Fatalf("Service.Name = %q, want demo-service", cfg.Service.Name)
	}
	if cfg.Service.Port != 8080 {
		t.Fatalf("Service.Port = %d, want 8080", cfg.Service.Port)
	}
	if cfg.Service.HTTP.ReadTimeout != 10*time.Second {
		t.Fatalf("Service.HTTP.ReadTimeout = %s, want 10s", cfg.Service.HTTP.ReadTimeout)
	}
	if cfg.Database.Host != "localhost" {
		t.Fatalf("Database.Host = %q, want localhost", cfg.Database.Host)
	}
	if cfg.Database.Port != 5432 {
		t.Fatalf("Database.Port = %d, want 5432", cfg.Database.Port)
	}
	if cfg.Database.User != "app" {
		t.Fatalf("Database.User = %q, want app", cfg.Database.User)
	}
	if cfg.Database.Password != "from-file" {
		t.Fatalf("Database.Password = %q, want from-file", cfg.Database.Password)
	}
	if !cfg.FeatureFlag {
		t.Fatal("FeatureFlag = false, want true")
	}
}

func TestLoadAppliesEnvironmentOverrides(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configFile := writeTestFile(t, dir, applicationFileName, `
service:
  name: demo-service
  port: 8080
  http:
    read_timeout: 5s
database:
  host: localhost
  port: 5432
  user: app
  password: from-file
feature_flag: false
`)

	env := map[string]string{
		"APP_SERVICE_PORT":              "9090",
		"APP_SERVICE_HTTP_READ_TIMEOUT": "30s",
		"APP_DATABASE_HOST":             "db.internal",
		"DB_PASSWORD":                   "from-env",
		"APP_FEATURE_FLAG":              "true",
	}

	cfg, err := Load[testConfig](LoadOptions{
		Files:     []string{configFile},
		EnvPrefix: "APP_",
		LookupEnv: lookupFromMap(env),
	})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Service.Port != 9090 {
		t.Fatalf("Service.Port = %d, want 9090", cfg.Service.Port)
	}
	if cfg.Service.HTTP.ReadTimeout != 30*time.Second {
		t.Fatalf("Service.HTTP.ReadTimeout = %s, want 30s", cfg.Service.HTTP.ReadTimeout)
	}
	if cfg.Database.Host != "db.internal" {
		t.Fatalf("Database.Host = %q, want db.internal", cfg.Database.Host)
	}
	if cfg.Database.Password != "from-env" {
		t.Fatalf("Database.Password = %q, want from-env", cfg.Database.Password)
	}
	if !cfg.FeatureFlag {
		t.Fatal("FeatureFlag = false, want true")
	}
}

func TestLoadRejectsUnsupportedYAMLSequence(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configFile := writeTestFile(t, dir, applicationFileName, `
service:
  name: demo-service
  hosts:
    - a
    - b
`)

	_, err := Load[testConfig](LoadOptions{Files: []string{configFile}})
	if err == nil {
		t.Fatal("Load() error = nil, want unsupported YAML sequence error")
	}
	if !strings.Contains(err.Error(), "YAML sequences are not supported") {
		t.Fatalf("Load() error = %v, want sequence error", err)
	}
}

func TestLoadRejectsYAMLAnchorsAndMergeKeys(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configFile := writeTestFile(t, dir, applicationFileName, `
defaults: &defaults
  host: localhost
database:
  <<: *defaults
  port: 5432
`)

	_, err := Load[testConfig](LoadOptions{Files: []string{configFile}})
	if err == nil {
		t.Fatal("Load() error = nil, want unsupported YAML anchor error")
	}
	if !strings.Contains(err.Error(), "YAML anchors are not supported") {
		t.Fatalf("Load() error = %v, want anchor error", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configFile := writeTestFile(t, dir, applicationFileName, `
service:
  name: demo-service
unknown: value
`)

	_, err := Load[testConfig](LoadOptions{Files: []string{configFile}})
	if err == nil {
		t.Fatal("Load() error = nil, want unknown field error")
	}
	if !strings.Contains(err.Error(), "field unknown not found") {
		t.Fatalf("Load() error = %v, want unknown field error", err)
	}
}

func writeTestFile(t *testing.T, dir, name, contents string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.TrimSpace(contents)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}

func lookupFromMap(values map[string]string) LookupEnvFunc {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
