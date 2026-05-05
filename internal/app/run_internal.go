package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/scimsandbox/scim-server-impl-go/internal/configloader"
	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/messages"
)

func loadConfig(lookupEnv LookupEnvFunc) (Config, error) {
	configDir := "config"
	if envDir, ok := lookupEnv("GO_CONFIG_DIR"); ok {
		configDir = envDir
	}

	mainFile := filepath.Join(configDir, "app-conf.yaml")
	if _, err := os.Stat(mainFile); err != nil {
		if os.IsNotExist(err) {
			return Config{}, fmt.Errorf("config file not found: %s", mainFile)
		}
		return Config{}, fmt.Errorf("error checking %s: %w", mainFile, err)
	}

	files := resolveConfigFiles(configDir)

	cfg, err := configloader.Load[Config](configloader.LoadOptions{
		Files:     files,
		EnvPrefix: "GO_",
		LookupEnv: configloader.LookupEnvFunc(lookupEnv),
	})
	if err != nil {
		return Config{}, err
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func resolveConfigFiles(configDir string) []string {
	var files []string

	mainFile := filepath.Join(configDir, "app-conf.yaml")
	if _, err := os.Stat(mainFile); err == nil {
		files = append(files, mainFile)
	}

	secretsFile := filepath.Join(configDir, "app-secrets.yaml")
	if _, err := os.Stat(secretsFile); err == nil {
		files = append(files, secretsFile)
	}

	return files
}

func healthcheck(lookupEnv LookupEnvFunc) error {
	cfg, err := loadConfig(lookupEnv)
	if err != nil {
		return err
	}
	port := managementPort(cfg)

	url := fmt.Sprintf("http://127.0.0.1:%d/actuator/health", port)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("healthcheck failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("healthcheck failed: status %d", resp.StatusCode)
	}
	return nil
}

func printConfig(stdout io.Writer, lookupEnv LookupEnvFunc) error {
	cfg, err := loadConfig(lookupEnv)
	if err != nil {
		return err
	}

	printable := printableConfig(cfg)
	data, err := json.MarshalIndent(printable, "", "  ")
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(stdout, string(data))
	return err
}

func setupLogger(cfg Config, writer io.Writer) logging.Logger {
	return logging.NewLogger(logging.Config{
		Writer: writer,
		Level:  cfg.Logging.Level,
	})
}

func setupLocalizer(cfg Config) messages.Localizer {
	return messages.New(cfg.Messages)
}
