package testsupport

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const localFlywayImageTag = "scim-server-db:test"

var (
	buildFlywayImageOnce sync.Once
	buildFlywayImageErr  error
)

func ApplyScimServerDBMigrations(t testing.TB, ctx context.Context, postgresURL string) {
	t.Helper()

	jdbcURL, username, password, err := flywayConnection(postgresURL)
	if err != nil {
		t.Fatalf("build Flyway connection: %v", err)
	}

	buildFlywayImageOnce.Do(func() {
		buildFlywayImageErr = buildLocalFlywayImage(ctx)
	})
	if buildFlywayImageErr != nil {
		t.Fatalf("build scim-server-db image: %v", buildFlywayImageErr)
	}

	command := exec.CommandContext(
		ctx,
		"docker",
		"run",
		"--rm",
		"--add-host",
		"host.docker.internal:host-gateway",
		"-e",
		"FLYWAY_URL="+jdbcURL,
		"-e",
		"FLYWAY_USER="+username,
		"-e",
		"FLYWAY_PASSWORD="+password,
		localFlywayImageTag,
	)

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run scim-server-db migrations: %v\n%s", err, strings.TrimSpace(string(output)))
	}
}

func buildLocalFlywayImage(ctx context.Context) error {
	modulePath, err := scimServerDBModulePath()
	if err != nil {
		return err
	}

	command := exec.CommandContext(ctx, "docker", "build", "-t", localFlywayImageTag, modulePath)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker build: %w\n%s", err, strings.TrimSpace(string(output)))
	}

	return nil
}

func scimServerDBModulePath() (string, error) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("resolve current file")
	}

	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	modulePath := filepath.Join(repoRoot, "..", "scim-server-db")
	if _, err := os.Stat(modulePath); err != nil {
		return "", fmt.Errorf("locate scim-server-db module: %w", err)
	}

	return modulePath, nil
}

func flywayConnection(postgresURL string) (string, string, string, error) {
	parsed, err := url.Parse(postgresURL)
	if err != nil {
		return "", "", "", err
	}

	username := parsed.User.Username()
	password, _ := parsed.User.Password()
	if username == "" {
		return "", "", "", fmt.Errorf("postgres URL missing username")
	}

	database := strings.TrimPrefix(parsed.Path, "/")
	if database == "" {
		return "", "", "", fmt.Errorf("postgres URL missing database name")
	}

	port := parsed.Port()
	if port == "" {
		port = "5432"
	}

	jdbcURL := fmt.Sprintf("jdbc:postgresql://host.docker.internal:%s/%s", port, database)
	if query := parsed.Query().Encode(); query != "" {
		jdbcURL += "?" + query
	}

	return jdbcURL, username, password, nil
}
