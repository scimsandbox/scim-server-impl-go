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
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const localFlywayImageTag = "scim-server-db:test"

var (
	buildFlywayImageOnce sync.Once
	buildFlywayImageErr  error
)

func ApplyScimServerDBMigrations(t testing.TB, ctx context.Context, postgresURL string) {
	t.Helper()

	if err := waitForPostgresReady(ctx, postgresURL); err != nil {
		t.Fatalf("wait for postgres readiness before Flyway migrations: %v", err)
	}

	jdbcURL, username, password, pgContainerID, err := flywayConnection(ctx, postgresURL)
	if err != nil {
		t.Fatalf("build Flyway connection: %v", err)
	}

	buildFlywayImageOnce.Do(func() {
		buildFlywayImageErr = buildLocalFlywayImage(ctx)
	})
	if buildFlywayImageErr != nil {
		t.Fatalf("build scim-server-db image: %v", buildFlywayImageErr)
	}

	var lastOutput []byte
	var lastErr error
	for attempt := 1; attempt <= 2; attempt++ {
		if ctx.Err() != nil {
			t.Fatalf("context canceled before Flyway attempt %d: %v", attempt, ctx.Err())
		}
		containerName := "scim-flyway-" + uuid.NewString()
		attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		args := []string{
			"run",
			"--rm",
			"--name",
			containerName,
		}
		if pgContainerID != "" {
			args = append(args, "--network", "container:"+pgContainerID)
		} else {
			args = append(args, "--add-host", "host.docker.internal:host-gateway")
		}
		args = append(args,
			"-e",
			"FLYWAY_CHECK_FOR_UPDATES=false",
			"-e",
			"FLYWAY_CONNECT_RETRIES=5",
			"-e",
			"FLYWAY_CONNECT_RETRIES_INTERVAL=1",
			"-e",
			"FLYWAY_URL="+jdbcURL,
			"-e",
			"FLYWAY_USER="+username,
			"-e",
			"FLYWAY_PASSWORD="+password,
			localFlywayImageTag,
		)
		command := exec.CommandContext(attemptCtx, "docker", args...)

		output, runErr := command.CombinedOutput()
		timedOut := attemptCtx.Err() == context.DeadlineExceeded
		cancel()
		if timedOut {
			_ = exec.Command("docker", "rm", "-f", containerName).Run()
		}
		if runErr == nil {
			return
		}
		lastOutput = output
		lastErr = runErr
		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("run scim-server-db migrations: %v\n%s", lastErr, strings.TrimSpace(string(lastOutput)))
}

func waitForPostgresReady(ctx context.Context, postgresURL string) error {
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var lastErr error
	for {
		if waitCtx.Err() != nil {
			return fmt.Errorf("postgres not ready at %s: %w (last error: %v)", postgresURL, waitCtx.Err(), lastErr)
		}
		attemptCtx, attemptCancel := context.WithTimeout(waitCtx, 2*time.Second)
		conn, err := pgx.Connect(attemptCtx, postgresURL)
		if err == nil {
			var one int
			err = conn.QueryRow(attemptCtx, "SELECT 1").Scan(&one)
			_ = conn.Close(attemptCtx)
			attemptCancel()
			if err == nil && one == 1 {
				return nil
			}
			lastErr = err
		} else {
			attemptCancel()
			lastErr = err
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("postgres not ready at %s: %w (last error: %v)", postgresURL, waitCtx.Err(), lastErr)
		case <-time.After(250 * time.Millisecond):
		}
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

func findPostgresContainerByPublishedPort(ctx context.Context, port string) string {
	if port == "" || port == "5432" {
		return ""
	}
	psCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(
		psCtx,
		"docker",
		"ps",
		"--filter", "status=running",
		"--format", "{{.ID}}\t{{.Ports}}",
	).Output()
	if err != nil {
		return ""
	}

	needle := ":" + port + "->5432/"
	var matches []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		id, ports, ok := strings.Cut(line, "\t")
		if ok && id != "" && strings.Contains(ports, needle) {
			matches = append(matches, strings.TrimSpace(id))
		}
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return ""
}

func flywayConnection(ctx context.Context, postgresURL string) (string, string, string, string, error) {
	parsed, err := url.Parse(postgresURL)
	if err != nil {
		return "", "", "", "", err
	}

	username := parsed.User.Username()
	password, _ := parsed.User.Password()
	if username == "" {
		return "", "", "", "", fmt.Errorf("postgres URL missing username")
	}

	database := strings.TrimPrefix(parsed.Path, "/")
	if database == "" {
		return "", "", "", "", fmt.Errorf("postgres URL missing database name")
	}

	port := parsed.Port()
	if port == "" {
		port = "5432"
	}

	var pgContainerID string
	hostName := strings.ToLower(parsed.Hostname())
	if hostName == "" || hostName == "localhost" || hostName == "127.0.0.1" || hostName == "::1" || hostName == "0.0.0.0" {
		pgContainerID = findPostgresContainerByPublishedPort(ctx, port)
	}

	jdbcHostPort := "host.docker.internal:" + port
	if pgContainerID != "" {
		jdbcHostPort = "127.0.0.1:5432"
	}

	jdbcURL := fmt.Sprintf("jdbc:postgresql://%s/%s", jdbcHostPort, database)
	q := parsed.Query()
	if !q.Has("connectTimeout") {
		q.Set("connectTimeout", "5")
	}
	if !q.Has("socketTimeout") {
		q.Set("socketTimeout", "15")
	}
	if !q.Has("loginTimeout") {
		q.Set("loginTimeout", "5")
	}
	if query := q.Encode(); query != "" {
		jdbcURL += "?" + query
	}

	return jdbcURL, username, password, pgContainerID, nil
}
