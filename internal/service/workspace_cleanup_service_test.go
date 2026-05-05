package service

import (
	"context"
	"testing"
	"time"

	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
)

// mockLogger is a minimal logging.Logger that captures logged messages.
type mockLogger struct {
	errors []string
	infos  []string
}

func (m *mockLogger) Debug(msg string, _ ...logging.Field) {}
func (m *mockLogger) Warn(msg string, _ ...logging.Field)  {}
func (m *mockLogger) Flush() error                         { return nil }
func (m *mockLogger) With(_ ...logging.Field) logging.Logger {
	return m
}
func (m *mockLogger) Info(msg string, _ ...logging.Field) {
	m.infos = append(m.infos, msg)
}
func (m *mockLogger) Error(msg string, _ ...logging.Field) {
	m.errors = append(m.errors, msg)
}

func TestWorkspaceCleanupService_Start_StopsOnContextCancel(t *testing.T) {
	t.Parallel()

	svc := NewWorkspaceCleanupService(repository.NewWorkspaceRepository(), &mockLogger{})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Use a very long interval so cleanup is never called before cancel.
		svc.Start(ctx, 24*time.Hour, 24*time.Hour)
	}()

	cancel()

	select {
	case <-done:
		// OK: Start() returned after context was cancelled
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not return after context cancellation")
	}
}

func TestWorkspaceCleanupService_cleanup_LogsErrorWhenRepoFails(t *testing.T) {
	t.Parallel()

	logger := &mockLogger{}
	svc := NewWorkspaceCleanupService(repository.NewWorkspaceRepository(), logger)

	// jdbc backend is not initialized, so DeleteStale will return an error.
	svc.cleanup(context.Background(), time.Hour)

	if len(logger.errors) == 0 {
		t.Fatal("expected error to be logged when jdbc is not initialized, got none")
	}
}

func TestNewWorkspaceCleanupService_FieldsSet(t *testing.T) {
	t.Parallel()

	repo := repository.NewWorkspaceRepository()
	logger := &mockLogger{}
	svc := NewWorkspaceCleanupService(repo, logger)

	if svc == nil {
		t.Fatal("NewWorkspaceCleanupService() returned nil")
	}
	if svc.workspaceRepo != repo {
		t.Error("workspaceRepo not set correctly")
	}
	if svc.logger != logger {
		t.Error("logger not set correctly")
	}
}
