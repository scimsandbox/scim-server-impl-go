package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/logging"
)

// safeMockLogger is a thread-safe mock implementation of logging.Logger.
type safeMockLogger struct {
	mu     sync.Mutex
	errors []string
	infos  []string
}

func (m *safeMockLogger) Debug(_ string, _ ...logging.Field) {}
func (m *safeMockLogger) Warn(_ string, _ ...logging.Field)  {}
func (m *safeMockLogger) Flush() error                       { return nil }
func (m *safeMockLogger) With(_ ...logging.Field) logging.Logger {
	return m
}
func (m *safeMockLogger) Info(msg string, _ ...logging.Field) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.infos = append(m.infos, msg)
}
func (m *safeMockLogger) Error(msg string, _ ...logging.Field) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors = append(m.errors, msg)
}
func (m *safeMockLogger) ErrorCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.errors)
}
func (m *safeMockLogger) InfoCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.infos)
}

type deletionCall struct {
	WorkspaceID uuid.UUID
	MaxCount    int
}

type mockRequestLogDeleter struct {
	mu                sync.Mutex
	deleteFunc        func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error)
	listExceedingFunc func(ctx context.Context, maxCount int) ([]uuid.UUID, error)
	calls             []deletionCall
}

func (m *mockRequestLogDeleter) ListWorkspaceIDsExceedingLogCount(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listExceedingFunc != nil {
		return m.listExceedingFunc(ctx, maxCount)
	}
	return nil, nil
}

func (m *mockRequestLogDeleter) DeleteOldLogsForWorkspace(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
	m.mu.Lock()
	m.calls = append(m.calls, deletionCall{WorkspaceID: workspaceID, MaxCount: maxCount})
	m.mu.Unlock()
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, workspaceID, maxCount)
	}
	return 0, nil
}

func (m *mockRequestLogDeleter) getCalls() []deletionCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]deletionCall, len(m.calls))
	copy(result, m.calls)
	return result
}

func TestRequestLogCleanupService_Constructor_And_Defaults(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	logRepo := &mockRequestLogDeleter{}

	svc := NewRequestLogCleanupService(logRepo, logger, true, 0, 0)
	if svc == nil {
		t.Fatal("NewRequestLogCleanupService() returned nil")
	}
	if !svc.enabled {
		t.Fatal("svc.enabled = false, want true")
	}
	if svc.interval != DefaultRequestLogCleanupInterval {
		t.Fatalf("svc.interval = %v, want default %v", svc.interval, DefaultRequestLogCleanupInterval)
	}
	if svc.maxCount != DefaultRequestLogCleanupMaxCount {
		t.Fatalf("svc.maxCount = %d, want default %d", svc.maxCount, DefaultRequestLogCleanupMaxCount)
	}

	// Test custom values and non-positive overrides via constructor
	customSvc := NewRequestLogCleanupService(nil, logger, false, 2*time.Hour, 500)
	if customSvc.enabled {
		t.Fatal("customSvc.enabled = true, want false")
	}
	if customSvc.interval != 2*time.Hour {
		t.Fatalf("customSvc.interval = %v, want 2h", customSvc.interval)
	}
	if customSvc.maxCount != 500 {
		t.Fatalf("customSvc.maxCount = %d, want 500", customSvc.maxCount)
	}

	nonPositiveSvc := NewRequestLogCleanupService(nil, logger, true, -1, -1)
	if nonPositiveSvc.interval != DefaultRequestLogCleanupInterval {
		t.Fatalf("nonPositiveSvc.interval = %v after negative, want default", nonPositiveSvc.interval)
	}
	if nonPositiveSvc.maxCount != DefaultRequestLogCleanupMaxCount {
		t.Fatalf("nonPositiveSvc.maxCount = %d after negative, want default", nonPositiveSvc.maxCount)
	}
}

func TestRequestLogCleanupService_Lifecycle_StopOnContextCancel(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	logRepo := &mockRequestLogDeleter{}
	svc := NewRequestLogCleanupService(logRepo, logger, true, 24*time.Hour, 10000)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		svc.Start(ctx)
	}()

	cancel()

	select {
	case <-done:
		// Succeeded: Start returned cleanly on context cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not return after context cancellation")
	}
}

func TestRequestLogCleanupService_Lifecycle_TickerTrigger(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	wsID := uuid.New()

	var callCount atomic.Int32
	logRepo := &mockRequestLogDeleter{
		listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
			return []uuid.UUID{wsID}, nil
		},
		deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
			callCount.Add(1)
			return 1, nil
		},
	}

	svc := NewRequestLogCleanupService(logRepo, logger, true, 15*time.Millisecond, 10000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.Start(ctx)
	}()

	// Wait for ticker to fire at least twice
	deadline := time.After(2 * time.Second)
	for callCount.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for ticker triggers, got %d calls", callCount.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}

	cancel()

	select {
	case <-done:
		// Passed: clean termination
	case <-time.After(2 * time.Second):
		t.Fatal("Start() did not exit after context cancellation")
	}
}

func TestRequestLogCleanupService_DisabledToggle(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	logRepo := &mockRequestLogDeleter{
		listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
			t.Fatal("ListWorkspaceIDsExceedingLogCount should not be called when service is disabled")
			return nil, nil
		},
		deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
			t.Fatal("DeleteOldLogsForWorkspace should not be called when service is disabled")
			return 0, nil
		},
	}

	svc := NewRequestLogCleanupService(logRepo, logger, false, time.Hour, 10000)

	// 1. CleanupOnce returns (0, nil) immediately
	deleted, err := svc.CleanupOnce(context.Background())
	if err != nil {
		t.Fatalf("CleanupOnce() error = %v, want nil", err)
	}
	if deleted != 0 {
		t.Fatalf("CleanupOnce() deleted = %d, want 0", deleted)
	}

	// 2. Start returns immediately without waiting
	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.Start(context.Background())
	}()

	select {
	case <-done:
		// Passed: Start exited immediately when disabled
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Start() blocked when disabled")
	}
}

func TestRequestLogCleanupService_CleanupOnce_Success(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	ws1 := uuid.New()

	// Only ws1 has excess logs; ws2 is under threshold and omitted by listExceedingFunc
	logRepo := &mockRequestLogDeleter{
		listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
			return []uuid.UUID{ws1}, nil
		},
		deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
			if workspaceID == ws1 {
				return 15, nil
			}
			t.Fatalf("unexpected deletion call for workspace %v", workspaceID)
			return 0, nil
		},
	}

	svc := NewRequestLogCleanupService(logRepo, logger, true, time.Hour, 10000)

	deleted, err := svc.CleanupOnce(context.Background())
	if err != nil {
		t.Fatalf("CleanupOnce() error = %v, want nil", err)
	}
	if deleted != 15 {
		t.Fatalf("CleanupOnce() deleted = %d, want 15", deleted)
	}

	calls := logRepo.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 deletion call (only ws1), got %d", len(calls))
	}
	if calls[0].WorkspaceID != ws1 || calls[0].MaxCount != 10000 {
		t.Errorf("call[0] mismatch: %+v", calls[0])
	}

	if logger.InfoCount() == 0 {
		t.Error("expected info log when logs are deleted, got none")
	}
	if logger.ErrorCount() != 0 {
		t.Errorf("expected 0 error logs, got %d", logger.ErrorCount())
	}
}

func TestRequestLogCleanupService_PerWorkspaceIndependence_And_ErrorContainment(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	ws1 := uuid.New()
	ws2 := uuid.New()
	ws3 := uuid.New()

	dbErr := errors.New("database connection reset")
	logRepo := &mockRequestLogDeleter{
		listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
			return []uuid.UUID{ws1, ws2, ws3}, nil
		},
		deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
			switch workspaceID {
			case ws1:
				return 5, nil
			case ws2:
				return 0, dbErr
			case ws3:
				return 8, nil
			default:
				return 0, nil
			}
		},
	}

	svc := NewRequestLogCleanupService(logRepo, logger, true, time.Hour, 10000)

	deleted, err := svc.CleanupOnce(context.Background())
	if err != nil {
		t.Fatalf("CleanupOnce() error = %v, want nil (error should be contained)", err)
	}
	if deleted != 13 {
		t.Fatalf("CleanupOnce() deleted = %d, want 13 (5 + 8)", deleted)
	}

	calls := logRepo.getCalls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 deletion calls (ws2 failure must not stop ws3), got %d", len(calls))
	}

	if logger.ErrorCount() != 1 {
		t.Fatalf("expected 1 error log for failed workspace, got %d", logger.ErrorCount())
	}
}

func TestRequestLogCleanupService_ListExceedingWorkspaces_Error(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	expectedErr := errors.New("failed to query request logs table")

	logRepo := &mockRequestLogDeleter{
		listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
			return nil, expectedErr
		},
		deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
			t.Fatal("DeleteOldLogsForWorkspace should not be called when ListWorkspaceIDsExceedingLogCount fails")
			return 0, nil
		},
	}

	svc := NewRequestLogCleanupService(logRepo, logger, true, time.Hour, 10000)

	deleted, err := svc.CleanupOnce(context.Background())
	if err == nil {
		t.Fatal("CleanupOnce() error = nil, want error")
	}
	if !errors.Is(err, expectedErr) {
		t.Fatalf("CleanupOnce() error = %v, want %v", err, expectedErr)
	}
	if deleted != 0 {
		t.Fatalf("CleanupOnce() deleted = %d, want 0", deleted)
	}

	if logger.ErrorCount() != 1 {
		t.Fatalf("expected 1 error log, got %d", logger.ErrorCount())
	}
}

func TestRequestLogCleanupService_ContextCancelDuringIteration(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	ws1 := uuid.New()
	ws2 := uuid.New()
	ws3 := uuid.New()

	ctx, cancel := context.WithCancel(context.Background())

	logRepo := &mockRequestLogDeleter{
		listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
			return []uuid.UUID{ws1, ws2, ws3}, nil
		},
		deleteFunc: func(c context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
			if workspaceID == ws1 {
				cancel() // Cancel context during ws1 processing
				return 4, nil
			}
			t.Fatalf("workspace %v should not be processed after context cancellation", workspaceID)
			return 0, nil
		},
	}

	svc := NewRequestLogCleanupService(logRepo, logger, true, time.Hour, 10000)

	deleted, err := svc.CleanupOnce(ctx)
	if err == nil {
		t.Fatal("CleanupOnce() error = nil, want context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CleanupOnce() error = %v, want context.Canceled", err)
	}
	if deleted != 4 {
		t.Fatalf("CleanupOnce() deleted = %d, want 4", deleted)
	}
}

func TestRequestLogCleanupService_ContextAlreadyCancelled(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	logRepo := &mockRequestLogDeleter{}

	svc := NewRequestLogCleanupService(logRepo, logger, true, time.Hour, 10000)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	deleted, err := svc.CleanupOnce(ctx)
	if err == nil {
		t.Fatal("CleanupOnce() error = nil, want context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CleanupOnce() error = %v, want context.Canceled", err)
	}
	if deleted != 0 {
		t.Fatalf("CleanupOnce() deleted = %d, want 0", deleted)
	}
}
