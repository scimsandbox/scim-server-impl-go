package service

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

type asyncDeletionCall struct {
	WorkspaceID uuid.UUID
	MaxCount    int
}

type asyncTransitionCall struct {
	TxnID       uuid.UUID
	Payload     string
	CompletedAt time.Time
}

type mockAsyncEventPruner struct {
	mu                sync.Mutex
	deleteFunc        func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error)
	listExceedingFunc func(ctx context.Context, maxCount int) ([]uuid.UUID, error)
	findStaleFunc     func(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error)
	transitionFunc    func(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error)

	deletionCalls   []asyncDeletionCall
	transitionCalls []asyncTransitionCall
}

func (m *mockAsyncEventPruner) ListWorkspaceIDsExceedingEventCount(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listExceedingFunc != nil {
		return m.listExceedingFunc(ctx, maxCount)
	}
	return nil, nil
}

func (m *mockAsyncEventPruner) DeleteOldEventsForWorkspace(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
	m.mu.Lock()
	m.deletionCalls = append(m.deletionCalls, asyncDeletionCall{WorkspaceID: workspaceID, MaxCount: maxCount})
	m.mu.Unlock()
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, workspaceID, maxCount)
	}
	return 0, nil
}

func (m *mockAsyncEventPruner) FindStalePendingEvents(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.findStaleFunc != nil {
		return m.findStaleFunc(ctx, olderThan, limit)
	}
	return nil, nil
}

func (m *mockAsyncEventPruner) TransitionPendingToFailed(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error) {
	m.mu.Lock()
	m.transitionCalls = append(m.transitionCalls, asyncTransitionCall{
		TxnID:       txnID,
		Payload:     payload,
		CompletedAt: completedAt,
	})
	m.mu.Unlock()
	if m.transitionFunc != nil {
		return m.transitionFunc(ctx, txnID, payload, completedAt)
	}
	return true, nil
}

func (m *mockAsyncEventPruner) getDeletionCalls() []asyncDeletionCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]asyncDeletionCall, len(m.deletionCalls))
	copy(result, m.deletionCalls)
	return result
}

func (m *mockAsyncEventPruner) getTransitionCalls() []asyncTransitionCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]asyncTransitionCall, len(m.transitionCalls))
	copy(result, m.transitionCalls)
	return result
}

func TestAsyncEventCleanupService_Constructor_And_Defaults(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	pruner := &mockAsyncEventPruner{}

	svc := NewAsyncEventCleanupService(pruner, logger, true, 0, 0, 0)
	if svc == nil {
		t.Fatal("NewAsyncEventCleanupService() returned nil")
	}
	if !svc.enabled {
		t.Fatal("svc.enabled = false, want true")
	}
	if svc.interval != DefaultAsyncEventCleanupInterval {
		t.Fatalf("svc.interval = %v, want default %v", svc.interval, DefaultAsyncEventCleanupInterval)
	}
	if svc.maxCount != DefaultAsyncEventCleanupMaxCount {
		t.Fatalf("svc.maxCount = %d, want default %d", svc.maxCount, DefaultAsyncEventCleanupMaxCount)
	}
	if svc.stalePendingAfter != DefaultAsyncEventStalePendingAfter {
		t.Fatalf("svc.stalePendingAfter = %v, want default %v", svc.stalePendingAfter, DefaultAsyncEventStalePendingAfter)
	}

	// Custom and negative overrides
	customSvc := NewAsyncEventCleanupService(nil, logger, false, 2*time.Hour, 500, 10*time.Minute)
	if customSvc.enabled {
		t.Fatal("customSvc.enabled = true, want false")
	}
	if customSvc.interval != 2*time.Hour {
		t.Fatalf("customSvc.interval = %v, want 2h", customSvc.interval)
	}
	if customSvc.maxCount != 500 {
		t.Fatalf("customSvc.maxCount = %d, want 500", customSvc.maxCount)
	}
	if customSvc.stalePendingAfter != 10*time.Minute {
		t.Fatalf("customSvc.stalePendingAfter = %v, want 10m", customSvc.stalePendingAfter)
	}

	nonPositiveSvc := NewAsyncEventCleanupService(nil, logger, true, -1, -1, -1)
	if nonPositiveSvc.interval != DefaultAsyncEventCleanupInterval {
		t.Fatalf("nonPositiveSvc.interval = %v, want default", nonPositiveSvc.interval)
	}
	if nonPositiveSvc.maxCount != DefaultAsyncEventCleanupMaxCount {
		t.Fatalf("nonPositiveSvc.maxCount = %d, want default", nonPositiveSvc.maxCount)
	}
	if nonPositiveSvc.stalePendingAfter != DefaultAsyncEventStalePendingAfter {
		t.Fatalf("nonPositiveSvc.stalePendingAfter = %v, want default", nonPositiveSvc.stalePendingAfter)
	}
}

func TestAsyncEventCleanupService_Lifecycle_StopOnContextCancel(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	pruner := &mockAsyncEventPruner{}
	svc := NewAsyncEventCleanupService(pruner, logger, true, 24*time.Hour, 5000, 5*time.Minute)

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

func TestAsyncEventCleanupService_Lifecycle_TickerTrigger(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	wsID := uuid.New()

	var pruneCount atomic.Int32
	var reapCount atomic.Int32

	pruner := &mockAsyncEventPruner{
		listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
			return []uuid.UUID{wsID}, nil
		},
		deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
			pruneCount.Add(1)
			return 1, nil
		},
		findStaleFunc: func(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
			reapCount.Add(1)
			return nil, nil
		},
	}

	svc := NewAsyncEventCleanupService(pruner, logger, true, 15*time.Millisecond, 5000, 5*time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.Start(ctx)
	}()

	// Wait for ticker to fire at least twice
	deadline := time.After(2 * time.Second)
	for pruneCount.Load() < 2 || reapCount.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for ticker triggers, pruneCount=%d, reapCount=%d", pruneCount.Load(), reapCount.Load())
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

func TestAsyncEventCleanupService_DisabledToggle(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	pruner := &mockAsyncEventPruner{
		listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
			t.Fatal("ListWorkspaceIDsExceedingEventCount should not be called when disabled")
			return nil, nil
		},
		deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
			t.Fatal("DeleteOldEventsForWorkspace should not be called when disabled")
			return 0, nil
		},
		findStaleFunc: func(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
			t.Fatal("FindStalePendingEvents should not be called when disabled")
			return nil, nil
		},
	}

	svc := NewAsyncEventCleanupService(pruner, logger, false, time.Hour, 5000, 5*time.Minute)

	deleted, err := svc.CleanupTerminalOnce(context.Background())
	if err != nil || deleted != 0 {
		t.Fatalf("CleanupTerminalOnce() = (%d, %v), want (0, nil)", deleted, err)
	}

	reaped, err := svc.ReapStalePendingOnce(context.Background())
	if err != nil || reaped != 0 {
		t.Fatalf("ReapStalePendingOnce() = (%d, %v), want (0, nil)", reaped, err)
	}

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

func TestAsyncEventCleanupService_CleanupTerminalOnce_Success(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	ws1 := uuid.New()

	pruner := &mockAsyncEventPruner{
		listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
			return []uuid.UUID{ws1}, nil
		},
		deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
			if workspaceID == ws1 {
				return 10, nil
			}
			t.Fatalf("unexpected deletion call for workspace %v", workspaceID)
			return 0, nil
		},
	}

	svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)

	deleted, err := svc.CleanupTerminalOnce(context.Background())
	if err != nil {
		t.Fatalf("CleanupTerminalOnce() error = %v, want nil", err)
	}
	if deleted != 10 {
		t.Fatalf("CleanupTerminalOnce() deleted = %d, want 10", deleted)
	}

	calls := pruner.getDeletionCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 deletion call, got %d", len(calls))
	}
	if calls[0].WorkspaceID != ws1 || calls[0].MaxCount != 5000 {
		t.Errorf("call[0] mismatch: %+v", calls[0])
	}
}

func TestAsyncEventCleanupService_CleanupTerminalOnce_ErrorContainment(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	ws1 := uuid.New()
	ws2 := uuid.New()
	ws3 := uuid.New()

	dbErr := errors.New("simulated DB error")
	pruner := &mockAsyncEventPruner{
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

	svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)

	deleted, err := svc.CleanupTerminalOnce(context.Background())
	if err != nil {
		t.Fatalf("CleanupTerminalOnce() error = %v, want nil (error should be contained)", err)
	}
	if deleted != 13 {
		t.Fatalf("CleanupTerminalOnce() deleted = %d, want 13 (5 + 8)", deleted)
	}

	calls := pruner.getDeletionCalls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 deletion calls, got %d", len(calls))
	}
}

func TestAsyncEventCleanupService_ReapStalePendingOnce_Success(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	wsID := uuid.New()
	txn1 := uuid.New()
	resID1 := uuid.New()
	txn2 := uuid.New()

	staleEvent1 := &model.ScimAsyncEvent{
		TxnID:        txn1,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		ResourceID:   &resID1,
		Status:       model.AsyncStatusPending,
		CreatedAt:    time.Now().UTC().Add(-10 * time.Minute),
	}
	staleEvent2 := &model.ScimAsyncEvent{
		TxnID:        txn2,
		WorkspaceID:  wsID,
		Operation:    "DELETE",
		ResourceType: "Group",
		ResourceID:   nil,
		Status:       model.AsyncStatusPending,
		CreatedAt:    time.Now().UTC().Add(-15 * time.Minute),
	}

	pruner := &mockAsyncEventPruner{
		findStaleFunc: func(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
			return []*model.ScimAsyncEvent{staleEvent1, staleEvent2}, nil
		},
		transitionFunc: func(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error) {
			return true, nil
		},
	}

	svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)

	reaped, err := svc.ReapStalePendingOnce(context.Background())
	if err != nil {
		t.Fatalf("ReapStalePendingOnce() error = %v, want nil", err)
	}
	if reaped != 2 {
		t.Fatalf("ReapStalePendingOnce() reaped = %d, want 2", reaped)
	}

	calls := pruner.getTransitionCalls()
	if len(calls) != 2 {
		t.Fatalf("expected 2 transition calls, got %d", len(calls))
	}

	// Verify SET structure of call 0
	var payloadMap map[string]any
	if err := json.Unmarshal([]byte(calls[0].Payload), &payloadMap); err != nil {
		t.Fatalf("failed to parse SET payload: %v", err)
	}
	if payloadMap["txn"] != txn1.String() {
		t.Errorf("payload txn = %v, want %v", payloadMap["txn"], txn1)
	}
	eventsMap, ok := payloadMap["events"].(map[string]any)
	if !ok {
		t.Fatalf("payload missing events object: %+v", payloadMap)
	}
	asyncResp, ok := eventsMap["urn:ietf:params:scim:event:misc:asyncresp"].(map[string]any)
	if !ok {
		t.Fatalf("payload missing asyncresp: %+v", eventsMap)
	}
	if asyncResp["status"] != "500" {
		t.Errorf("asyncResp status = %v, want 500", asyncResp["status"])
	}
	if asyncResp["method"] != "POST" {
		t.Errorf("asyncResp method = %v, want POST", asyncResp["method"])
	}
	respObj, ok := asyncResp["response"].(map[string]any)
	if !ok {
		t.Fatalf("asyncResp missing response object: %+v", asyncResp)
	}
	if respObj["detail"] != StalePendingTimeoutDetail {
		t.Errorf("resp detail = %v, want %q", respObj["detail"], StalePendingTimeoutDetail)
	}
}

func TestAsyncEventCleanupService_ReapStalePendingOnce_ErrorContainment(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	wsID := uuid.New()
	txn1 := uuid.New()
	txn2 := uuid.New()

	event1 := &model.ScimAsyncEvent{
		TxnID:        txn1,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusPending,
	}
	event2 := &model.ScimAsyncEvent{
		TxnID:        txn2,
		WorkspaceID:  wsID,
		Operation:    "PUT",
		ResourceType: "User",
		Status:       model.AsyncStatusPending,
	}

	pruner := &mockAsyncEventPruner{
		findStaleFunc: func(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
			return []*model.ScimAsyncEvent{event1, event2}, nil
		},
		transitionFunc: func(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error) {
			if txnID == txn1 {
				return false, errors.New("transition failed")
			}
			return true, nil
		},
	}

	svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)

	reaped, err := svc.ReapStalePendingOnce(context.Background())
	if err != nil {
		t.Fatalf("ReapStalePendingOnce() error = %v, want nil", err)
	}
	if reaped != 1 {
		t.Fatalf("ReapStalePendingOnce() reaped = %d, want 1", reaped)
	}
}

func TestBuildStalePendingErrorSET_Properties(t *testing.T) {
	t.Parallel()

	wsID := uuid.New()
	txnID := uuid.New()
	resID := uuid.New()

	event := &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID,
		Operation:    "patch",
		ResourceType: "Group",
		ResourceID:   &resID,
		Status:       model.AsyncStatusPending,
	}

	setJSON := BuildStalePendingErrorSET(event)
	if setJSON == "" {
		t.Fatal("BuildStalePendingErrorSET returned empty string")
	}

	var m map[string]any
	if err := json.Unmarshal([]byte(setJSON), &m); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if m["txn"] != txnID.String() {
		t.Errorf("txn = %v, want %v", m["txn"], txnID)
	}
	subID, ok := m["sub_id"].(map[string]any)
	if !ok {
		t.Fatalf("sub_id missing or not map: %+v", m)
	}
	expectedURI := "http://localhost:8080/ws/" + wsID.String() + "/scim/v2/Groups/" + resID.String()
	if subID["uri"] != expectedURI {
		t.Errorf("sub_id.uri = %v, want %v", subID["uri"], expectedURI)
	}

	// Verify configured baseOrigin is used when provided
	customOrigin := "https://scim.tenant.example.com"
	eventForCustom := &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID,
		Operation:    "PUT",
		ResourceType: "User",
		ResourceID:   &resID,
		Status:       model.AsyncStatusPending,
	}
	setJSONCustom := BuildStalePendingErrorSET(eventForCustom, customOrigin)
	var mCustom map[string]any
	if err := json.Unmarshal([]byte(setJSONCustom), &mCustom); err != nil {
		t.Fatalf("unmarshal custom SET error: %v", err)
	}
	wantCustomBaseURL := customOrigin + "/ws/" + wsID.String() + "/scim/v2"
	if mCustom["iss"] != wantCustomBaseURL {
		t.Errorf("custom iss = %v, want %v", mCustom["iss"], wantCustomBaseURL)
	}
	subIDCustom, _ := mCustom["sub_id"].(map[string]any)
	wantCustomURI := wantCustomBaseURL + "/Users/" + resID.String()
	if subIDCustom["uri"] != wantCustomURI {
		t.Errorf("custom sub_id.uri = %v, want %v", subIDCustom["uri"], wantCustomURI)
	}
}
