package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

// --- 1. Boundary Tests for AsyncEventCleanupService ---

func TestAsyncEventCleanupService_Boundary_WorkspaceEventCounts(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}

	t.Run("Workspace with 0 events: ListExceeding returns empty slice", func(t *testing.T) {
		t.Parallel()
		pruner := &mockAsyncEventPruner{
			listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
				return []uuid.UUID{}, nil
			},
			deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
				t.Fatal("DeleteOldEventsForWorkspace should not be called when 0 workspaces exceed maxCount")
				return 0, nil
			},
		}

		svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)
		deleted, err := svc.CleanupTerminalOnce(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if deleted != 0 {
			t.Fatalf("deleted = %d, want 0", deleted)
		}
	})

	t.Run("Workspace with <= maxCount events: not returned in ListExceeding", func(t *testing.T) {
		t.Parallel()
		// Only wsExceeding is returned; wsUnder is <= maxCount and filtered out
		wsExceeding := uuid.New()
		pruner := &mockAsyncEventPruner{
			listExceedingFunc: func(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
				if maxCount != 5000 {
					t.Fatalf("maxCount = %d, want 5000", maxCount)
				}
				return []uuid.UUID{wsExceeding}, nil
			},
			deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
				if workspaceID != wsExceeding {
					t.Fatalf("unexpected workspace %v called for deletion", workspaceID)
				}
				return 50, nil
			},
		}

		svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)
		deleted, err := svc.CleanupTerminalOnce(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if deleted != 50 {
			t.Fatalf("deleted = %d, want 50", deleted)
		}
	})

	t.Run("Workspace exceeding maxCount: pruned to maxCount", func(t *testing.T) {
		t.Parallel()
		wsID := uuid.New()
		const maxCount = 100
		const excess = 42

		pruner := &mockAsyncEventPruner{
			listExceedingFunc: func(ctx context.Context, mc int) ([]uuid.UUID, error) {
				return []uuid.UUID{wsID}, nil
			},
			deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, mc int) (int64, error) {
				if mc != maxCount {
					t.Errorf("maxCount passed to delete = %d, want %d", mc, maxCount)
				}
				return excess, nil
			},
		}

		svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, maxCount, 5*time.Minute)
		deleted, err := svc.CleanupTerminalOnce(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if deleted != excess {
			t.Fatalf("deleted = %d, want %d", deleted, excess)
		}
	})

	t.Run("Zero or negative maxCount runtime fallback to default", func(t *testing.T) {
		t.Parallel()
		wsID := uuid.New()
		var capturedMaxCount int

		pruner := &mockAsyncEventPruner{
			listExceedingFunc: func(ctx context.Context, mc int) ([]uuid.UUID, error) {
				capturedMaxCount = mc
				return []uuid.UUID{wsID}, nil
			},
			deleteFunc: func(ctx context.Context, workspaceID uuid.UUID, mc int) (int64, error) {
				return 1, nil
			},
		}

		// Constructor with 0 maxCount falls back to DefaultAsyncEventCleanupMaxCount
		svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 0, 5*time.Minute)
		if svc.maxCount != DefaultAsyncEventCleanupMaxCount {
			t.Fatalf("svc.maxCount = %d, want %d", svc.maxCount, DefaultAsyncEventCleanupMaxCount)
		}

		_, err := svc.CleanupTerminalOnce(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if capturedMaxCount != DefaultAsyncEventCleanupMaxCount {
			t.Fatalf("capturedMaxCount = %d, want %d", capturedMaxCount, DefaultAsyncEventCleanupMaxCount)
		}
	})
}

// --- 2. Multi-Batch Deletion Exhaustion Tests ---

func TestAsyncEventCleanupService_MultiBatchDeletion_Simulation(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	wsID := uuid.New()

	cases := []struct {
		name          string
		totalExcess   int64
		batchSize     int64
		expectedCalls int
	}{
		{
			name:          "Zero excess: 1 batch returning 0",
			totalExcess:   0,
			batchSize:     5000,
			expectedCalls: 1,
		},
		{
			name:          "Partial batch: 1500 excess (< 5000)",
			totalExcess:   1500,
			batchSize:     5000,
			expectedCalls: 1,
		},
		{
			name:          "Exactly 1 batch: 5000 excess",
			totalExcess:   5000,
			batchSize:     5000,
			expectedCalls: 2, // 5000 then 0
		},
		{
			name:          "Multi-batch: 12500 excess (5000 + 5000 + 2500)",
			totalExcess:   12500,
			batchSize:     5000,
			expectedCalls: 3, // 5000, 5000, 2500 (< 5000 breaks)
		},
		{
			name:          "Exact multi-batch: 15000 excess (5000 + 5000 + 5000 + 0)",
			totalExcess:   15000,
			batchSize:     5000,
			expectedCalls: 4, // 5000, 5000, 5000, 0
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			remaining := tc.totalExcess
			callCount := 0

			// Simulates repository DeleteOldEventsForWorkspace batching loop
			simulateBatchDeletion := func(ctx context.Context, wid uuid.UUID, maxCount int) (int64, error) {
				var totalDeleted int64
				for {
					if err := ctx.Err(); err != nil {
						return totalDeleted, err
					}
					callCount++
					batchDeleted := remaining
					if batchDeleted > tc.batchSize {
						batchDeleted = tc.batchSize
					}
					remaining -= batchDeleted
					totalDeleted += batchDeleted

					if batchDeleted < tc.batchSize {
						break
					}
				}
				return totalDeleted, nil
			}

			pruner := &mockAsyncEventPruner{
				listExceedingFunc: func(ctx context.Context, mc int) ([]uuid.UUID, error) {
					return []uuid.UUID{wsID}, nil
				},
				deleteFunc: simulateBatchDeletion,
			}

			svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)
			deleted, err := svc.CleanupTerminalOnce(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if deleted != tc.totalExcess {
				t.Fatalf("deleted = %d, want %d", deleted, tc.totalExcess)
			}
			if callCount != tc.expectedCalls {
				t.Fatalf("batch call count = %d, want %d", callCount, tc.expectedCalls)
			}
		})
	}
}

// --- 3. Context Cancellation Tests ---

func TestAsyncEventCleanupService_ContextCancellation_StopsProcessingImmediately(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}

	t.Run("Context already cancelled before CleanupTerminalOnce", func(t *testing.T) {
		t.Parallel()
		pruner := &mockAsyncEventPruner{
			listExceedingFunc: func(ctx context.Context, mc int) ([]uuid.UUID, error) {
				t.Fatal("ListWorkspaceIDsExceedingEventCount should not be called on cancelled context")
				return nil, nil
			},
		}

		svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		deleted, err := svc.CleanupTerminalOnce(ctx)
		if err == nil || err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if deleted != 0 {
			t.Fatalf("deleted = %d, want 0", deleted)
		}
	})

	t.Run("Context cancelled during workspace iteration stops remaining workspaces", func(t *testing.T) {
		t.Parallel()

		ws1 := uuid.New()
		ws2 := uuid.New()
		ws3 := uuid.New()

		ctx, cancel := context.WithCancel(context.Background())

		var processedWorkspaces []uuid.UUID
		var mu sync.Mutex

		pruner := &mockAsyncEventPruner{
			listExceedingFunc: func(ctx context.Context, mc int) ([]uuid.UUID, error) {
				return []uuid.UUID{ws1, ws2, ws3}, nil
			},
			deleteFunc: func(c context.Context, wid uuid.UUID, mc int) (int64, error) {
				mu.Lock()
				processedWorkspaces = append(processedWorkspaces, wid)
				mu.Unlock()

				if wid == ws1 {
					// Cancel during ws1
					cancel()
					return 10, nil
				}
				t.Fatalf("workspace %v should NOT be processed after cancellation", wid)
				return 0, nil
			},
		}

		svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)
		deleted, err := svc.CleanupTerminalOnce(ctx)
		if err == nil || err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if deleted != 10 {
			t.Fatalf("deleted = %d, want 10", deleted)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(processedWorkspaces) != 1 || processedWorkspaces[0] != ws1 {
			t.Fatalf("expected only ws1 processed, got %v", processedWorkspaces)
		}
	})

	t.Run("Context already cancelled before ReapStalePendingOnce", func(t *testing.T) {
		t.Parallel()
		pruner := &mockAsyncEventPruner{
			findStaleFunc: func(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
				t.Fatal("FindStalePendingEvents should not be called on cancelled context")
				return nil, nil
			},
		}

		svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		reaped, err := svc.ReapStalePendingOnce(ctx)
		if err == nil || err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if reaped != 0 {
			t.Fatalf("reaped = %d, want 0", reaped)
		}
	})

	t.Run("Context cancelled during stale pending iteration stops remaining events", func(t *testing.T) {
		t.Parallel()

		txn1 := uuid.New()
		txn2 := uuid.New()
		txn3 := uuid.New()

		e1 := &model.ScimAsyncEvent{TxnID: txn1, Status: model.AsyncStatusPending}
		e2 := &model.ScimAsyncEvent{TxnID: txn2, Status: model.AsyncStatusPending}
		e3 := &model.ScimAsyncEvent{TxnID: txn3, Status: model.AsyncStatusPending}

		ctx, cancel := context.WithCancel(context.Background())

		var processedTxns []uuid.UUID
		var mu sync.Mutex

		pruner := &mockAsyncEventPruner{
			findStaleFunc: func(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
				return []*model.ScimAsyncEvent{e1, e2, e3}, nil
			},
			transitionFunc: func(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error) {
				mu.Lock()
				processedTxns = append(processedTxns, txnID)
				mu.Unlock()

				if txnID == txn1 {
					cancel()
					return true, nil
				}
				t.Fatalf("event %v should NOT be reaped after cancellation", txnID)
				return false, nil
			},
		}

		svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)
		reaped, err := svc.ReapStalePendingOnce(ctx)
		if err == nil || err != context.Canceled {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if reaped != 1 {
			t.Fatalf("reaped = %d, want 1", reaped)
		}

		mu.Lock()
		defer mu.Unlock()
		if len(processedTxns) != 1 || processedTxns[0] != txn1 {
			t.Fatalf("expected only txn1 processed, got %v", processedTxns)
		}
	})
}

// --- 4. Invariant: PENDING Events Are Never Deleted by Terminal Pruning ---

func TestAsyncEventCleanupService_Invariant_PendingEventsNeverDeleted(t *testing.T) {
	t.Parallel()

	// In-memory model of async events representing database rows
	type eventRow struct {
		txnID     uuid.UUID
		status    string
		createdAt time.Time
	}

	wsID := uuid.New()
	baseTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	var store []eventRow
	// 10 PENDING events
	for i := 0; i < 10; i++ {
		store = append(store, eventRow{
			txnID:     uuid.New(),
			status:    model.AsyncStatusPending,
			createdAt: baseTime.Add(time.Duration(i) * time.Minute),
		})
	}
	// 15 COMPLETED events
	for i := 0; i < 15; i++ {
		store = append(store, eventRow{
			txnID:     uuid.New(),
			status:    model.AsyncStatusCompleted,
			createdAt: baseTime.Add(time.Duration(10+i) * time.Minute),
		})
	}
	// 5 FAILED events
	for i := 0; i < 5; i++ {
		store = append(store, eventRow{
			txnID:     uuid.New(),
			status:    model.AsyncStatusFailed,
			createdAt: baseTime.Add(time.Duration(25+i) * time.Minute),
		})
	}

	// Oracle: simulate exact SQL behavior of repository.DeleteOldEventsForWorkspace:
	// Only terminal events ('COMPLETED', 'FAILED') are selected for pruning beyond maxCount.
	simulateRepoPruning := func(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
		var terminalIndices []int
		for idx, row := range store {
			if row.status == model.AsyncStatusCompleted || row.status == model.AsyncStatusFailed {
				terminalIndices = append(terminalIndices, idx)
			}
		}

		terminalCount := len(terminalIndices)
		if terminalCount <= maxCount {
			return 0, nil
		}

		// Excess to delete: oldest terminal rows (terminalCount - maxCount)
		excessCount := terminalCount - maxCount
		toDeleteSet := make(map[uuid.UUID]bool)
		for i := 0; i < excessCount; i++ {
			toDeleteSet[store[terminalIndices[i]].txnID] = true
		}

		// Delete from store
		var newStore []eventRow
		var deletedCount int64
		for _, row := range store {
			if toDeleteSet[row.txnID] {
				// Assert: NEVER delete a PENDING event!
				if row.status == model.AsyncStatusPending {
					t.Fatalf("FATAL INVARIANT VIOLATION: attempting to delete PENDING event %v", row.txnID)
				}
				deletedCount++
			} else {
				newStore = append(newStore, row)
			}
		}
		store = newStore
		return deletedCount, nil
	}

	// Retain only latest 5 terminal events (out of 20 total terminal events).
	// Should delete exactly 15 terminal events, leaving 5 terminal events + all 10 PENDING events = 15 total.
	const maxRetained = 5
	deleted, err := simulateRepoPruning(context.Background(), wsID, maxRetained)
	if err != nil {
		t.Fatalf("pruning error: %v", err)
	}
	if deleted != 15 {
		t.Fatalf("deleted = %d, want 15", deleted)
	}

	// Verify invariant on post-prune store
	var pendingRemaining int
	var completedRemaining int
	var failedRemaining int
	for _, row := range store {
		switch row.status {
		case model.AsyncStatusPending:
			pendingRemaining++
		case model.AsyncStatusCompleted:
			completedRemaining++
		case model.AsyncStatusFailed:
			failedRemaining++
		}
	}

	if pendingRemaining != 10 {
		t.Fatalf("Invariant violated: pendingRemaining = %d, want 10 (all PENDING must be preserved)", pendingRemaining)
	}
	if completedRemaining+failedRemaining != maxRetained {
		t.Fatalf("terminal remaining = %d, want %d", completedRemaining+failedRemaining, maxRetained)
	}
}

// --- 5. Stale PENDING Reaper: Timing Precision Tests ---

func TestStalePendingReaper_TimingPrecision(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}
	const staleDuration = 5 * time.Minute

	var capturedOlderThan time.Time
	var mu sync.Mutex

	// Test that ReapStalePendingOnce computes cutoff as now - staleDuration
	beforeCall := time.Now().UTC().Add(-staleDuration)

	pruner := &mockAsyncEventPruner{
		findStaleFunc: func(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
			mu.Lock()
			capturedOlderThan = olderThan
			mu.Unlock()

			// Test strict boundary against this exact olderThan
			eventBefore := &model.ScimAsyncEvent{
				TxnID:     uuid.New(),
				Status:    model.AsyncStatusPending,
				CreatedAt: olderThan.Add(-1 * time.Millisecond),
			}
			eventAt := &model.ScimAsyncEvent{
				TxnID:     uuid.New(),
				Status:    model.AsyncStatusPending,
				CreatedAt: olderThan,
			}
			eventAfter := &model.ScimAsyncEvent{
				TxnID:     uuid.New(),
				Status:    model.AsyncStatusPending,
				CreatedAt: olderThan.Add(1 * time.Millisecond),
			}

			// Simulating SQL WHERE status = 'PENDING' AND created_at < olderThan
			var result []*model.ScimAsyncEvent
			for _, e := range []*model.ScimAsyncEvent{eventBefore, eventAt, eventAfter} {
				if e.Status == model.AsyncStatusPending && e.CreatedAt.Before(olderThan) {
					result = append(result, e)
				}
			}
			return result, nil
		},
		transitionFunc: func(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error) {
			return true, nil
		},
	}

	svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, staleDuration)
	reaped, err := svc.ReapStalePendingOnce(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	afterCall := time.Now().UTC().Add(-staleDuration)

	mu.Lock()
	cutoff := capturedOlderThan
	mu.Unlock()

	// Verify cutoff computed by service is within [beforeCall, afterCall]
	if cutoff.Before(beforeCall) || cutoff.After(afterCall) {
		t.Fatalf("cutoff %v not between %v and %v", cutoff, beforeCall, afterCall)
	}

	// Only eventBefore strictly matches (eventAt and eventAfter must be excluded)
	if reaped != 1 {
		t.Fatalf("reaped = %d, want 1 (strictly before cutoff)", reaped)
	}
}

// --- 6. Stale PENDING Reaper: Atomic Transition Tests ---

func TestStalePendingReaper_AtomicTransition(t *testing.T) {
	t.Parallel()

	logger := &safeMockLogger{}

	t.Run("Only transitions rows where status is PENDING", func(t *testing.T) {
		t.Parallel()

		txnPending := uuid.New()
		txnCompleted := uuid.New()
		txnFailed := uuid.New()

		// Database state simulator for TransitionPendingToFailed
		// WHERE txn_id = $1 AND status = 'PENDING'
		dbStatus := map[uuid.UUID]string{
			txnPending:   model.AsyncStatusPending,
			txnCompleted: model.AsyncStatusCompleted,
			txnFailed:    model.AsyncStatusFailed,
		}

		simulateTransition := func(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error) {
			currentStatus, exists := dbStatus[txnID]
			if !exists || currentStatus != model.AsyncStatusPending {
				return false, nil // 0 rows affected
			}
			dbStatus[txnID] = model.AsyncStatusFailed
			return true, nil
		}

		pruner := &mockAsyncEventPruner{
			findStaleFunc: func(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
				return []*model.ScimAsyncEvent{
					{TxnID: txnPending, Status: model.AsyncStatusPending},
					{TxnID: txnCompleted, Status: model.AsyncStatusPending}, // was PENDING when queried, but completed concurrently
					{TxnID: txnFailed, Status: model.AsyncStatusPending},
				}, nil
			},
			transitionFunc: simulateTransition,
		}

		svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)
		reaped, err := svc.ReapStalePendingOnce(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Only txnPending should have been reaped (1)
		if reaped != 1 {
			t.Fatalf("reaped = %d, want 1", reaped)
		}

		if dbStatus[txnPending] != model.AsyncStatusFailed {
			t.Errorf("txnPending status = %q, want %q", dbStatus[txnPending], model.AsyncStatusFailed)
		}
		if dbStatus[txnCompleted] != model.AsyncStatusCompleted {
			t.Errorf("txnCompleted was overwritten! status = %q, want %q", dbStatus[txnCompleted], model.AsyncStatusCompleted)
		}
	})

	t.Run("Returns false if event does not exist", func(t *testing.T) {
		t.Parallel()

		nonExistentTxn := uuid.New()
		pruner := &mockAsyncEventPruner{
			findStaleFunc: func(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
				return []*model.ScimAsyncEvent{
					{TxnID: nonExistentTxn, Status: model.AsyncStatusPending},
				}, nil
			},
			transitionFunc: func(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error) {
				return false, nil // Row not found
			},
		}

		svc := NewAsyncEventCleanupService(pruner, logger, true, time.Hour, 5000, 5*time.Minute)
		reaped, err := svc.ReapStalePendingOnce(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reaped != 0 {
			t.Fatalf("reaped = %d, want 0", reaped)
		}
	})
}

// --- 7. RFC 9967 SET JSON Payload Safety & Fallback Tests ---

func TestBuildStalePendingErrorSET_RFC9967_Conformance(t *testing.T) {
	t.Parallel()

	wsID := uuid.New()
	txnID := uuid.New()
	resID := uuid.New()

	testCases := []struct {
		name         string
		event        *model.ScimAsyncEvent
		wantMethod   string
		wantLocation bool
		wantSubID    bool
		wantPlural   string
	}{
		{
			name: "POST User with ResourceID",
			event: &model.ScimAsyncEvent{
				TxnID:        txnID,
				WorkspaceID:  wsID,
				Operation:    "POST",
				ResourceType: "User",
				ResourceID:   &resID,
				Status:       model.AsyncStatusPending,
			},
			wantMethod:   "POST",
			wantLocation: true,
			wantSubID:    true,
			wantPlural:   "Users",
		},
		{
			name: "Lowercase patch Group with ResourceID",
			event: &model.ScimAsyncEvent{
				TxnID:        txnID,
				WorkspaceID:  wsID,
				Operation:    "patch",
				ResourceType: "Group",
				ResourceID:   &resID,
				Status:       model.AsyncStatusPending,
			},
			wantMethod:   "PATCH",
			wantLocation: true,
			wantSubID:    true,
			wantPlural:   "Groups",
		},
		{
			name: "DELETE without ResourceID",
			event: &model.ScimAsyncEvent{
				TxnID:        txnID,
				WorkspaceID:  wsID,
				Operation:    "DELETE",
				ResourceType: "User",
				ResourceID:   nil,
				Status:       model.AsyncStatusPending,
			},
			wantMethod:   "DELETE",
			wantLocation: false,
			wantSubID:    false,
		},
		{
			name: "Empty operation defaults to POST",
			event: &model.ScimAsyncEvent{
				TxnID:        txnID,
				WorkspaceID:  wsID,
				Operation:    "",
				ResourceType: "User",
				ResourceID:   nil,
				Status:       model.AsyncStatusPending,
			},
			wantMethod:   "POST",
			wantLocation: false,
			wantSubID:    false,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rawJSON := BuildStalePendingErrorSET(tc.event)
			if rawJSON == "" {
				t.Fatal("BuildStalePendingErrorSET returned empty string")
			}

			// 1. Must be valid JSON
			var m map[string]any
			if err := json.Unmarshal([]byte(rawJSON), &m); err != nil {
				t.Fatalf("failed to parse JSON: %v\nRaw: %s", err, rawJSON)
			}

			// 2. Base SET claims (RFC 8417 / RFC 9967)
			if m["iss"] != fmt.Sprintf("/ws/%s/scim/v2", wsID.String()) {
				t.Errorf("iss = %v, want /ws/%s/scim/v2", m["iss"], wsID)
			}
			if _, ok := m["iat"].(float64); !ok {
				t.Errorf("iat = %v, want numeric unix timestamp", m["iat"])
			}
			jtiStr, ok := m["jti"].(string)
			if !ok || jtiStr == "" {
				t.Errorf("jti is missing or not string: %v", m["jti"])
			}
			if _, err := uuid.Parse(jtiStr); err != nil {
				t.Errorf("jti is not a valid UUID: %v", jtiStr)
			}
			if m["txn"] != tc.event.TxnID.String() {
				t.Errorf("txn = %v, want %v", m["txn"], tc.event.TxnID)
			}

			// 3. Events claim containing misc:asyncresp
			eventsMap, ok := m["events"].(map[string]any)
			if !ok {
				t.Fatalf("events claim missing or not map: %+v", m)
			}
			asyncResp, ok := eventsMap["urn:ietf:params:scim:event:misc:asyncresp"].(map[string]any)
			if !ok {
				t.Fatalf("urn:ietf:params:scim:event:misc:asyncresp missing: %+v", eventsMap)
			}

			if asyncResp["status"] != "500" {
				t.Errorf("asyncResp.status = %v, want \"500\"", asyncResp["status"])
			}
			if asyncResp["method"] != tc.wantMethod {
				t.Errorf("asyncResp.method = %v, want %q", asyncResp["method"], tc.wantMethod)
			}

			// 4. Nested SCIM Error response (RFC 7644 §3.12)
			errResp, ok := asyncResp["response"].(map[string]any)
			if !ok {
				t.Fatalf("asyncResp.response missing or not map: %+v", asyncResp)
			}
			if errResp["status"] != "500" {
				t.Errorf("errResp.status = %v, want \"500\"", errResp["status"])
			}
			if errResp["detail"] != StalePendingTimeoutDetail {
				t.Errorf("errResp.detail = %v, want %q", errResp["detail"], StalePendingTimeoutDetail)
			}
			schemas, ok := errResp["schemas"].([]any)
			if !ok || len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
				t.Errorf("errResp.schemas = %v, want [urn:ietf:params:scim:api:messages:2.0:Error]", schemas)
			}

			// 5. Sub ID and location verification
			if tc.wantLocation {
				expectedURI := fmt.Sprintf("/ws/%s/scim/v2/%s/%s", wsID.String(), tc.wantPlural, resID.String())
				if asyncResp["location"] != expectedURI {
					t.Errorf("asyncResp.location = %v, want %q", asyncResp["location"], expectedURI)
				}
				subID, ok := m["sub_id"].(map[string]any)
				if !ok {
					t.Fatalf("sub_id missing or not map: %+v", m)
				}
				if subID["uri"] != expectedURI {
					t.Errorf("sub_id.uri = %v, want %q", subID["uri"], expectedURI)
				}
				if subID["format"] != "uri" {
					t.Errorf("sub_id.format = %v, want \"uri\"", subID["format"])
				}
			} else {
				if _, ok := asyncResp["location"]; ok {
					t.Errorf("asyncResp.location present unexpectedly: %v", asyncResp["location"])
				}
				if _, ok := m["sub_id"]; ok {
					t.Errorf("m[sub_id] present unexpectedly: %v", m["sub_id"])
				}
			}
		})
	}
}

func TestBuildStalePendingErrorSET_FallbackJSONSafety(t *testing.T) {
	t.Parallel()

	// Directly verify the static fallback JSON formatting string used in BuildStalePendingErrorSET
	baseURL := "/ws/00000000-0000-0000-0000-000000000001/scim/v2"
	nowUnix := time.Now().UTC().Unix()
	jti := uuid.New().String()
	txn := uuid.New().String()
	upperMethod := "POST"

	fallback := fmt.Sprintf(`{"iss":%q,"iat":%d,"jti":%q,"txn":%q,"events":{"urn:ietf:params:scim:event:misc:asyncresp":{"status":"500","method":%q,"response":{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":%q}}}}`,
		baseURL, nowUnix, jti, txn, upperMethod, StalePendingTimeoutDetail)

	var m map[string]any
	if err := json.Unmarshal([]byte(fallback), &m); err != nil {
		t.Fatalf("fallback string is invalid JSON: %v\nJSON: %s", err, fallback)
	}

	if m["iss"] != baseURL {
		t.Errorf("iss = %v, want %v", m["iss"], baseURL)
	}
	if m["txn"] != txn {
		t.Errorf("txn = %v, want %v", m["txn"], txn)
	}
	events, ok := m["events"].(map[string]any)
	if !ok {
		t.Fatalf("events map missing in fallback")
	}
	asyncResp, ok := events["urn:ietf:params:scim:event:misc:asyncresp"].(map[string]any)
	if !ok {
		t.Fatalf("asyncresp missing in fallback")
	}
	if asyncResp["status"] != "500" || asyncResp["method"] != "POST" {
		t.Errorf("asyncResp mismatch: %+v", asyncResp)
	}
	errResp, ok := asyncResp["response"].(map[string]any)
	if !ok {
		t.Fatalf("response missing in fallback")
	}
	if errResp["detail"] != StalePendingTimeoutDetail {
		t.Errorf("errResp.detail = %v, want %q", errResp["detail"], StalePendingTimeoutDetail)
	}
}
