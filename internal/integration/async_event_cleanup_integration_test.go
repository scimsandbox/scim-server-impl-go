package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
	"github.com/scimsandbox/scim-server-impl-go/internal/testsupport"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startPostgresContainer(t *testing.T, ctx context.Context) (string, func()) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:18-alpine3.22",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "postgres",
			"POSTGRES_PASSWORD": "postgres",
			"POSTGRES_DB":       "scim_test",
		},
		WaitingFor: wait.ForAll(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
			wait.ForListeningPort("5432/tcp"),
		).WithDeadline(60 * time.Second),
	}

	pgc, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}

	host, err := pgc.Host(ctx)
	if err != nil {
		_ = pgc.Terminate(ctx)
		t.Fatalf("container host: %v", err)
	}
	port, err := pgc.MappedPort(ctx, "5432/tcp")
	if err != nil {
		_ = pgc.Terminate(ctx)
		t.Fatalf("mapped port: %v", err)
	}

	dbURL := fmt.Sprintf("postgres://postgres:postgres@%s:%s/scim_test?sslmode=disable", host, port.Port())
	testsupport.ApplyScimServerDBMigrations(t, ctx, dbURL)

	cleanup := func() {
		_ = pgc.Terminate(ctx)
	}
	return dbURL, cleanup
}

func TestAsyncEventPruningSQL_BoundariesAndInvariants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dbURL, containerCleanup := startPostgresContainer(t, ctx)
	defer containerCleanup()

	if err := jdbc.Init(ctx, jdbc.Config{DSN: dbURL, MaxConns: 5, MinConns: 1}); err != nil {
		t.Fatalf("jdbc.Init: %v", err)
	}
	t.Cleanup(func() { _ = jdbc.Close() })

	repo := repository.NewAsyncEventRepository()

	createWorkspace := func(name string) uuid.UUID {
		id := uuid.New()
		now := time.Now().UTC()
		if _, err := jdbc.ExecContext(ctx,
			`INSERT INTO workspaces (id, name, created_at, updated_at) VALUES ($1,$2,$3,$4)`,
			id, name, now, now); err != nil {
			t.Fatalf("insert workspace: %v", err)
		}
		return id
	}

	// wsA: Excess terminal events (will be pruned) + PENDING events (must NEVER be pruned)
	wsA := createWorkspace("ws-prune-a")
	// wsB: Only PENDING events (should NEVER be selected for pruning or deleted)
	wsB := createWorkspace("ws-pending-only-b")
	// wsC: 0 events (boundary)
	wsC := createWorkspace("ws-empty-c")

	baseTime := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)

	// 1. Insert 5 PENDING events for wsB
	for i := 0; i < 5; i++ {
		err := repo.Create(ctx, &model.ScimAsyncEvent{
			TxnID:        uuid.New(),
			WorkspaceID:  wsB,
			Operation:    "POST",
			ResourceType: "User",
			Status:       model.AsyncStatusPending,
			CreatedAt:    baseTime.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatalf("insert wsB pending event: %v", err)
		}
	}

	// 2. Insert for wsA:
	// - 6 PENDING events
	// - 8 COMPLETED events
	// - 4 FAILED events
	// Total terminal = 12. PENDING = 6. Total = 18.
	for i := 0; i < 6; i++ {
		err := repo.Create(ctx, &model.ScimAsyncEvent{
			TxnID:        uuid.New(),
			WorkspaceID:  wsA,
			Operation:    "POST",
			ResourceType: "User",
			Status:       model.AsyncStatusPending,
			CreatedAt:    baseTime.Add(time.Duration(i) * time.Minute),
		})
		if err != nil {
			t.Fatalf("insert wsA pending event: %v", err)
		}
	}

	payload := `{"test":"payload"}`
	for i := 0; i < 8; i++ {
		completedAt := baseTime.Add(time.Duration(10+i) * time.Minute)
		err := repo.Create(ctx, &model.ScimAsyncEvent{
			TxnID:        uuid.New(),
			WorkspaceID:  wsA,
			Operation:    "PUT",
			ResourceType: "User",
			Status:       model.AsyncStatusCompleted,
			SetPayload:   &payload,
			CreatedAt:    baseTime.Add(time.Duration(10+i) * time.Minute),
			CompletedAt:  &completedAt,
		})
		if err != nil {
			t.Fatalf("insert wsA completed event: %v", err)
		}
	}

	for i := 0; i < 4; i++ {
		completedAt := baseTime.Add(time.Duration(20+i) * time.Minute)
		err := repo.Create(ctx, &model.ScimAsyncEvent{
			TxnID:        uuid.New(),
			WorkspaceID:  wsA,
			Operation:    "DELETE",
			ResourceType: "Group",
			Status:       model.AsyncStatusFailed,
			SetPayload:   &payload,
			CreatedAt:    baseTime.Add(time.Duration(20+i) * time.Minute),
			CompletedAt:  &completedAt,
		})
		if err != nil {
			t.Fatalf("insert wsA failed event: %v", err)
		}
	}

	// --- Verification 1: ListWorkspaceIDsExceedingEventCount ---
	// With threshold = 10:
	// wsA has 12 terminal events (> 10) -> MATCH
	// wsB has 0 terminal events (5 PENDING) (<= 10) -> NO MATCH
	// wsC has 0 events -> NO MATCH
	exceeding, err := repo.ListWorkspaceIDsExceedingEventCount(ctx, 10)
	if err != nil {
		t.Fatalf("ListWorkspaceIDsExceedingEventCount: %v", err)
	}
	if len(exceeding) != 1 || exceeding[0] != wsA {
		t.Fatalf("expected only wsA exceeding, got %v", exceeding)
	}

	// With threshold = 15: wsA has 12 <= 15 -> NO MATCH
	exceeding15, err := repo.ListWorkspaceIDsExceedingEventCount(ctx, 15)
	if err != nil {
		t.Fatalf("ListWorkspaceIDsExceedingEventCount(15): %v", err)
	}
	if len(exceeding15) != 0 {
		t.Fatalf("expected 0 exceeding for threshold 15, got %v", exceeding15)
	}

	// --- Verification 2: DeleteOldEventsForWorkspace with maxCount = 5 on wsA ---
	// wsA has 12 terminal events. maxCount = 5.
	// Expected deleted = 12 - 5 = 7 terminal events.
	deleted, err := repo.DeleteOldEventsForWorkspace(ctx, wsA, 5)
	if err != nil {
		t.Fatalf("DeleteOldEventsForWorkspace: %v", err)
	}
	if deleted != 7 {
		t.Fatalf("deleted = %d, want 7", deleted)
	}

	// Check post-deletion state in wsA:
	// Total terminal remaining must be exactly 5.
	// Total PENDING remaining MUST be exactly 6 (NEVER DELETED).
	countByStatus := func(wid uuid.UUID, status string) int64 {
		row := jdbc.QueryRowContext(ctx,
			`SELECT count(*) FROM scim_async_events WHERE workspace_id = $1 AND status = $2`,
			wid, status)
		var c int64
		if err := row.Scan(&c); err != nil {
			t.Fatalf("count status %s: %v", status, err)
		}
		return c
	}

	wsAPending := countByStatus(wsA, model.AsyncStatusPending)
	if wsAPending != 6 {
		t.Fatalf("INVARIANT VIOLATION: wsA pending count = %d, want 6 (PENDING events must never be deleted)", wsAPending)
	}

	wsACompleted := countByStatus(wsA, model.AsyncStatusCompleted)
	wsAFailed := countByStatus(wsA, model.AsyncStatusFailed)
	if wsACompleted+wsAFailed != 5 {
		t.Fatalf("wsA terminal count = %d, want 5", wsACompleted+wsAFailed)
	}

	// Check wsB state: ALL 5 PENDING events untouched
	wsBPending := countByStatus(wsB, model.AsyncStatusPending)
	if wsBPending != 5 {
		t.Fatalf("wsB pending count = %d, want 5", wsBPending)
	}

	// --- Verification 3: Subsequent call when <= maxCount deletes 0 ---
	deletedAgain, err := repo.DeleteOldEventsForWorkspace(ctx, wsA, 5)
	if err != nil {
		t.Fatalf("DeleteOldEventsForWorkspace again: %v", err)
	}
	if deletedAgain != 0 {
		t.Fatalf("deletedAgain = %d, want 0", deletedAgain)
	}

	// --- Verification 4: Call on empty workspace deletes 0 ---
	deletedEmpty, err := repo.DeleteOldEventsForWorkspace(ctx, wsC, 5)
	if err != nil {
		t.Fatalf("DeleteOldEventsForWorkspace on wsC: %v", err)
	}
	if deletedEmpty != 0 {
		t.Fatalf("deletedEmpty = %d, want 0", deletedEmpty)
	}
}

func TestStalePendingReaperSQL_TimingPrecisionAndAtomicTransition(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	dbURL, containerCleanup := startPostgresContainer(t, ctx)
	defer containerCleanup()

	if err := jdbc.Init(ctx, jdbc.Config{DSN: dbURL, MaxConns: 5, MinConns: 1}); err != nil {
		t.Fatalf("jdbc.Init: %v", err)
	}
	t.Cleanup(func() { _ = jdbc.Close() })

	repo := repository.NewAsyncEventRepository()

	wsID := uuid.New()
	now := time.Now().UTC()
	if _, err := jdbc.ExecContext(ctx,
		`INSERT INTO workspaces (id, name, created_at, updated_at) VALUES ($1,$2,$3,$4)`,
		wsID, "ws-reaper", now, now); err != nil {
		t.Fatalf("insert workspace: %v", err)
	}

	// Event 1: PENDING, created 10m ago (stale)
	txn1 := uuid.New()
	time1 := now.Add(-10 * time.Minute)
	if err := repo.Create(ctx, &model.ScimAsyncEvent{
		TxnID:        txn1,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusPending,
		CreatedAt:    time1,
	}); err != nil {
		t.Fatalf("insert txn1: %v", err)
	}

	// Event 2: PENDING, created 30s ago (fresh, NOT stale)
	txn2 := uuid.New()
	time2 := now.Add(-30 * time.Second)
	if err := repo.Create(ctx, &model.ScimAsyncEvent{
		TxnID:        txn2,
		WorkspaceID:  wsID,
		Operation:    "PUT",
		ResourceType: "User",
		Status:       model.AsyncStatusPending,
		CreatedAt:    time2,
	}); err != nil {
		t.Fatalf("insert txn2: %v", err)
	}

	// Event 3: COMPLETED, created 10m ago (already completed, NOT stale)
	txn3 := uuid.New()
	completedAt := now.Add(-9 * time.Minute)
	payload := `{"iss":"test"}`
	if err := repo.Create(ctx, &model.ScimAsyncEvent{
		TxnID:        txn3,
		WorkspaceID:  wsID,
		Operation:    "PATCH",
		ResourceType: "Group",
		Status:       model.AsyncStatusCompleted,
		SetPayload:   &payload,
		CreatedAt:    now.Add(-10 * time.Minute),
		CompletedAt:  &completedAt,
	}); err != nil {
		t.Fatalf("insert txn3: %v", err)
	}

	// Cutoff = 5m ago
	cutoff := now.Add(-5 * time.Minute)

	// --- 1. Timing Precision on FindStalePendingEvents ---
	staleEvents, err := repo.FindStalePendingEvents(ctx, cutoff, 100)
	if err != nil {
		t.Fatalf("FindStalePendingEvents: %v", err)
	}
	if len(staleEvents) != 1 {
		t.Fatalf("expected 1 stale event, got %d", len(staleEvents))
	}
	if staleEvents[0].TxnID != txn1 {
		t.Fatalf("expected txn1 reaped, got %v", staleEvents[0].TxnID)
	}

	// --- 2. Atomic Transition on PENDING event ---
	errPayload := `{"error":"timeout"}`
	reapedAt := time.Now().UTC()
	transitioned, err := repo.TransitionPendingToFailed(ctx, txn1, errPayload, reapedAt)
	if err != nil {
		t.Fatalf("TransitionPendingToFailed: %v", err)
	}
	if !transitioned {
		t.Fatal("expected transition to succeed for PENDING event")
	}

	// Verify state in DB
	reapedEvent, err := repo.FindByTxnIDAndWorkspaceID(ctx, txn1, wsID)
	if err != nil || reapedEvent == nil {
		t.Fatalf("failed to retrieve reaped event: %v", err)
	}
	if reapedEvent.Status != model.AsyncStatusFailed {
		t.Errorf("status = %q, want %q", reapedEvent.Status, model.AsyncStatusFailed)
	}
	if reapedEvent.SetPayload == nil || *reapedEvent.SetPayload != errPayload {
		t.Errorf("payload mismatch: %v", reapedEvent.SetPayload)
	}
	if reapedEvent.CompletedAt == nil {
		t.Error("completed_at is nil for FAILED event")
	}

	// --- 3. Atomic Safety: Second transition on already-FAILED event returns false ---
	transitioned2, err := repo.TransitionPendingToFailed(ctx, txn1, `{"new":"payload"}`, time.Now().UTC())
	if err != nil {
		t.Fatalf("TransitionPendingToFailed second call: %v", err)
	}
	if transitioned2 {
		t.Fatal("expected second transition to return false (event is no longer PENDING)")
	}

	// Verify payload was NOT overwritten
	eventAfterSecond, err := repo.FindByTxnIDAndWorkspaceID(ctx, txn1, wsID)
	if err != nil || eventAfterSecond == nil {
		t.Fatalf("retrieve event: %v", err)
	}
	if *eventAfterSecond.SetPayload != errPayload {
		t.Errorf("payload was overwritten! got %q, want %q", *eventAfterSecond.SetPayload, errPayload)
	}

	// --- 4. Atomic Safety: Transition on COMPLETED event returns false ---
	transitionedCompleted, err := repo.TransitionPendingToFailed(ctx, txn3, errPayload, time.Now().UTC())
	if err != nil {
		t.Fatalf("TransitionPendingToFailed on completed: %v", err)
	}
	if transitionedCompleted {
		t.Fatal("expected transition on COMPLETED event to return false")
	}

	// --- 5. Transition on non-existent event returns false ---
	transitionedNonExistent, err := repo.TransitionPendingToFailed(ctx, uuid.New(), errPayload, time.Now().UTC())
	if err != nil {
		t.Fatalf("TransitionPendingToFailed on non-existent: %v", err)
	}
	if transitionedNonExistent {
		t.Fatal("expected transition on non-existent event to return false")
	}
}
