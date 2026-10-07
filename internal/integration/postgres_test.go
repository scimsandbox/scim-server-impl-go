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

// TestGroupMembershipTransaction verifies that repository transactional helpers
// correctly roll back and commit when using a Postgres container.
func TestGroupMembershipTransaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:18-alpine3.22",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "postgres",
			"POSTGRES_PASSWORD": "postgres",
			"POSTGRES_DB":       "scim_test",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
	}

	pgc, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}
	defer func() { _ = pgc.Terminate(ctx) }()

	host, err := pgc.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := pgc.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("mapped port: %v", err)
	}

	dbURL := fmt.Sprintf("postgres://postgres:postgres@%s:%s/scim_test?sslmode=disable", host, port.Port())
	testsupport.ApplyScimServerDBMigrations(t, ctx, dbURL)
	if err := jdbc.Init(ctx, jdbc.Config{DSN: dbURL, MaxConns: 5, MinConns: 1}); err != nil {
		t.Fatalf("jdbc.Init: %v", err)
	}
	t.Cleanup(func() { _ = jdbc.Close() })

	groupRepo := repository.NewGroupRepository()
	membershipRepo := repository.NewMembershipRepository()

	// ensure workspace exists (migrations create table only)
	wsID := uuid.New()
	if _, err := jdbc.ExecContext(ctx,
		`INSERT INTO workspaces (id, name, created_at, updated_at) VALUES ($1,$2,$3,$4)`,
		wsID, "test-workspace", time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatalf("insert workspace: %v", err)
	}

	// create a group
	g := &model.ScimGroup{
		WorkspaceID: wsID,
		DisplayName: "team-transaction-test",
	}
	if err := groupRepo.Create(ctx, g); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// prepare a member
	mt := "User"
	disp := "Alice"
	member := model.ScimGroupMembership{
		ID:          uuid.New(),
		GroupID:     g.ID,
		WorkspaceID: g.WorkspaceID,
		MemberValue: uuid.New(),
		MemberType:  &mt,
		Display:     &disp,
	}

	// attempt to insert then force rollback
	err = jdbc.InTransaction(ctx, func(tx jdbc.Tx) error {
		if err := membershipRepo.CreateBatchTx(ctx, tx, []model.ScimGroupMembership{member}); err != nil {
			return err
		}
		return fmt.Errorf("force rollback")
	})
	if err == nil {
		t.Fatalf("expected error from transactional function")
	}

	// membership should not exist after rollback
	items, err := membershipRepo.FindByMemberValue(ctx, member.MemberValue)
	if err != nil {
		t.Fatalf("find by member value: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 memberships after rollback, got %d", len(items))
	}

	// now commit within a transaction
	if err := jdbc.InTransaction(ctx, func(tx jdbc.Tx) error {
		return membershipRepo.CreateBatchTx(ctx, tx, []model.ScimGroupMembership{member})
	}); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	// verify membership exists
	items, err = membershipRepo.FindByGroupID(ctx, g.ID)
	if err != nil {
		t.Fatalf("find by group id: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 membership after commit, got %d", len(items))
	}
}

// TestRequestLogPruningSQL tests request log pruning via DeleteOldLogsForWorkspace:
// - Retains exactly the newest maxCount logs.
// - Deterministic tie-breaking on id DESC when created_at is identical.
// - Workspace isolation: leaves logs of other workspaces untouched.
// - No-op when log count is under or equal to maxCount.
// - Batched execution across batches (surpassing DefaultPruneBatchSize).
func TestRequestLogPruningSQL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:18-alpine3.22",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "postgres",
			"POSTGRES_PASSWORD": "postgres",
			"POSTGRES_DB":       "scim_test",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
	}

	pgc, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start container: %v", err)
	}
	defer func() { _ = pgc.Terminate(ctx) }()

	host, err := pgc.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := pgc.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("mapped port: %v", err)
	}

	dbURL := fmt.Sprintf("postgres://postgres:postgres@%s:%s/scim_test?sslmode=disable", host, port.Port())
	testsupport.ApplyScimServerDBMigrations(t, ctx, dbURL)
	if err := jdbc.Init(ctx, jdbc.Config{DSN: dbURL, MaxConns: 5, MinConns: 1}); err != nil {
		t.Fatalf("jdbc.Init: %v", err)
	}
	t.Cleanup(func() { _ = jdbc.Close() })

	requestLogRepo := repository.NewRequestLogRepository()

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

	countLogs := func(wsID uuid.UUID) int64 {
		row := jdbc.QueryRowContext(ctx, `SELECT count(*) FROM scim_request_logs WHERE workspace_id = $1`, wsID)
		var count int64
		if err := row.Scan(&count); err != nil {
			t.Fatalf("count logs: %v", err)
		}
		return count
	}

	wsA := createWorkspace("ws-a")
	wsB := createWorkspace("ws-b")

	// 1. Insert logs for wsB (which should remain unaffected throughout wsA operations)
	baseTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		_, err := jdbc.ExecContext(ctx,
			`INSERT INTO scim_request_logs (id, workspace_id, http_method, request_path, http_status, created_at)
			 VALUES ($1, $2, 'GET', '/Users', 200, $3)`,
			uuid.New(), wsB, baseTime.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatalf("insert wsB log: %v", err)
		}
	}
	if c := countLogs(wsB); c != 5 {
		t.Fatalf("expected 5 logs in wsB, got %d", c)
	}

	// 2. Insert 10 logs for wsA with strictly ascending timestamps
	var wsALogIDs []uuid.UUID
	for i := 0; i < 10; i++ {
		id := uuid.New()
		wsALogIDs = append(wsALogIDs, id)
		_, err := jdbc.ExecContext(ctx,
			`INSERT INTO scim_request_logs (id, workspace_id, http_method, request_path, http_status, created_at)
			 VALUES ($1, $2, 'POST', '/Users', 201, $3)`,
			id, wsA, baseTime.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatalf("insert wsA log: %v", err)
		}
	}

	// Case A: No-op when count <= maxCount
	deleted, err := requestLogRepo.DeleteOldLogsForWorkspace(ctx, wsA, 10)
	if err != nil {
		t.Fatalf("delete old logs (maxCount=10): %v", err)
	}
	if deleted != 0 {
		t.Fatalf("expected 0 deleted when at threshold, got %d", deleted)
	}
	if c := countLogs(wsA); c != 10 {
		t.Fatalf("expected 10 logs in wsA, got %d", c)
	}

	deleted, err = requestLogRepo.DeleteOldLogsForWorkspace(ctx, wsA, 15)
	if err != nil {
		t.Fatalf("delete old logs (maxCount=15): %v", err)
	}
	if deleted != 0 {
		t.Fatalf("expected 0 deleted when below threshold, got %d", deleted)
	}

	// Case B: Prune excess logs and verify that newest are kept
	// We want to keep 6 newest (indices 4..9), deleting the 4 oldest (indices 0..3)
	deleted, err = requestLogRepo.DeleteOldLogsForWorkspace(ctx, wsA, 6)
	if err != nil {
		t.Fatalf("delete old logs (maxCount=6): %v", err)
	}
	if deleted != 4 {
		t.Fatalf("expected 4 deleted, got %d", deleted)
	}
	if c := countLogs(wsA); c != 6 {
		t.Fatalf("expected 6 logs remaining in wsA, got %d", c)
	}

	// Verify remaining wsA logs match the 6 newest IDs
	rows, err := jdbc.QueryContext(ctx,
		`SELECT id FROM scim_request_logs WHERE workspace_id = $1 ORDER BY created_at ASC`, wsA)
	if err != nil {
		t.Fatalf("query remaining logs: %v", err)
	}
	defer rows.Close()

	var remainingIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan id: %v", err)
		}
		remainingIDs = append(remainingIDs, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}

	expectedIDs := wsALogIDs[4:] // indices 4 through 9
	if len(remainingIDs) != len(expectedIDs) {
		t.Fatalf("expected %d remaining logs, got %d", len(expectedIDs), len(remainingIDs))
	}
	for i := range expectedIDs {
		if remainingIDs[i] != expectedIDs[i] {
			t.Fatalf("mismatch at position %d: expected %s, got %s", i, expectedIDs[i], remainingIDs[i])
		}
	}

	// Case C: Verify workspace isolation — wsB logs must be unchanged
	if c := countLogs(wsB); c != 5 {
		t.Fatalf("workspace isolation violated: expected wsB to still have 5 logs, got %d", c)
	}

	// Case D: Tie-breaker on id DESC when created_at is identical
	wsTie := createWorkspace("ws-tie")
	sameTime := time.Date(2026, 2, 1, 10, 0, 0, 0, time.UTC)
	uuid1 := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	uuid2 := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	uuid3 := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	uuid4 := uuid.MustParse("00000000-0000-0000-0000-000000000004")
	for _, u := range []uuid.UUID{uuid1, uuid2, uuid3, uuid4} {
		_, err := jdbc.ExecContext(ctx,
			`INSERT INTO scim_request_logs (id, workspace_id, http_method, request_path, http_status, created_at)
			 VALUES ($1, $2, 'GET', '/Users', 200, $3)`,
			u, wsTie, sameTime)
		if err != nil {
			t.Fatalf("insert tie log: %v", err)
		}
	}
	// Keep 2. ORDER BY created_at DESC, id DESC -> keeps uuid4 and uuid3, prunes uuid2 and uuid1.
	deleted, err = requestLogRepo.DeleteOldLogsForWorkspace(ctx, wsTie, 2)
	if err != nil {
		t.Fatalf("prune tie logs: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("expected 2 deleted for tie logs, got %d", deleted)
	}
	rowsTie, err := jdbc.QueryContext(ctx,
		`SELECT id FROM scim_request_logs WHERE workspace_id = $1 ORDER BY id DESC`, wsTie)
	if err != nil {
		t.Fatalf("query tie remaining logs: %v", err)
	}
	defer rowsTie.Close()
	var tieRemaining []uuid.UUID
	for rowsTie.Next() {
		var u uuid.UUID
		if err := rowsTie.Scan(&u); err != nil {
			t.Fatalf("scan tie id: %v", err)
		}
		tieRemaining = append(tieRemaining, u)
	}
	if len(tieRemaining) != 2 || tieRemaining[0] != uuid4 || tieRemaining[1] != uuid3 {
		t.Fatalf("expected uuid4 and uuid3 to be retained, got %v", tieRemaining)
	}

	// Case E: Multi-batch deletion (exceeding DefaultPruneBatchSize = 5000)
	wsBatch := createWorkspace("ws-batch")
	_, err = jdbc.ExecContext(ctx,
		`INSERT INTO scim_request_logs (id, workspace_id, http_method, request_path, http_status, created_at)
		 SELECT gen_random_uuid(), $1, 'GET', '/Users', 200, now() - (n || ' seconds')::interval
		 FROM generate_series(1, 5005) AS n`, wsBatch)
	if err != nil {
		t.Fatalf("bulk insert for batch test: %v", err)
	}
	if c := countLogs(wsBatch); c != 5005 {
		t.Fatalf("expected 5005 logs in wsBatch, got %d", c)
	}

	deleted, err = requestLogRepo.DeleteOldLogsForWorkspace(ctx, wsBatch, 3)
	if err != nil {
		t.Fatalf("batch prune: %v", err)
	}
	if deleted != 5002 {
		t.Fatalf("expected 5002 total deleted across multiple batches, got %d", deleted)
	}
	if c := countLogs(wsBatch); c != 3 {
		t.Fatalf("expected 3 logs remaining in wsBatch, got %d", c)
	}
}

