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
