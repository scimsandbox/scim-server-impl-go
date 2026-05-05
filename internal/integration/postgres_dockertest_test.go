package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
	"github.com/scimsandbox/scim-server-impl-go/internal/testsupport"
)

func TestGroupMembershipTransactionDockertest(t *testing.T) {
	// This test uses Docker to start Postgres and verifies transactional helpers.
	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %v", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "15-alpine",
		Env: []string{
			"POSTGRES_USER=postgres",
			"POSTGRES_PASSWORD=postgres",
			"POSTGRES_DB=scim_test",
		},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		t.Fatalf("could not start resource: %v", err)
	}
	defer func() {
		if err := pool.Purge(resource); err != nil {
			t.Logf("failed purge: %v", err)
		}
	}()

	var dbURL string
	if err := pool.Retry(func() error {
		port := resource.GetPort("5432/tcp")
		dbURL = fmt.Sprintf("postgres://postgres:postgres@localhost:%s/scim_test?sslmode=disable", port)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p, err := pgxpool.New(ctx, dbURL)
		if err != nil {
			return err
		}
		if err := p.Ping(ctx); err != nil {
			p.Close()
			return err
		}
		p.Close()
		return nil
	}); err != nil {
		t.Fatalf("could not connect to docker postgres: %v", err)
	}

	ctx := context.Background()
	testsupport.ApplyScimServerDBMigrations(t, ctx, dbURL)
	if err := jdbc.Init(ctx, jdbc.Config{DSN: dbURL, MaxConns: 5, MinConns: 1}); err != nil {
		t.Fatalf("jdbc.Init: %v", err)
	}
	t.Cleanup(func() { _ = jdbc.Close() })

	groupRepo := repository.NewGroupRepository()
	membershipRepo := repository.NewMembershipRepository()

	wsID := uuid.New()
	if _, err := jdbc.ExecContext(ctx,
		`INSERT INTO workspaces (id, name, created_at, updated_at) VALUES ($1,$2,$3,$4)`,
		wsID, "test-workspace", time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatalf("insert workspace: %v", err)
	}

	// create a group
	g := &model.ScimGroup{
		WorkspaceID: wsID,
		DisplayName: "team-dockertest",
	}
	if err := groupRepo.Create(ctx, g); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// prepare a member
	memberType := "User"
	display := "Alice"
	member := model.ScimGroupMembership{
		ID:          uuid.New(),
		GroupID:     g.ID,
		WorkspaceID: g.WorkspaceID,
		MemberValue: uuid.New(),
		MemberType:  &memberType,
		Display:     &display,
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
