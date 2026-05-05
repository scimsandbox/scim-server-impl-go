package integration

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
	"github.com/scimsandbox/scim-server-impl-go/internal/testsupport"
)

func TestGroupMembershipTransactionDockerCLI(t *testing.T) {
	ctx := context.Background()

	// Start Postgres container using docker CLI
	runCmd := exec.CommandContext(ctx, "docker", "run", "-d", "-e", "POSTGRES_USER=postgres", "-e", "POSTGRES_PASSWORD=postgres", "-e", "POSTGRES_DB=scim_test", "-P", "postgres:18-alpine3.22")
	out, err := runCmd.Output()
	if err != nil {
		t.Fatalf("docker run failed: %v", err)
	}
	containerID := strings.TrimSpace(string(out))
	if containerID == "" {
		t.Fatalf("empty container id from docker run")
	}

	// Ensure container is removed at the end
	defer func() {
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", containerID).Run()
	}()

	// Obtain mapped port
	var hostPort string
	for i := 0; i < 60; i++ {
		portCmd := exec.CommandContext(ctx, "docker", "port", containerID, "5432/tcp")
		pout, _ := portCmd.Output()
		if len(pout) > 0 {
			// output looks like "0.0.0.0:32768\n"
			parts := strings.Split(strings.TrimSpace(string(pout)), ":")
			hostPort = parts[len(parts)-1]
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if hostPort == "" {
		t.Fatalf("could not obtain mapped port for container %s", containerID)
	}

	dbURL := fmt.Sprintf("postgres://postgres:postgres@localhost:%s/scim_test?sslmode=disable", hostPort)

	// wait for DB to accept connections
	var poolConn *pgxpool.Pool
	success := false
	for i := 0; i < 60; i++ {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		p, err := pgxpool.New(cctx, dbURL)
		if err == nil {
			// verify connectivity
			pingCtx, pingCancel := context.WithTimeout(ctx, 2*time.Second)
			pingErr := p.Ping(pingCtx)
			pingCancel()
			if pingErr == nil {
				poolConn = p
				success = true
				cancel()
				break
			}
			p.Close()
		}
		cancel()
		time.Sleep(500 * time.Millisecond)
	}
	if !success {
		t.Fatalf("could not connect to postgres at %s", dbURL)
	}
	defer poolConn.Close()
	testsupport.ApplyScimServerDBMigrations(t, ctx, dbURL)
	if err := jdbc.Init(ctx, jdbc.Config{DSN: dbURL, MaxConns: 5, MinConns: 1}); err != nil {
		t.Fatalf("jdbc.Init: %v", err)
	}
	t.Cleanup(func() { _ = jdbc.Close() })

	groupRepo := repository.NewGroupRepository()
	membershipRepo := repository.NewMembershipRepository()

	// create a group
	wsID := uuid.New()
	// ensure workspace exists (migrations create table only)
	if _, err := jdbc.ExecContext(ctx,
		`INSERT INTO workspaces (id, name, created_at, updated_at) VALUES ($1,$2,$3,$4)`,
		wsID, "test-workspace", time.Now().UTC(), time.Now().UTC()); err != nil {
		t.Fatalf("insert workspace: %v", err)
	}

	g := &model.ScimGroup{
		WorkspaceID: wsID,
		DisplayName: "team-dockercli",
	}
	if err := groupRepo.Create(ctx, g); err != nil {
		t.Fatalf("create group: %v", err)
	}

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

	if err := jdbc.InTransaction(ctx, func(tx jdbc.Tx) error {
		if err := membershipRepo.CreateBatchTx(ctx, tx, []model.ScimGroupMembership{member}); err != nil {
			return err
		}
		return fmt.Errorf("force rollback")
	}); err == nil {
		t.Fatalf("expected error from transactional function")
	}

	items, err := membershipRepo.FindByMemberValue(ctx, member.MemberValue)
	if err != nil {
		t.Fatalf("find by member value: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected 0 memberships after rollback, got %d", len(items))
	}

	if err := jdbc.InTransaction(ctx, func(tx jdbc.Tx) error {
		return membershipRepo.CreateBatchTx(ctx, tx, []model.ScimGroupMembership{member})
	}); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	items, err = membershipRepo.FindByGroupID(ctx, g.ID)
	if err != nil {
		t.Fatalf("find by group id: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 membership after commit, got %d", len(items))
	}
}
