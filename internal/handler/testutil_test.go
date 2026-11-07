package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/scimsandbox/scim-server-impl-go/internal/jdbc"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/repository"
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
	"github.com/scimsandbox/scim-server-impl-go/internal/testsupport"
)

type testEnv struct {
	server *httptest.Server
	ctx    context.Context
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

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
	t.Cleanup(func() { _ = pgc.Terminate(ctx) })

	host, err := pgc.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := pgc.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("mapped port: %v", err)
	}

	dsn := fmt.Sprintf("postgres://postgres:postgres@%s:%s/scim_test?sslmode=disable", host, port.Port())
	testsupport.ApplyScimServerDBMigrations(t, ctx, dsn)

	err = jdbc.Init(ctx, jdbc.Config{DSN: dsn, MaxConns: 5, MinConns: 1})
	if err != nil {
		t.Fatalf("jdbc.Init: %v", err)
	}
	t.Cleanup(func() { _ = jdbc.Close() })

	userRepo := repository.NewUserRepository()
	groupRepo := repository.NewGroupRepository()
	membershipRepo := repository.NewMembershipRepository()
	workspaceRepo := repository.NewWorkspaceRepository()
	tokenRepo := repository.NewTokenRepository()
	requestLogRepo := repository.NewRequestLogRepository()
	asyncEventRepo := repository.NewAsyncEventRepository()

	userHandler := NewUserHandler(userRepo, membershipRepo, workspaceRepo, asyncEventRepo)
	groupHandler := NewGroupHandler(groupRepo, membershipRepo, userRepo, workspaceRepo, asyncEventRepo)
	bulkHandler := NewBulkHandler(userHandler, groupHandler)
	discoveryHandler := NewDiscoveryHandler(userHandler, groupHandler)
	asyncEventHandler := NewAsyncEventHandler(asyncEventRepo)

	r := chi.NewRouter()

	registerScimEndpoints := func(r chi.Router) {
		r.Post("/Users", userHandler.CreateUser)
		r.Get("/Users", userHandler.ListUsers)
		r.Put("/Users", MethodNotAllowedWithAllow("GET, POST"))
		r.Patch("/Users", MethodNotAllowedWithAllow("GET, POST"))
		r.Delete("/Users", MethodNotAllowedWithAllow("GET, POST"))

		r.Get("/Users/{id}", userHandler.GetUser)
		r.Put("/Users/{id}", userHandler.ReplaceUser)
		r.Patch("/Users/{id}", userHandler.PatchUser)
		r.Delete("/Users/{id}", userHandler.DeleteUser)
		r.Post("/Users/{id}", MethodNotAllowedWithAllow("GET, PUT, PATCH, DELETE"))

		r.Post("/Users/.search", userHandler.SearchUsers)
		r.Get("/Users/.search", MethodNotAllowedWithAllow("POST"))
		r.Put("/Users/.search", MethodNotAllowedWithAllow("POST"))
		r.Patch("/Users/.search", MethodNotAllowedWithAllow("POST"))
		r.Delete("/Users/.search", MethodNotAllowedWithAllow("POST"))

		r.Post("/Groups", groupHandler.CreateGroup)
		r.Get("/Groups", groupHandler.ListGroups)
		r.Put("/Groups", MethodNotAllowedWithAllow("GET, POST"))
		r.Patch("/Groups", MethodNotAllowedWithAllow("GET, POST"))
		r.Delete("/Groups", MethodNotAllowedWithAllow("GET, POST"))

		r.Get("/Groups/{id}", groupHandler.GetGroup)
		r.Put("/Groups/{id}", groupHandler.ReplaceGroup)
		r.Patch("/Groups/{id}", groupHandler.PatchGroup)
		r.Delete("/Groups/{id}", groupHandler.DeleteGroup)
		r.Post("/Groups/{id}", MethodNotAllowedWithAllow("GET, PUT, PATCH, DELETE"))

		r.Post("/Groups/.search", groupHandler.SearchGroups)
		r.Get("/Groups/.search", MethodNotAllowedWithAllow("POST"))
		r.Put("/Groups/.search", MethodNotAllowedWithAllow("POST"))
		r.Patch("/Groups/.search", MethodNotAllowedWithAllow("POST"))
		r.Delete("/Groups/.search", MethodNotAllowedWithAllow("POST"))

		r.Get("/", discoveryHandler.RootSearch)
		r.Post("/", MethodNotAllowedWithAllow("GET"))
		r.Put("/", MethodNotAllowedWithAllow("GET"))
		r.Patch("/", MethodNotAllowedWithAllow("GET"))
		r.Delete("/", MethodNotAllowedWithAllow("GET"))

		r.Post("/Bulk", bulkHandler.ProcessBulk)
		r.Get("/Bulk", MethodNotAllowedWithAllow("POST"))
		r.Put("/Bulk", MethodNotAllowedWithAllow("POST"))
		r.Patch("/Bulk", MethodNotAllowedWithAllow("POST"))
		r.Delete("/Bulk", MethodNotAllowedWithAllow("POST"))

		r.Post("/.search", discoveryHandler.RootSearch)
		r.Get("/.search", MethodNotAllowedWithAllow("POST"))
		r.Put("/.search", MethodNotAllowedWithAllow("POST"))
		r.Patch("/.search", MethodNotAllowedWithAllow("POST"))
		r.Delete("/.search", MethodNotAllowedWithAllow("POST"))

		r.Get("/Events/{txnId}", asyncEventHandler.GetEvent)
		r.Post("/Events/{txnId}", MethodNotAllowedWithAllow("GET"))
		r.Put("/Events/{txnId}", MethodNotAllowedWithAllow("GET"))
		r.Patch("/Events/{txnId}", MethodNotAllowedWithAllow("GET"))
		r.Delete("/Events/{txnId}", MethodNotAllowedWithAllow("GET"))

		r.Get("/ServiceProviderConfig", discoveryHandler.GetServiceProviderConfig)
		r.Post("/ServiceProviderConfig", MethodNotAllowedWithAllow("GET"))
		r.Put("/ServiceProviderConfig", MethodNotAllowedWithAllow("GET"))
		r.Patch("/ServiceProviderConfig", MethodNotAllowedWithAllow("GET"))
		r.Delete("/ServiceProviderConfig", MethodNotAllowedWithAllow("GET"))

		r.Get("/Schemas", discoveryHandler.GetSchemas)
		r.Post("/Schemas", MethodNotAllowedWithAllow("GET"))
		r.Put("/Schemas", MethodNotAllowedWithAllow("GET"))
		r.Patch("/Schemas", MethodNotAllowedWithAllow("GET"))
		r.Delete("/Schemas", MethodNotAllowedWithAllow("GET"))

		r.Get("/Schemas/{id}", discoveryHandler.GetSchemaByID)
		r.Post("/Schemas/{id}", MethodNotAllowedWithAllow("GET"))
		r.Put("/Schemas/{id}", MethodNotAllowedWithAllow("GET"))
		r.Patch("/Schemas/{id}", MethodNotAllowedWithAllow("GET"))
		r.Delete("/Schemas/{id}", MethodNotAllowedWithAllow("GET"))

		r.Get("/ResourceTypes", discoveryHandler.GetResourceTypes)
		r.Post("/ResourceTypes", MethodNotAllowedWithAllow("GET"))
		r.Put("/ResourceTypes", MethodNotAllowedWithAllow("GET"))
		r.Patch("/ResourceTypes", MethodNotAllowedWithAllow("GET"))
		r.Delete("/ResourceTypes", MethodNotAllowedWithAllow("GET"))

		r.Get("/ResourceTypes/{id}", discoveryHandler.GetResourceTypeByID)
		r.Post("/ResourceTypes/{id}", MethodNotAllowedWithAllow("GET"))
		r.Put("/ResourceTypes/{id}", MethodNotAllowedWithAllow("GET"))
		r.Patch("/ResourceTypes/{id}", MethodNotAllowedWithAllow("GET"))
		r.Delete("/ResourceTypes/{id}", MethodNotAllowedWithAllow("GET"))

		r.MethodNotAllowed(MethodNotAllowed)
	}

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		scim.WriteScimError(w, scim.NewScimError(http.StatusNotFound, "", "Requested SCIM endpoint or protocol version not found"))
	})
	r.MethodNotAllowed(MethodNotAllowed)

	r.Route("/ws/{workspaceId}/scim/v2", func(r chi.Router) {
		r.Use(middleware.ExtractWorkspaceID)
		r.Use(middleware.BearerTokenAuth(tokenRepo, workspaceRepo))
		r.Use(middleware.RequestResponseLogging(requestLogRepo))

		registerScimEndpoints(r)

		r.Route("/{compat}", func(r chi.Router) {
			registerScimEndpoints(r)
		})
	})

	server := httptest.NewServer(r)
	t.Cleanup(server.Close)

	return &testEnv{
		server: server,
		ctx:    ctx,
	}
}

func generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func seedWorkspaceAndToken(t *testing.T, ctx context.Context, wsID uuid.UUID, token string) {
	t.Helper()
	now := time.Now().UTC()

	_, err := jdbc.ExecContext(ctx,
		`INSERT INTO workspaces (id, name, description, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`,
		wsID, "ws-"+wsID.String(), "test workspace", now, now)
	if err != nil {
		t.Fatalf("seed workspace: %v", err)
	}

	_, err = jdbc.ExecContext(ctx,
		`INSERT INTO workspace_tokens (id, workspace_id, token_hash, name, description, expires_at, revoked, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		uuid.New(), wsID, hashToken(token), "test-token", "integration test token", nil, false, now, now)
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
}

func seedUser(t *testing.T, ctx context.Context, wsID, userID uuid.UUID, userName, displayName string) {
	t.Helper()
	now := time.Now().UTC()
	_, err := jdbc.ExecContext(ctx,
		`INSERT INTO scim_users (id, workspace_id, user_name, active, display_name, created_at, last_modified, version) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		userID, wsID, userName, true, displayName, now, now, 0)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func seedGroup(t *testing.T, ctx context.Context, wsID, groupID uuid.UUID, displayName string) {
	t.Helper()
	now := time.Now().UTC()
	_, err := jdbc.ExecContext(ctx,
		`INSERT INTO scim_groups (id, workspace_id, display_name, created_at, last_modified, version) VALUES ($1, $2, $3, $4, $5, $6)`,
		groupID, wsID, displayName, now, now, 0)
	if err != nil {
		t.Fatalf("seed group: %v", err)
	}
}

func scimURL(baseURL string, wsID uuid.UUID, path string) string {
	return fmt.Sprintf("%s/ws/%s/scim/v2%s", baseURL, wsID, path)
}

func doRequest(t *testing.T, method, url, token string, body string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/scim+json")
	if body != "" {
		req.Header.Set("Content-Type", "application/scim+json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}
