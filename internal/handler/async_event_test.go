package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/scimsandbox/scim-server-impl-go/internal/middleware"
	"github.com/scimsandbox/scim-server-impl-go/internal/model"
)

type mockAsyncEventRepo struct {
	mu        sync.Mutex
	events    map[uuid.UUID]*model.ScimAsyncEvent
	createErr error
	findErr   error
	updateErr error
}

func newMockAsyncEventRepo() *mockAsyncEventRepo {
	return &mockAsyncEventRepo{
		events: make(map[uuid.UUID]*model.ScimAsyncEvent),
	}
}

func (m *mockAsyncEventRepo) Create(ctx context.Context, e *model.ScimAsyncEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	if e.TxnID == uuid.Nil {
		e.TxnID = uuid.New()
	}
	m.events[e.TxnID] = e
	return nil
}

func (m *mockAsyncEventRepo) FindByTxnIDAndWorkspaceID(ctx context.Context, txnID, workspaceID uuid.UUID) (*model.ScimAsyncEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.findErr != nil {
		return nil, m.findErr
	}
	e, ok := m.events[txnID]
	if !ok || e.WorkspaceID != workspaceID {
		return nil, nil
	}
	return e, nil
}

func (m *mockAsyncEventRepo) UpdateStatusAndPayload(
	ctx context.Context,
	txnID uuid.UUID,
	status string,
	resourceID *uuid.UUID,
	payload *string,
	completedAt time.Time,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	if e, ok := m.events[txnID]; ok {
		e.Status = status
		if resourceID != nil {
			e.ResourceID = resourceID
		}
		e.SetPayload = payload
		e.CompletedAt = &completedAt
	}
	return nil
}

func TestIsAsyncPreferred(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
		want    bool
	}{
		{
			name:    "no headers",
			headers: nil,
			want:    false,
		},
		{
			name:    "empty header",
			headers: []string{""},
			want:    false,
		},
		{
			name:    "exact respond-async",
			headers: []string{"respond-async"},
			want:    true,
		},
		{
			name:    "case insensitive Respond-Async",
			headers: []string{"Respond-Async"},
			want:    true,
		},
		{
			name:    "case insensitive RESPOND-ASYNC",
			headers: []string{"RESPOND-ASYNC"},
			want:    true,
		},
		{
			name:    "comma separated list with respond-async",
			headers: []string{"return=minimal, respond-async"},
			want:    true,
		},
		{
			name:    "parameterized respond-async",
			headers: []string{"respond-async; wait=10"},
			want:    true,
		},
		{
			name:    "multiple preferences with parameters",
			headers: []string{"return=representation, respond-async; wait=10; other=param"},
			want:    true,
		},
		{
			name:    "multiple Prefer headers",
			headers: []string{"return=minimal", "respond-async"},
			want:    true,
		},
		{
			name:    "other preference only",
			headers: []string{"return=representation"},
			want:    false,
		},
		{
			name:    "prefix match should not match",
			headers: []string{"respond-async-other"},
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "/Users", nil)
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			for _, h := range tc.headers {
				req.Header.Add("Prefer", h)
			}
			got := isAsyncPreferred(req)
			if got != tc.want {
				t.Errorf("isAsyncPreferred() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildSETJson(t *testing.T) {
	baseURL := "https://example.com/ws/123/scim/v2"
	txnID := uuid.New()
	resourceID := uuid.New()

	ops := []struct {
		method       string
		resourceType string
		wantEventURN string
		hasAttrs     bool
	}{
		{
			method:       "POST",
			resourceType: "User",
			wantEventURN: "urn:ietf:params:scim:event:prov:create:full",
			hasAttrs:     true,
		},
		{
			method:       "PUT",
			resourceType: "User",
			wantEventURN: "urn:ietf:params:scim:event:prov:put:full",
			hasAttrs:     true,
		},
		{
			method:       "PATCH",
			resourceType: "User",
			wantEventURN: "urn:ietf:params:scim:event:prov:patch:full",
			hasAttrs:     true,
		},
		{
			method:       "DELETE",
			resourceType: "User",
			wantEventURN: "urn:ietf:params:scim:event:prov:delete:full",
			hasAttrs:     false,
		},
		{
			method:       "POST",
			resourceType: "Group",
			wantEventURN: "urn:ietf:params:scim:event:prov:create:full",
			hasAttrs:     true,
		},
		{
			method:       "DELETE",
			resourceType: "Group",
			wantEventURN: "urn:ietf:params:scim:event:prov:delete:full",
			hasAttrs:     false,
		},
	}

	for _, op := range ops {
		t.Run(op.method+"_"+op.resourceType, func(t *testing.T) {
			attrs := map[string]any{"id": resourceID.String(), "userName": "alice"}
			setJSON, err := buildSETJson(baseURL, txnID, op.resourceType, resourceID, op.method, attrs)
			if err != nil {
				t.Fatalf("buildSETJson failed: %v", err)
			}

			var payload map[string]any
			if err := json.Unmarshal([]byte(setJSON), &payload); err != nil {
				t.Fatalf("failed to unmarshal SET JSON: %v", err)
			}

			if payload["iss"] != baseURL {
				t.Errorf("iss = %v, want %v", payload["iss"], baseURL)
			}
			if payload["txn"] != txnID.String() {
				t.Errorf("txn = %v, want %v", payload["txn"], txnID.String())
			}
			if _, ok := payload["jti"].(string); !ok {
				t.Errorf("jti is missing or not a string")
			}
			if _, ok := payload["iat"].(float64); !ok {
				t.Errorf("iat is missing or not a number")
			}

			subID, ok := payload["sub_id"].(map[string]any)
			if !ok {
				t.Fatalf("sub_id missing or not a map")
			}
			if subID["format"] != "uri" {
				t.Errorf("sub_id.format = %v, want uri", subID["format"])
			}
			plural := "Users"
			if op.resourceType == "Group" {
				plural = "Groups"
			}
			expectedURI := baseURL + "/" + plural + "/" + resourceID.String()
			if subID["uri"] != expectedURI {
				t.Errorf("sub_id.uri = %v, want %v", subID["uri"], expectedURI)
			}

			events, ok := payload["events"].(map[string]any)
			if !ok {
				t.Fatalf("events missing or not a map")
			}
			eventData, ok := events[op.wantEventURN].(map[string]any)
			if !ok {
				t.Fatalf("event URN %s missing from events map: %v", op.wantEventURN, events)
			}

			if op.hasAttrs {
				if _, ok := eventData["attributes"]; !ok {
					t.Errorf("expected attributes in eventData for %s", op.method)
				}
			} else {
				if _, ok := eventData["attributes"]; ok {
					t.Errorf("expected no attributes in eventData for %s", op.method)
				}
			}
		})
	}
}

func TestGetEvent_NotFound(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID := uuid.New()
	txnID := uuid.New()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/Events/"+txnID.String(), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("txnId", txnID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.GetEvent(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestGetEvent_InvalidUUID(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID := uuid.New()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/Events/not-a-uuid", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("txnId", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.GetEvent(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestGetEvent_Pending(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID := uuid.New()
	txnID := uuid.New()

	_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusPending,
		CreatedAt:    time.Now().UTC(),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/"+wsID.String()+"/scim/v2/Events/"+txnID.String(), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	rctx.URLParams.Add("txnId", txnID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.GetEvent(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("202 response body length = %d, want 0", rec.Body.Len())
	}
	if rec.Header().Get("Set-Txn") != txnID.String() {
		t.Errorf("Set-Txn = %v, want %v", rec.Header().Get("Set-Txn"), txnID.String())
	}
	if !strings.HasSuffix(rec.Header().Get("Location"), "/Events/"+txnID.String()) {
		t.Errorf("Location = %v, want suffix /Events/%s", rec.Header().Get("Location"), txnID.String())
	}
}

func TestGetEvent_Completed(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID := uuid.New()
	txnID := uuid.New()
	payload := `{"iss":"https://example.com","txn":"` + txnID.String() + `"}`

	_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusCompleted,
		SetPayload:   &payload,
		CreatedAt:    time.Now().UTC(),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/"+wsID.String()+"/scim/v2/Events/"+txnID.String(), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	rctx.URLParams.Add("txnId", txnID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.GetEvent(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %v, want application/json", rec.Header().Get("Content-Type"))
	}
	if rec.Body.String() != payload {
		t.Errorf("body = %s, want %s", rec.Body.String(), payload)
	}
}

func TestGetEvent_Failed(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID := uuid.New()
	txnID := uuid.New()

	_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusFailed,
		CreatedAt:    time.Now().UTC(),
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/Events/"+txnID.String(), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("txnId", txnID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.GetEvent(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestGetEvent_WorkspaceIsolation(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID1 := uuid.New()
	wsID2 := uuid.New()
	txnID := uuid.New()

	_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID1,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusPending,
		CreatedAt:    time.Now().UTC(),
	})

	// Query from different workspace wsID2
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/Events/"+txnID.String(), nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID2))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("txnId", txnID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.GetEvent(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for cross-workspace event access", rec.Code)
	}
}

func TestAsyncDispatch_CreateUser_HonorsPrefer(t *testing.T) {
	repo := newMockAsyncEventRepo()
	uh := NewUserHandler(nil, nil, nil, repo)

	wsID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"async_user@test.com"}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ws/"+wsID.String()+"/scim/v2/Users", bytes.NewBufferString(body))
	req.Header.Set("Prefer", "respond-async")
	req.Header.Set("Content-Type", ScimContentType)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	uh.CreateUser(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected 0-byte body, got %d bytes: %s", rec.Body.Len(), rec.Body.String())
	}

	setTxn := rec.Header().Get("Set-Txn")
	if setTxn == "" {
		t.Fatalf("Set-Txn header missing")
	}
	txnID, err := uuid.Parse(setTxn)
	if err != nil {
		t.Fatalf("Set-Txn is not a valid UUID: %v", err)
	}

	prefApplied := rec.Header().Get("Preference-Applied")
	if prefApplied != "respond-async" {
		t.Errorf("Preference-Applied = %v, want respond-async", prefApplied)
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/Events/"+txnID.String()) {
		t.Errorf("Location = %v, want it to contain /Events/%s", loc, txnID.String())
	}

	// Verify row created in repository
	event, err := repo.FindByTxnIDAndWorkspaceID(context.Background(), txnID, wsID)
	if err != nil || event == nil {
		t.Fatalf("event was not saved in repo: %v", err)
	}
	if event.Operation != "POST" || event.ResourceType != "User" {
		t.Errorf("event operation=%s, resourceType=%s; want POST, User", event.Operation, event.ResourceType)
	}
	if event.Status != model.AsyncStatusPending {
		// Note: in background it may have transitioned to failed because userRepo is nil, which is fine
		if event.Status != model.AsyncStatusFailed && event.Status != model.AsyncStatusCompleted {
			t.Errorf("event status = %s", event.Status)
		}
	}
}

func TestAsyncDispatch_CreateGroup_HonorsPrefer(t *testing.T) {
	repo := newMockAsyncEventRepo()
	gh := NewGroupHandler(nil, nil, nil, nil, repo)

	wsID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Async Test Group"}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ws/"+wsID.String()+"/scim/v2/Groups", bytes.NewBufferString(body))
	req.Header.Set("Prefer", "respond-async")
	req.Header.Set("Content-Type", ScimContentType)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	gh.CreateGroup(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected 0-byte body, got %d bytes: %s", rec.Body.Len(), rec.Body.String())
	}

	setTxn := rec.Header().Get("Set-Txn")
	if setTxn == "" {
		t.Fatalf("Set-Txn header missing")
	}
	txnID, err := uuid.Parse(setTxn)
	if err != nil {
		t.Fatalf("Set-Txn is not a valid UUID: %v", err)
	}

	prefApplied := rec.Header().Get("Preference-Applied")
	if prefApplied != "respond-async" {
		t.Errorf("Preference-Applied = %v, want respond-async", prefApplied)
	}

	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/Events/"+txnID.String()) {
		t.Errorf("Location = %v, want it to contain /Events/%s", loc, txnID.String())
	}

	event, err := repo.FindByTxnIDAndWorkspaceID(context.Background(), txnID, wsID)
	if err != nil || event == nil {
		t.Fatalf("event was not saved in repo: %v", err)
	}
	if event.Operation != "POST" || event.ResourceType != "Group" {
		t.Errorf("event operation=%s, resourceType=%s; want POST, Group", event.Operation, event.ResourceType)
	}
}

func TestAsyncDispatch_ReplaceUser_HonorsPrefer(t *testing.T) {
	repo := newMockAsyncEventRepo()
	uh := NewUserHandler(nil, nil, nil, repo)

	wsID := uuid.New()
	userID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"updated_user@test.com"}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/ws/"+wsID.String()+"/scim/v2/Users/"+userID.String(), bytes.NewBufferString(body))
	req.Header.Set("Prefer", "respond-async")
	req.Header.Set("Content-Type", ScimContentType)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	rctx.URLParams.Add("id", userID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	uh.ReplaceUser(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected 0-byte body, got %d bytes: %s", rec.Body.Len(), rec.Body.String())
	}
	setTxn := rec.Header().Get("Set-Txn")
	txnID, err := uuid.Parse(setTxn)
	if err != nil {
		t.Fatalf("invalid Set-Txn: %v", err)
	}

	event, err := repo.FindByTxnIDAndWorkspaceID(context.Background(), txnID, wsID)
	if err != nil || event == nil {
		t.Fatalf("event was not saved in repo: %v", err)
	}
	if event.Operation != "PUT" || event.ResourceType != "User" {
		t.Errorf("event operation=%s, resourceType=%s; want PUT, User", event.Operation, event.ResourceType)
	}
}

func TestAsyncDispatch_PatchUser_HonorsPrefer(t *testing.T) {
	repo := newMockAsyncEventRepo()
	uh := NewUserHandler(nil, nil, nil, repo)

	wsID := uuid.New()
	userID := uuid.New()
	body := `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"displayName","value":"New Name"}]
	}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/ws/"+wsID.String()+"/scim/v2/Users/"+userID.String(), bytes.NewBufferString(body))
	req.Header.Set("Prefer", "respond-async")
	req.Header.Set("Content-Type", ScimContentType)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	rctx.URLParams.Add("id", userID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	uh.PatchUser(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected 0-byte body, got %d bytes: %s", rec.Body.Len(), rec.Body.String())
	}
	setTxn := rec.Header().Get("Set-Txn")
	txnID, err := uuid.Parse(setTxn)
	if err != nil {
		t.Fatalf("invalid Set-Txn: %v", err)
	}

	event, err := repo.FindByTxnIDAndWorkspaceID(context.Background(), txnID, wsID)
	if err != nil || event == nil {
		t.Fatalf("event was not saved in repo: %v", err)
	}
	if event.Operation != "PATCH" || event.ResourceType != "User" {
		t.Errorf("event operation=%s, resourceType=%s; want PATCH, User", event.Operation, event.ResourceType)
	}
}

func TestAsyncDispatch_DeleteUser_HonorsPrefer(t *testing.T) {
	repo := newMockAsyncEventRepo()
	uh := NewUserHandler(nil, nil, nil, repo)

	wsID := uuid.New()
	userID := uuid.New()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/ws/"+wsID.String()+"/scim/v2/Users/"+userID.String(), nil)
	req.Header.Set("Prefer", "respond-async")
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	rctx.URLParams.Add("id", userID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	uh.DeleteUser(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected 0-byte body, got %d bytes: %s", rec.Body.Len(), rec.Body.String())
	}
	setTxn := rec.Header().Get("Set-Txn")
	txnID, err := uuid.Parse(setTxn)
	if err != nil {
		t.Fatalf("invalid Set-Txn: %v", err)
	}

	event, err := repo.FindByTxnIDAndWorkspaceID(context.Background(), txnID, wsID)
	if err != nil || event == nil {
		t.Fatalf("event was not saved in repo: %v", err)
	}
	if event.Operation != "DELETE" || event.ResourceType != "User" {
		t.Errorf("event operation=%s, resourceType=%s; want DELETE, User", event.Operation, event.ResourceType)
	}
}

func TestAsyncDispatch_ReplaceGroup_HonorsPrefer(t *testing.T) {
	repo := newMockAsyncEventRepo()
	gh := NewGroupHandler(nil, nil, nil, nil, repo)

	wsID := uuid.New()
	groupID := uuid.New()
	body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Updated Group"}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/ws/"+wsID.String()+"/scim/v2/Groups/"+groupID.String(), bytes.NewBufferString(body))
	req.Header.Set("Prefer", "respond-async")
	req.Header.Set("Content-Type", ScimContentType)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	rctx.URLParams.Add("id", groupID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	gh.ReplaceGroup(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected 0-byte body, got %d bytes: %s", rec.Body.Len(), rec.Body.String())
	}
	setTxn := rec.Header().Get("Set-Txn")
	txnID, err := uuid.Parse(setTxn)
	if err != nil {
		t.Fatalf("invalid Set-Txn: %v", err)
	}

	event, err := repo.FindByTxnIDAndWorkspaceID(context.Background(), txnID, wsID)
	if err != nil || event == nil {
		t.Fatalf("event was not saved in repo: %v", err)
	}
	if event.Operation != "PUT" || event.ResourceType != "Group" {
		t.Errorf("event operation=%s, resourceType=%s; want PUT, Group", event.Operation, event.ResourceType)
	}
}

func TestAsyncDispatch_PatchGroup_HonorsPrefer(t *testing.T) {
	repo := newMockAsyncEventRepo()
	gh := NewGroupHandler(nil, nil, nil, nil, repo)

	wsID := uuid.New()
	groupID := uuid.New()
	body := `{
		"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"displayName","value":"Renamed Group"}]
	}`

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/ws/"+wsID.String()+"/scim/v2/Groups/"+groupID.String(), bytes.NewBufferString(body))
	req.Header.Set("Prefer", "respond-async")
	req.Header.Set("Content-Type", ScimContentType)
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	rctx.URLParams.Add("id", groupID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	gh.PatchGroup(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected 0-byte body, got %d bytes: %s", rec.Body.Len(), rec.Body.String())
	}
	setTxn := rec.Header().Get("Set-Txn")
	txnID, err := uuid.Parse(setTxn)
	if err != nil {
		t.Fatalf("invalid Set-Txn: %v", err)
	}

	event, err := repo.FindByTxnIDAndWorkspaceID(context.Background(), txnID, wsID)
	if err != nil || event == nil {
		t.Fatalf("event was not saved in repo: %v", err)
	}
	if event.Operation != "PATCH" || event.ResourceType != "Group" {
		t.Errorf("event operation=%s, resourceType=%s; want PATCH, Group", event.Operation, event.ResourceType)
	}
}

func TestAsyncDispatch_DeleteGroup_HonorsPrefer(t *testing.T) {
	repo := newMockAsyncEventRepo()
	gh := NewGroupHandler(nil, nil, nil, nil, repo)

	wsID := uuid.New()
	groupID := uuid.New()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/ws/"+wsID.String()+"/scim/v2/Groups/"+groupID.String(), nil)
	req.Header.Set("Prefer", "respond-async")
	req = req.WithContext(context.WithValue(req.Context(), middleware.WorkspaceIDKey, wsID))

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workspaceId", wsID.String())
	rctx.URLParams.Add("id", groupID.String())
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	gh.DeleteGroup(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("expected 0-byte body, got %d bytes: %s", rec.Body.Len(), rec.Body.String())
	}
	setTxn := rec.Header().Get("Set-Txn")
	txnID, err := uuid.Parse(setTxn)
	if err != nil {
		t.Fatalf("invalid Set-Txn: %v", err)
	}

	event, err := repo.FindByTxnIDAndWorkspaceID(context.Background(), txnID, wsID)
	if err != nil || event == nil {
		t.Fatalf("event was not saved in repo: %v", err)
	}
	if event.Operation != "DELETE" || event.ResourceType != "Group" {
		t.Errorf("event operation=%s, resourceType=%s; want DELETE, Group", event.Operation, event.ResourceType)
	}
}

func TestEventsRoute_MethodNotAllowed(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	r := chi.NewRouter()
	const eventsPath = "/Events/{txnId}"
	r.Get(eventsPath, h.GetEvent)
	r.Post(eventsPath, MethodNotAllowed)
	r.Put(eventsPath, MethodNotAllowed)
	r.Patch(eventsPath, MethodNotAllowed)
	r.Delete(eventsPath, MethodNotAllowed)

	txnID := uuid.New()
	methods := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(method, "/Events/"+txnID.String(), nil)
			r.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s /Events/{txnId} status = %d, want 405", method, rec.Code)
			}
		})
	}
}

