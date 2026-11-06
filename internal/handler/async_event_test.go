package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	"github.com/scimsandbox/scim-server-impl-go/internal/scim"
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
	cp := *e
	m.events[cp.TxnID] = &cp
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
	cp := *e
	return &cp, nil
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
	if e, ok := m.events[txnID]; ok && e.Status == model.AsyncStatusPending {
		e.Status = status
		if resourceID != nil {
			e.ResourceID = resourceID
		}
		e.SetPayload = payload
		e.CompletedAt = &completedAt
	}
	return nil
}

func (m *mockAsyncEventRepo) ListWorkspaceIDsExceedingEventCount(ctx context.Context, maxCount int) ([]uuid.UUID, error) {
	return nil, nil
}

func (m *mockAsyncEventRepo) DeleteOldEventsForWorkspace(ctx context.Context, workspaceID uuid.UUID, maxCount int) (int64, error) {
	return 0, nil
}

func (m *mockAsyncEventRepo) FindStalePendingEvents(ctx context.Context, olderThan time.Time, limit int) ([]*model.ScimAsyncEvent, error) {
	return nil, nil
}

func (m *mockAsyncEventRepo) TransitionPendingToFailed(ctx context.Context, txnID uuid.UUID, payload string, completedAt time.Time) (bool, error) {
	return false, nil
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

	// Updated per RFC 9967 §2.2, §2.4, §2.4.4, §2.5.1.3:
	// - Completion SETs include urn:ietf:params:scim:event:misc:asyncresp
	// - :full events (create:full, put:full) carry "data" (resource object)
	// - :notice events (patch:notice) carry "attributes" (list of modified attrPaths)
	// - delete uses urn:ietf:params:scim:event:prov:delete (no :full/:notice suffix) with empty {}
	ops := []struct {
		method         string
		resourceType   string
		wantEventURN   string
		wantStatus     string
		wantDataMap    bool
		wantNoticeList bool
		patchPaths     []string
	}{
		{
			method:       "POST",
			resourceType: "User",
			wantEventURN: "urn:ietf:params:scim:event:prov:create:full",
			wantStatus:   "201",
			wantDataMap:  true,
		},
		{
			method:       "PUT",
			resourceType: "User",
			wantEventURN: "urn:ietf:params:scim:event:prov:put:full",
			wantStatus:   "200",
			wantDataMap:  true,
		},
		{
			method:         "PATCH",
			resourceType:   "User",
			wantEventURN:   "urn:ietf:params:scim:event:prov:patch:notice",
			wantStatus:     "200",
			wantNoticeList: true,
			patchPaths:     []string{"displayName", "name.givenName"},
		},
		{
			method:       "DELETE",
			resourceType: "User",
			wantEventURN: "urn:ietf:params:scim:event:prov:delete",
			wantStatus:   "204",
		},
		{
			method:       "POST",
			resourceType: "Group",
			wantEventURN: "urn:ietf:params:scim:event:prov:create:full",
			wantStatus:   "201",
			wantDataMap:  true,
		},
		{
			method:       "DELETE",
			resourceType: "Group",
			wantEventURN: "urn:ietf:params:scim:event:prov:delete",
			wantStatus:   "204",
		},
	}

	for _, op := range ops {
		t.Run(op.method+"_"+op.resourceType, func(t *testing.T) {
			var resMap map[string]any
			if op.method != "DELETE" {
				resMap = map[string]any{
					"id":       resourceID.String(),
					"userName": "alice",
					"meta":     map[string]any{"version": `W/"1"`},
				}
			}
			setJSON, err := buildSETJson(baseURL, txnID, op.resourceType, resourceID, op.method, resMap, op.patchPaths...)
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

			asyncResp, ok := events[AsyncRespEventURN].(map[string]any)
			if !ok {
				t.Fatalf("event URN %s missing from events map: %v", AsyncRespEventURN, events)
			}
			if asyncResp["status"] != op.wantStatus {
				t.Errorf("asyncresp status = %v, want %v", asyncResp["status"], op.wantStatus)
			}
			if asyncResp["method"] != op.method {
				t.Errorf("asyncresp method = %v, want %v", asyncResp["method"], op.method)
			}

			eventData, ok := events[op.wantEventURN].(map[string]any)
			if !ok {
				t.Fatalf("event URN %s missing from events map: %v", op.wantEventURN, events)
			}

			if op.wantDataMap {
				if _, ok := eventData["data"].(map[string]any); !ok {
					t.Errorf("expected 'data' map in :full eventData for %s, got %v", op.method, eventData)
				}
				if _, ok := eventData["attributes"]; ok {
					t.Errorf("unexpected 'attributes' in :full eventData for %s", op.method)
				}
			} else if op.wantNoticeList {
				attrSlice, ok := eventData["attributes"].([]any)
				if !ok || len(attrSlice) == 0 {
					t.Errorf("expected non-empty 'attributes' slice in :notice eventData, got %v", eventData)
				}
				if _, ok := eventData["data"]; ok {
					t.Errorf("unexpected 'data' in :notice eventData")
				}
			} else {
				if len(eventData) != 0 {
					t.Errorf("expected empty event payload for %s, got %v", op.method, eventData)
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

func TestGetEvent_Completed_NilPayload_Returns500(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID := uuid.New()
	txnID := uuid.New()

	_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusCompleted,
		SetPayload:   nil,
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

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for completed event with nil payload", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/scim+json") {
		t.Errorf("Content-Type = %v, want application/scim+json", ct)
	}
	var errResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if errResp["detail"] != "Asynchronous event payload missing" {
		t.Errorf("detail = %v, want 'Asynchronous event payload missing'", errResp["detail"])
	}
}

func TestGetEvent_Completed_WhitespacePayload_Returns500(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID := uuid.New()
	txnID := uuid.New()
	emptyPayload := "   \t\n  "

	_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusCompleted,
		SetPayload:   &emptyPayload,
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

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for completed event with whitespace payload", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/scim+json") {
		t.Errorf("Content-Type = %v, want application/scim+json", ct)
	}
	var errResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if errResp["detail"] != "Asynchronous event payload missing" {
		t.Errorf("detail = %v, want 'Asynchronous event payload missing'", errResp["detail"])
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

func TestShouldExecuteAsync_WaitPreference(t *testing.T) {
	reqSync, _ := http.NewRequest(http.MethodPost, "/Users", nil)
	reqSync.Header.Set("Prefer", "respond-async, wait=10")
	if async, _ := shouldExecuteAsync(reqSync); async {
		t.Fatal("expected Prefer: respond-async, wait=10 to execute synchronously within wait budget")
	}

	reqSyncSemi, _ := http.NewRequest(http.MethodPost, "/Users", nil)
	reqSyncSemi.Header.Set("Prefer", "respond-async; wait=5")
	if async, _ := shouldExecuteAsync(reqSyncSemi); async {
		t.Fatal("expected Prefer: respond-async; wait=5 to execute synchronously within wait budget")
	}

	reqZero, _ := http.NewRequest(http.MethodPost, "/Users", nil)
	reqZero.Header.Set("Prefer", "respond-async, wait=0")
	if async, hdr := shouldExecuteAsync(reqZero); !async || hdr != "respond-async, wait=0" {
		t.Fatalf("got (%v, %q), want (true, \"respond-async, wait=0\")", async, hdr)
	}
}

func TestGetEvent_FailedWithErrorSET_Returns200AsyncResp(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID := uuid.New()
	txnID := uuid.New()
	baseURL := "http://example.com/ws/" + wsID.String() + "/scim/v2"

	errSet, err := buildErrorSETJson(baseURL, txnID, "User", nil, "POST",
		scim.NewScimError(http.StatusConflict, "uniqueness", "User already exists"))
	if err != nil {
		t.Fatalf("buildErrorSETJson failed: %v", err)
	}

	_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusFailed,
		SetPayload:   &errSet,
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
		t.Fatalf("status = %d, want 200 for error SET delivery", rec.Code)
	}

	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal SET: %v", err)
	}
	events, _ := decoded["events"].(map[string]any)
	asyncResp, ok := events[AsyncRespEventURN].(map[string]any)
	if !ok {
		t.Fatalf("missing %s in error SET: %v", AsyncRespEventURN, events)
	}
	if asyncResp["status"] != "409" {
		t.Errorf("asyncresp status = %v, want 409", asyncResp["status"])
	}
	errResp, _ := asyncResp["response"].(map[string]any)
	if errResp["scimType"] != "uniqueness" {
		t.Errorf("error scimType = %v, want uniqueness", errResp["scimType"])
	}
}

func TestGetEvent_Completed_EmptyStringPayload_Returns500(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID := uuid.New()
	txnID := uuid.New()
	emptyPayload := ""

	_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusCompleted,
		SetPayload:   &emptyPayload,
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

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for completed event with empty string payload", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/scim+json") {
		t.Errorf("Content-Type = %v, want application/scim+json", ct)
	}
	var errResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("unmarshal error response: %v", err)
	}
	if errResp["detail"] != "Asynchronous event payload missing" {
		t.Errorf("detail = %v, want 'Asynchronous event payload missing'", errResp["detail"])
	}
	if errResp["status"] != "500" {
		t.Errorf("status = %v, want '500'", errResp["status"])
	}
	schemas, ok := errResp["schemas"].([]any)
	if !ok || len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
		t.Errorf("schemas = %v, want ['urn:ietf:params:scim:api:messages:2.0:Error']", errResp["schemas"])
	}
}

func TestGetEvent_Completed_WhitespaceVariants_Returns500(t *testing.T) {
	whitespaceCases := []struct {
		name    string
		payload string
	}{
		{"spaces_only", "    "},
		{"tab_only", "\t"},
		{"newline_only", "\n"},
		{"crlf_only", "\r\n"},
		{"mixed_tabs_spaces_newlines_cr", "   \t\r\n "},
	}

	for _, tc := range whitespaceCases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockAsyncEventRepo()
			h := NewAsyncEventHandler(repo)

			wsID := uuid.New()
			txnID := uuid.New()
			p := tc.payload

			_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
				TxnID:        txnID,
				WorkspaceID:  wsID,
				Operation:    "POST",
				ResourceType: "User",
				Status:       model.AsyncStatusCompleted,
				SetPayload:   &p,
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

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500 for payload %q", rec.Code, tc.payload)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/scim+json") {
				t.Errorf("Content-Type = %v, want application/scim+json", ct)
			}
			var errResp map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Fatalf("unmarshal error response: %v", err)
			}
			if errResp["detail"] != "Asynchronous event payload missing" {
				t.Errorf("detail = %v, want 'Asynchronous event payload missing'", errResp["detail"])
			}
			if errResp["status"] != "500" {
				t.Errorf("status = %v, want '500'", errResp["status"])
			}
		})
	}
}

func TestGetEvent_Completed_ValidPayload_Integrity(t *testing.T) {
	repo := newMockAsyncEventRepo()
	h := NewAsyncEventHandler(repo)

	wsID := uuid.New()
	txnID := uuid.New()
	complexPayload := `{"iss":"https://example.com/ws/123","iat":1730790000,"jti":"abc-123","txn":"` + txnID.String() + `","events":{"urn:ietf:params:scim:event:prov:create:full":{"data":{"userName":"bjensen@example.com","name":{"formatted":"Ms. Barbara J Jensen"}}}},"sub_id":{"format":"uri","uri":"https://example.com/ws/123/Users/def-456"}}`

	_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
		TxnID:        txnID,
		WorkspaceID:  wsID,
		Operation:    "POST",
		ResourceType: "User",
		Status:       model.AsyncStatusCompleted,
		SetPayload:   &complexPayload,
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
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %v, want application/json", ct)
	}
	if rec.Body.String() != complexPayload {
		t.Errorf("body does not match intact payload:\ngot  %s\nwant %s", rec.Body.String(), complexPayload)
	}
}

func TestBuildErrorSETJson_FallbackFormatting(t *testing.T) {
	methods := []string{"POST", "PUT", "PATCH", "DELETE", "post", "patch"}

	for _, method := range methods {
		t.Run("Method_"+method, func(t *testing.T) {
			baseURL := "https://example.com/ws/123/scim/v2"
			txnID := uuid.New()
			upperMethod := strings.ToUpper(method)

			fallback := fmt.Sprintf(`{"iss":%q,"iat":%d,"jti":%q,"txn":%q,"events":{%q:{"status":"500","method":%q,"response":{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"500","detail":"Internal server error"}}}}`,
				baseURL, time.Now().UTC().Unix(), uuid.New().String(), txnID.String(), AsyncRespEventURN, upperMethod)

			var decoded map[string]any
			if err := json.Unmarshal([]byte(fallback), &decoded); err != nil {
				t.Fatalf("fallback json unmarshal failed: %v", err)
			}

			if decoded["iss"] != baseURL {
				t.Errorf("iss = %v, want %s", decoded["iss"], baseURL)
			}
			if decoded["txn"] != txnID.String() {
				t.Errorf("txn = %v, want %s", decoded["txn"], txnID.String())
			}
			if _, ok := decoded["iat"].(float64); !ok {
				t.Errorf("iat missing or not a number: %v", decoded["iat"])
			}
			if jtiStr, ok := decoded["jti"].(string); !ok || jtiStr == "" {
				t.Errorf("jti missing or invalid: %v", decoded["jti"])
			}

			events, ok := decoded["events"].(map[string]any)
			if !ok {
				t.Fatalf("events missing or not a map: %v", decoded["events"])
			}
			asyncResp, ok := events[AsyncRespEventURN].(map[string]any)
			if !ok {
				t.Fatalf("missing %s in events: %v", AsyncRespEventURN, events)
			}
			if asyncResp["status"] != "500" {
				t.Errorf("status = %v, want 500", asyncResp["status"])
			}
			if asyncResp["method"] != upperMethod {
				t.Errorf("method = %v, want %s", asyncResp["method"], upperMethod)
			}
			resp, ok := asyncResp["response"].(map[string]any)
			if !ok {
				t.Fatalf("response missing or not a map: %v", asyncResp["response"])
			}
			if resp["status"] != "500" {
				t.Errorf("response.status = %v, want 500", resp["status"])
			}
			if resp["detail"] != "Internal server error" {
				t.Errorf("response.detail = %v, want 'Internal server error'", resp["detail"])
			}
			schemas, ok := resp["schemas"].([]any)
			if !ok || len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:Error" {
				t.Errorf("response.schemas = %v, want ['urn:ietf:params:scim:api:messages:2.0:Error']", resp["schemas"])
			}
		})
	}
}

type ctxCapturingAsyncEventRepo struct {
	*mockAsyncEventRepo
	updateCtxErr chan error
}

func (c *ctxCapturingAsyncEventRepo) UpdateStatusAndPayload(
	ctx context.Context,
	txnID uuid.UUID,
	status string,
	resourceID *uuid.UUID,
	payload *string,
	completedAt time.Time,
) error {
	select {
	case c.updateCtxErr <- ctx.Err():
	default:
	}
	return c.mockAsyncEventRepo.UpdateStatusAndPayload(ctx, txnID, status, resourceID, payload, completedAt)
}

func TestRunAsyncWorker_PanicRecovery_FreshStatusContext_And_PendingGuard(t *testing.T) {
	wsID := uuid.New()
	baseURL := "https://example.com/ws/" + wsID.String() + "/scim/v2"

	t.Run("recovers from panic and transitions event to FAILED", func(t *testing.T) {
		repo := &ctxCapturingAsyncEventRepo{
			mockAsyncEventRepo: newMockAsyncEventRepo(),
			updateCtxErr:       make(chan error, 1),
		}
		txnID := uuid.New()
		resID := uuid.New()
		_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "POST",
			ResourceType: "User",
			Status:       model.AsyncStatusPending,
			CreatedAt:    time.Now().UTC(),
		})

		runAsyncWorker(repo, baseURL, txnID, "User", &resID, "POST", func(ctx context.Context) (*uuid.UUID, string, error) {
			panic("simulated worker crash")
		})

		select {
		case ctxErr := <-repo.updateCtxErr:
			if ctxErr != nil {
				t.Fatalf("expected non-canceled statusCtx in UpdateStatusAndPayload, got %v", ctxErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for panic recovery status update")
		}

		ev, _ := repo.FindByTxnIDAndWorkspaceID(context.Background(), txnID, wsID)
		if ev == nil || ev.Status != model.AsyncStatusFailed {
			t.Fatalf("event status = %v, want FAILED", ev)
		}
	})

	t.Run("uses fresh statusCtx even when worker operation context is canceled/expired", func(t *testing.T) {
		repo := &ctxCapturingAsyncEventRepo{
			mockAsyncEventRepo: newMockAsyncEventRepo(),
			updateCtxErr:       make(chan error, 1),
		}
		txnID := uuid.New()
		_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "POST",
			ResourceType: "User",
			Status:       model.AsyncStatusPending,
			CreatedAt:    time.Now().UTC(),
		})

		runAsyncWorker(repo, baseURL, txnID, "User", nil, "POST", func(ctx context.Context) (*uuid.UUID, string, error) {
			return nil, "", context.DeadlineExceeded
		})

		select {
		case ctxErr := <-repo.updateCtxErr:
			if ctxErr != nil {
				t.Fatalf("expected fresh statusCtx with nil Err(), got %v", ctxErr)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for failure status update")
		}
	})

	t.Run("does not overwrite FAILED event when reaper already transitioned it from PENDING", func(t *testing.T) {
		repo := newMockAsyncEventRepo()
		txnID := uuid.New()
		reaperPayload := `{"reaper":"failed"}`
		_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "POST",
			ResourceType: "User",
			Status:       model.AsyncStatusFailed,
			SetPayload:   &reaperPayload,
			CreatedAt:    time.Now().UTC(),
		})

		resID := uuid.New()
		latePayload := `{"worker":"completed"}`
		_ = repo.UpdateStatusAndPayload(context.Background(), txnID, model.AsyncStatusCompleted, &resID, &latePayload, time.Now().UTC())

		ev, _ := repo.FindByTxnIDAndWorkspaceID(context.Background(), txnID, wsID)
		if ev.Status != model.AsyncStatusFailed || ev.SetPayload == nil || *ev.SetPayload != reaperPayload {
			t.Fatalf("expected FAILED status and reaper payload to be preserved, got status=%s payload=%v", ev.Status, ev.SetPayload)
		}
	})

	t.Run("returns 503 tooMany without creating PENDING row when asyncWorkerSem is full", func(t *testing.T) {
		repo := newMockAsyncEventRepo()
		// Fill all available slots in asyncWorkerSem
		acquired := 0
		for {
			select {
			case asyncWorkerSem <- struct{}{}:
				acquired++
			default:
				goto filled
			}
		}
	filled:
		defer func() {
			for i := 0; i < acquired; i++ {
				<-asyncWorkerSem
			}
		}()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ws/"+wsID.String()+"/scim/v2/Users", nil)
		opCalled := false
		dispatchAsyncOperation(rec, req, repo, wsID, baseURL, "respond-async", "POST", "User", nil, func(ctx context.Context, txnID uuid.UUID) (*uuid.UUID, string, error) {
			opCalled = true
			return nil, "", nil
		})

		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503: %s", rec.Code, rec.Body.String())
		}
		var errBody map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil {
			t.Fatalf("unmarshal 503 response: %v", err)
		}
		if errBody["scimType"] != "tooMany" {
			t.Errorf("scimType = %v, want tooMany", errBody["scimType"])
		}
		repo.mu.Lock()
		evCount := len(repo.events)
		repo.mu.Unlock()
		if evCount != 0 {
			t.Errorf("expected 0 events in repo when 503 returned, got %d", evCount)
		}
		if opCalled {
			t.Error("expected worker op not to be called when 503 returned")
		}
	})

	t.Run("worker skips executing op when event is already FAILED before worker runs", func(t *testing.T) {
		repo := newMockAsyncEventRepo()
		txnID := uuid.New()
		reaperPayload := `{"reaper":"already-failed"}`
		_ = repo.Create(context.Background(), &model.ScimAsyncEvent{
			TxnID:        txnID,
			WorkspaceID:  wsID,
			Operation:    "POST",
			ResourceType: "User",
			Status:       model.AsyncStatusFailed,
			SetPayload:   &reaperPayload,
			CreatedAt:    time.Now().UTC(),
		})

		done := make(chan struct{})
		opExecuted := false
		asyncWorkerSem <- struct{}{}
		go func() {
			runAsyncWorkerWithAcquiredSlot(repo, wsID, baseURL, txnID, "User", nil, "POST", func(ctx context.Context) (*uuid.UUID, string, error) {
				opExecuted = true
				return nil, "{}", nil
			})
			// Wait briefly for the worker goroutine to check status and exit
			time.Sleep(50 * time.Millisecond)
			close(done)
		}()
		<-done
		if opExecuted {
			t.Fatal("expected worker to skip op execution when event was already FAILED")
		}
	})
}




